#!/usr/bin/env python3
"""
Architecture profile normalization and raw-binary inference.

Pure-python helpers (no IDA imports) so host + server_script can share logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple
import os
import struct
import math


_PROC_ALIASES = {
    "aarch64": ("arm", 64),
    "arm64": ("arm", 64),
    "armv8": ("arm", 64),
    "x64": ("metapc", 64),
    "x86_64": ("metapc", 64),
    "amd64": ("metapc", 64),
    "i386": ("metapc", 32),
    "i486": ("metapc", 32),
    "i586": ("metapc", 32),
    "i686": ("metapc", 32),
    "x86": ("metapc", 32),
    "mipsel": ("mipsl", 32),
    "mipseb": ("mipsb", 32),
    "ppc": ("powerpc", None),
}


def _norm_endian(value: Any) -> str | None:
    if value is None:
        return None
    txt = str(value).strip().lower()
    if txt in ("little", "little_endian", "little-endian", "littleendian", "le", "0", "false"):
        return "little"
    if txt in ("big", "big_endian", "big-endian", "bigendian", "be", "1", "true"):
        return "big"
    return None


def normalize_arch_options(options: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Canonicalize processor aliases and endian synonyms.
    Returns (normalized_options, meta).
    """
    out = dict(options or {})
    meta: Dict[str, Any] = {"normalizations": []}

    proc = out.get("processor")
    if proc is not None:
        raw = str(proc).strip().lower()
        canon, implied_bits = _PROC_ALIASES.get(raw, (raw, None))
        if canon != raw:
            meta["normalizations"].append(f"processor:{raw}->{canon}")
        out["processor"] = canon
        if out.get("bitness") in (None, "") and implied_bits is not None:
            out["bitness"] = implied_bits
            meta["normalizations"].append(f"bitness:auto={implied_bits}")

    end = out.get("endian")
    if end is not None:
        e2 = _norm_endian(end)
        if e2 is not None:
            out["endian"] = e2
            if str(end).strip().lower() != e2:
                meta["normalizations"].append(f"endian:{end}->{e2}")

    if "loader_options" in out and "value" not in out:
        out["value"] = out.get("loader_options")
        meta["normalizations"].append("loader_options->value")

    return out, meta


@dataclass
class ArchInference:
    processor: str | None = None
    bitness: int | None = None
    endian: str | None = None
    file_kind: str = "unknown"
    confidence: float = 0.0
    reason: str = ""
    candidates: list[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "processor": self.processor,
            "bitness": self.bitness,
            "endian": self.endian,
            "file_kind": self.file_kind,
            "confidence": round(float(self.confidence), 3),
            "reason": self.reason,
            "candidates": self.candidates,
        }


def _byte_2gram_embedding(data: bytes) -> Dict[int, float]:
    """Compact sparse embedding over byte 2-grams."""
    if not data or len(data) < 2:
        return {}
    v: Dict[int, float] = {}
    total = 0
    for i in range(len(data) - 1):
        key = (data[i] << 8) | data[i + 1]
        v[key] = v.get(key, 0.0) + 1.0
        total += 1
    if total <= 0:
        return {}
    inv = 1.0 / float(total)
    for k in list(v.keys()):
        v[k] *= inv
    return v


def _sparse_cosine(a: Dict[int, float], b: Dict[int, float]) -> float:
    if not a or not b:
        return 0.0
    dot = 0.0
    for k, av in a.items():
        bv = b.get(k)
        if bv is not None:
            dot += av * bv
    na = math.sqrt(sum(x * x for x in a.values()))
    nb = math.sqrt(sum(x * x for x in b.values()))
    if na <= 1e-12 or nb <= 1e-12:
        return 0.0
    return max(0.0, min(1.0, dot / (na * nb)))


def _arch_prototype_embeddings() -> Dict[str, Dict[int, float]]:
    """
    Lightweight architecture prototype embeddings.
    These are stable tokenized opcode bytes represented as n-gram vectors.
    """
    proto = {
        "metapc": b"\x55\x8b\xec\x83\xec\x08\xe8\xc3\x90\x8b\x45\xfc",
        "arm": b"\xf0\xb5\x70\x47\x00\xf0\x2d\xe9\xbd\xe8\x1e\xff\x2f\xe1",
        "mipsl": b"\xbd\x27\xbf\xaf\x08\x00\xe0\x03\x0c\x00\x00\x00",
        "mipsb": b"\x27\xbd\xaf\xbf\x03\xe0\x00\x08\x00\x00\x00\x0c",
    }
    return {k: _byte_2gram_embedding(v) for k, v in proto.items()}


def _embed_raw_arch_candidates(data: bytes) -> list[Dict[str, Any]]:
    """Embedding-similarity architecture candidates for raw blobs."""
    if not data:
        return []
    sample = data[: min(len(data), 8192)]
    sample_vec = _byte_2gram_embedding(sample)
    if not sample_vec:
        return []
    proto = _arch_prototype_embeddings()
    rows = []
    for arch, vec in proto.items():
        sim = _sparse_cosine(sample_vec, vec)
        rows.append((sim, arch))
    rows.sort(key=lambda x: x[0], reverse=True)
    if not rows or rows[0][0] <= 0.0:
        return []

    arch_meta = {
        "metapc": {"processor": "metapc", "bitness": 32, "endian": "little"},
        "arm": {"processor": "arm", "bitness": 32, "endian": "little"},
        "mipsl": {"processor": "mipsl", "bitness": 32, "endian": "little"},
        "mipsb": {"processor": "mipsb", "bitness": 32, "endian": "big"},
    }
    top_sim = rows[0][0]
    out: list[Dict[str, Any]] = []
    for sim, arch in rows[:4]:
        meta = arch_meta.get(arch, {})
        # Confidence is normalized to top similarity and bounded.
        conf = max(0.01, min(0.95, sim if sim == top_sim else (sim / max(top_sim, 1e-9)) * top_sim))
        out.append(
            {
                "processor": meta.get("processor"),
                "bitness": meta.get("bitness"),
                "endian": meta.get("endian"),
                "confidence": round(conf, 3),
                "reason": "byte-embedding similarity",
            }
        )
    return out


def infer_binary_arch_profile(binary_path: str) -> Dict[str, Any]:
    """
    Lightweight architecture inference for session bootstrap.
    Uses magic headers and Cortex-M vector-table heuristics for raw blobs.
    """
    inf = ArchInference()
    try:
        with open(binary_path, "rb") as f:
            head = f.read(64)
            f.seek(0)
            sample = f.read(8192)
    except Exception:
        inf.reason = "binary unreadable"
        return inf.to_dict()

    if head.startswith(b"\x7fELF"):
        inf.file_kind = "elf"
        # Let loader drive arch for ELF; host does not force processor.
        inf.confidence = 0.95
        inf.reason = "ELF header"
        return inf.to_dict()

    if head.startswith(b"MZ"):
        inf.file_kind = "pe"
        inf.processor = "metapc"
        inf.bitness = 32
        inf.endian = "little"
        inf.confidence = 0.85
        inf.reason = "MZ/PE header"
        return inf.to_dict()

    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        inf.file_kind = "macho"
        inf.confidence = 0.85
        inf.reason = "Mach-O magic"
        return inf.to_dict()

    inf.file_kind = "raw"
    # Cortex-M vector-table heuristic (little-endian default in the wild).
    if len(head) >= 8:
        sp_le, rv_le = struct.unpack_from("<II", head, 0)
        # Typical RAM ranges + Thumb reset vector.
        if 0x20000000 <= sp_le <= 0x40080000 and (rv_le & 1) == 1:
            inf.processor = "arm"
            inf.bitness = 32
            inf.endian = "little"
            inf.confidence = 0.92
            inf.reason = "raw Cortex-M vector table heuristic"
            return inf.to_dict()

    candidates = _embed_raw_arch_candidates(sample)
    inf.candidates = candidates
    if candidates:
        # Keep candidate ranking only for raw ambiguous blobs.
        # Avoid forcing architecture from an arbitrary confidence threshold.
        inf.processor = None
        inf.bitness = None
        inf.endian = None
        inf.confidence = float(candidates[0].get("confidence") or 0.2)
        inf.reason = "raw embedding-profile candidates available; explicit selection recommended"
        return inf.to_dict()

    # Unknown raw: avoid forcing a wrong processor. Keep suggestions only.
    inf.processor = None
    inf.bitness = None
    inf.endian = None
    inf.confidence = 0.2
    inf.reason = "raw binary ambiguous; no safe auto-architecture"
    return inf.to_dict()
