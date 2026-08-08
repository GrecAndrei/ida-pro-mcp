#!/usr/bin/env python3
"""
Architecture profile normalization and raw-binary inference.

Pure-python helpers (no IDA imports) so host + server_script can share logic.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from typing import Any

from ..stores.chip_db import find_chip_profile, identify_chip_from_bytes

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


def normalize_arch_options(options: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Canonicalize processor aliases and endian synonyms.
    Returns (normalized_options, meta).
    """
    out = dict(options or {})
    meta: dict[str, Any] = {"normalizations": []}

    # Strip arch keys that are empty/zero/whitespace — an LLM passing processor=""
    # or bitness=0 should be treated the same as not passing it at all, otherwise
    # IDA's loader detection gets overridden with nonsense.
    for _k in ("processor", "bitness", "endian", "loader", "flags"):
        if _k in out:
            _v = out[_k]
            if _v is None or (isinstance(_v, str) and not _v.strip()) or _v == 0:
                del out[_k]
                meta["normalizations"].append(f"{_k}:dropped_empty")

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

    for key in ("baseaddr", "start_ea", "min_ea", "max_ea"):
        if out.get(key) is None:
            continue
        raw = out.get(key)
        if isinstance(raw, int):
            continue
        text = str(raw).strip()
        coerced = None
        try:
            coerced = int(text, 0)
        except Exception:
            # int(s, 0) treats a leading zero as octal and fails on e.g.
            # "00401000" (contains '8').  Hex-looking strings without a 0x
            # prefix are common LLM/tool output, so fall back to base 16.
            if re.fullmatch(r"[0-9][0-9a-fA-F]*", text):
                try:
                    coerced = int(text, 16)
                except Exception:
                    coerced = None
        if coerced is None or coerced == raw:
            continue
        out[key] = coerced
        meta["normalizations"].append(f"{key}:coerced=int")

    return out, meta


@dataclass
class ArchInference:
    processor: str | None = None
    bitness: int | None = None
    endian: str | None = None
    loader: str | None = None
    file_kind: str = "unknown"
    confidence: float = 0.0
    reason: str = ""
    candidates: list[dict[str, Any]] = field(default_factory=list)
    load_base: int | None = None         # confirmed load base address (e.g. from WFFW header)
    chip_family: str | None = None       # e.g. "aic8800d80", "stm32", "esp32"
    memory_map: list[dict[str, Any]] = field(default_factory=list)
    peripheral_addresses: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "processor": self.processor,
            "bitness": self.bitness,
            "endian": self.endian,
            "file_kind": self.file_kind,
            "confidence": round(float(self.confidence), 3),
            "reason": self.reason,
            "candidates": self.candidates,
        }
        if self.loader is not None:
            d["loader"] = self.loader
        if self.load_base is not None:
            d["load_base"] = self.load_base
        if self.chip_family is not None:
            d["chip_family"] = self.chip_family
        if self.memory_map:
            d["memory_map"] = self.memory_map
        if self.peripheral_addresses:
            d["peripheral_addresses"] = self.peripheral_addresses
        return d


def _byte_2gram_embedding(data: bytes) -> dict[int, float]:
    """Compact sparse embedding over byte 2-grams."""
    if not data or len(data) < 2:
        return {}
    v: dict[int, float] = {}
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


def _sparse_cosine(a: dict[int, float], b: dict[int, float]) -> float:
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


def _arch_prototype_embeddings() -> dict[str, dict[int, float]]:
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


def _opcode_density_scores(data: bytes) -> dict[str, float]:
    """
    Score likely architectures using opcode-sequence density.
    Counts known prologues/epilogues as weighted hits.
    Returns a dict of arch -> raw score (not normalized).
    """
    sample = data[: min(len(data), 8192)]

    def _count(pat: bytes) -> int:
        return sample.count(pat)

    x86_score = 0.0
    x86_score += _count(b"\x55\x8b\xec") * 2.0        # push ebp; mov ebp,esp
    x86_score += _count(b"\x55\x48\x89\xe5") * 2.5    # x64 prologue
    x86_score += _count(b"\xe8") * 0.02               # call rel32 density
    x86_score += _count(b"\xc3") * 0.03               # ret density

    arm_score = 0.0
    arm_score += _count(b"\x70\x47") * 1.2            # bx lr (Thumb)
    arm_score += _count(b"\xf0\xb5") * 1.8            # push {..., lr} (Thumb)
    arm_score += _count(b"\x00\xf0") * 0.8            # bl prefix (Thumb-2)
    arm_score += _count(b"\x2d\xe9") * 1.8            # stmfd sp! (A32)
    arm_score += _count(b"\xbd\xe8") * 1.6            # ldmfd sp! (A32)
    arm_score += _count(b"\x1e\xff\x2f\xe1") * 2.0   # bx lr (A32)

    mipsl_score = 0.0
    mipsl_score += _count(b"\xbd\x27") * 1.8          # addiu sp (LE)
    mipsl_score += _count(b"\xbf\xaf") * 1.4          # sw ra (LE)
    mipsl_score += _count(b"\x08\x00\xe0\x03") * 1.8  # jr ra (LE)

    mipsb_score = 0.0
    mipsb_score += _count(b"\x27\xbd") * 1.8          # addiu sp (BE)
    mipsb_score += _count(b"\xaf\xbf") * 1.4          # sw ra (BE)
    mipsb_score += _count(b"\x03\xe0\x00\x08") * 1.8  # jr ra (BE)

    return {
        "metapc": x86_score,
        "arm": arm_score,
        "mipsl": mipsl_score,
        "mipsb": mipsb_score,
    }


def _raw_arch_candidates(data: bytes) -> list[dict[str, Any]]:
    """
    Blended architecture candidates for raw blobs.
    Combines opcode-density (primary) with byte-embedding (secondary).
    Opcode density carries 0.7 weight; embedding carries 0.3 weight.
    Reports inference_method so callers can gauge reliability.
    """
    if not data:
        return []
    sample = data[: min(len(data), 8192)]

    # --- opcode-density signal ---
    od_raw = _opcode_density_scores(sample)
    od_best = max(od_raw.values()) if od_raw else 0.0

    # --- embedding signal ---
    sample_vec = _byte_2gram_embedding(sample)
    proto = _arch_prototype_embeddings() if sample_vec else {}
    em_raw: dict[str, float] = {}
    for arch, vec in proto.items():
        em_raw[arch] = _sparse_cosine(sample_vec, vec)
    em_best = max(em_raw.values()) if em_raw else 0.0

    arch_meta: dict[str, dict[str, Any]] = {
        "metapc": {"processor": "metapc", "bitness": 32, "endian": "little"},
        "arm":    {"processor": "arm",    "bitness": 32, "endian": "little"},
        "mipsl":  {"processor": "mipsl",  "bitness": 32, "endian": "little"},
        "mipsb":  {"processor": "mipsb",  "bitness": 32, "endian": "big"},
    }

    OPCODE_W = 0.7
    EMBED_W = 0.3

    rows: list[tuple[float, str]] = []
    for arch in arch_meta:
        od_norm = (od_raw.get(arch, 0.0) / (od_best + 1e-9)) if od_best > 0 else 0.0
        em_norm = (em_raw.get(arch, 0.0) / (em_best + 1e-9)) if em_best > 0 else 0.0
        blended = OPCODE_W * od_norm + EMBED_W * em_norm
        rows.append((blended, arch))

    rows.sort(key=lambda x: x[0], reverse=True)
    if not rows or rows[0][0] <= 0.0:
        return []

    top_blended = rows[0][0]
    # Pick label: opcode-dominated when od_best > 0, otherwise embedding.
    method = "opcode-density + embedding blend" if od_best > 0 else "byte-embedding similarity"

    out: list[dict[str, Any]] = []
    for blended, arch in rows[:4]:
        meta = arch_meta[arch]
        # Relative-to-best ratio: the /top_blended and *top_blended cancelled
        # out before, so each candidate reported its absolute blended score.
        # Divide by top_blended only — the top candidate gets ~1.0 (capped at
        # 0.95) and runners-up get a true relative confidence.
        conf = max(0.01, min(0.95, blended / (top_blended + 1e-9)))
        out.append(
            {
                "processor": meta["processor"],
                "bitness": meta["bitness"],
                "endian": meta["endian"],
                "confidence": round(conf, 3),
                "reason": f"{method}",
                "inference_method": method,
            }
        )
    return out


def infer_binary_arch_profile(binary_path: str) -> dict[str, Any]:
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

    # Packed IDA database (.i64) - magic "IDA2"
    if head.startswith(b"IDA2"):
        inf.file_kind = "packed_idb"
        inf.confidence = 1.0
        inf.reason = "IDA packed database (IDA2 magic)"
        # Don't set processor/bitness/endian - let IDA load the DB and use its metadata
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
        if len(sample) >= 0x40:
            pe_offset = struct.unpack_from("<I", sample, 0x3c)[0]
            if pe_offset + 24 <= len(sample):
                pe_sig = sample[pe_offset:pe_offset+4]
                if pe_sig == b"PE\0\0":
                    machine = struct.unpack_from("<H", sample, pe_offset + 4)[0]
                    if machine == 0x8664:  # AMD64
                        inf.bitness = 64
                        inf.reason = "MZ/PE header (64-bit x64)"
                    elif machine == 0xaa64:  # ARM64
                        inf.processor = "arm"
                        inf.bitness = 64
                        inf.reason = "MZ/PE header (64-bit ARM64)"
                    elif machine in (0x1c0, 0x1c4):  # ARM 32-bit
                        inf.processor = "arm"
                        inf.bitness = 32
                        inf.reason = "MZ/PE header (32-bit ARM)"
                    elif machine == 0x014c:  # Intel 386
                        inf.bitness = 32
                        inf.reason = "MZ/PE header (32-bit x86)"
        return inf.to_dict()

    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        inf.file_kind = "macho"
        inf.confidence = 0.85
        inf.reason = "Mach-O magic"
        return inf.to_dict()

    inf.file_kind = "raw"
    chip = identify_chip_from_bytes(sample)
    if chip:
        inf.processor = chip.get("processor")
        inf.bitness = chip.get("bitness")
        inf.endian = chip.get("endian")
        inf.loader = "bin"
        inf.confidence = float(chip.get("confidence") or 0.95)
        inf.reason = f"chip profile match: {chip.get('chip_family', 'unknown')}"
        inf.chip_family = str(chip.get("chip_family") or "unknown")
        inf.load_base = chip.get("load_base")
        inf.memory_map = chip.get("memory_map") or []
        inf.peripheral_addresses = chip.get("peripheral_addresses") or []
        return inf.to_dict()

    # --- Standard Cortex-M vector-table heuristic (little-endian) ---
    if len(head) >= 8:
        sp_le, rv_le = struct.unpack_from("<II", head, 0)
        # Typical RAM ranges + Thumb reset vector.
        if 0x20000000 <= sp_le <= 0x40080000 and (rv_le & 1) == 1:
            inf.processor = "arm"
            inf.bitness = 32
            inf.endian = "little"
            inf.loader = "bin"
            inf.confidence = 0.92
            inf.reason = "raw Cortex-M vector table heuristic"
            rv_even = rv_le & ~1
            if 0x08000000 <= rv_even <= 0x08FFFFFF:
                prof = find_chip_profile("STM32") or {}
                inf.chip_family = "STM32"
            else:
                prof = find_chip_profile("Generic Cortex-M") or {}
                inf.chip_family = "Generic Cortex-M"
            inf.load_base = prof.get("load_base")
            inf.memory_map = prof.get("memory_map") or []
            inf.peripheral_addresses = prof.get("peripheral_addresses") or []
            return inf.to_dict()

    candidates = _raw_arch_candidates(sample)
    inf.candidates = candidates
    if candidates:
        # Keep candidate ranking only for raw ambiguous blobs.
        # Avoid forcing architecture from an arbitrary confidence threshold.
        inf.processor = None
        inf.bitness = None
        inf.endian = None
        inf.confidence = float(candidates[0].get("confidence") or 0.2)
        inf.reason = candidates[0].get("reason") or "raw candidates available; explicit selection recommended"
        return inf.to_dict()

    # Unknown raw: avoid forcing a wrong processor. Keep suggestions only.
    inf.processor = None
    inf.bitness = None
    inf.endian = None
    inf.confidence = 0.2
    inf.reason = "raw binary ambiguous; no safe auto-architecture"
    return inf.to_dict()
