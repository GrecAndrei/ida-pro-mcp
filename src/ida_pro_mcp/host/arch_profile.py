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


def _score_raw_arch_candidates(data: bytes) -> list[Dict[str, Any]]:
    """
    Score likely architectures for raw blobs from lightweight opcode signatures.
    Returns sorted candidates with normalized confidence.
    """
    if not data:
        return []

    sample = data[: min(len(data), 8192)]
    n = max(1, len(sample))

    def _count(pat: bytes) -> int:
        return sample.count(pat)

    # x86/x64-ish patterns
    x86_score = 0.0
    x86_score += _count(b"\x55\x8b\xec") * 2.0   # push ebp; mov ebp,esp
    x86_score += _count(b"\x55\x48\x89\xe5") * 2.5  # x64 prologue
    x86_score += _count(b"\xe8") * 0.02           # call rel32 opcode density
    x86_score += _count(b"\xc3") * 0.03           # ret opcode density

    # ARM Thumb signatures (common in firmware)
    arm_thumb_score = 0.0
    arm_thumb_score += _count(b"\x70\x47") * 1.2  # bx lr
    arm_thumb_score += _count(b"\xf0\xb5") * 1.8  # push {..., lr}
    arm_thumb_score += _count(b"\x00\xf0") * 0.8  # bl/branch prefix

    # ARM A32 signatures
    arm_a32_score = 0.0
    arm_a32_score += _count(b"\x2d\xe9") * 1.8    # stmfd sp!, {...}
    arm_a32_score += _count(b"\xbd\xe8") * 1.6    # ldmfd sp!, {...}
    arm_a32_score += _count(b"\x1e\xff\x2f\xe1") * 2.0  # bx lr

    # MIPS prologues (both endian variants represented in bytes)
    mips_le_score = 0.0
    mips_le_score += _count(b"\xbd\x27") * 1.8    # addiu sp,sp,-imm (LE)
    mips_le_score += _count(b"\xbf\xaf") * 1.4    # sw ra,off(sp) (LE)
    mips_le_score += _count(b"\x0c") * 0.02       # jal opcode high byte often 0x0c in BE word view

    mips_be_score = 0.0
    mips_be_score += _count(b"\x27\xbd") * 1.8    # addiu sp,sp,-imm (BE)
    mips_be_score += _count(b"\xaf\xbf") * 1.4    # sw ra,off(sp) (BE)
    mips_be_score += _count(b"\x03\xe0\x00\x08") * 1.8  # jr ra

    raw = [
        {"processor": "metapc", "bitness": 32, "endian": "little", "score": x86_score, "reason": "x86/x64 opcode density"},
        {"processor": "arm", "bitness": 32, "endian": "little", "score": arm_thumb_score + arm_a32_score, "reason": "ARM/Thumb opcode density"},
        {"processor": "mipsl", "bitness": 32, "endian": "little", "score": mips_le_score, "reason": "MIPS little-endian opcode density"},
        {"processor": "mipsb", "bitness": 32, "endian": "big", "score": mips_be_score, "reason": "MIPS big-endian opcode density"},
    ]
    raw.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
    best = float(raw[0]["score"]) if raw else 0.0
    second = float(raw[1]["score"]) if len(raw) > 1 else 0.0
    if best <= 0.0:
        return []
    # Absolute signal strength (per-sample) and separation confidence.
    abs_strength = min(1.0, best / max(6.0, n * 0.02))
    separation = (best - second) / max(best, 1e-6)
    top_conf = max(0.05, min(0.95, (0.65 * abs_strength) + (0.35 * separation)))
    out = []
    for idx, row in enumerate(raw[:4]):
        rel = max(0.0, min(1.0, float(row["score"]) / (best + 1e-6)))
        conf = top_conf if idx == 0 else max(0.01, min(0.9, top_conf * rel * 0.9))
        out.append(
            {
                "processor": row["processor"],
                "bitness": row["bitness"],
                "endian": row["endian"],
                "confidence": round(conf, 3),
                "reason": row["reason"],
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

    candidates = _score_raw_arch_candidates(sample)
    inf.candidates = candidates
    if candidates:
        top = candidates[0]
        top_conf = float(top.get("confidence") or 0.0)
        if top_conf >= 0.6:
            inf.processor = str(top.get("processor") or "")
            inf.bitness = int(top.get("bitness") or 32)
            inf.endian = str(top.get("endian") or "little")
            inf.confidence = min(0.85, top_conf)
            inf.reason = f"raw opcode signature heuristic ({top.get('reason')})"
            return inf.to_dict()

    # Unknown raw: avoid forcing a wrong processor. Keep suggestions only.
    inf.processor = None
    inf.bitness = None
    inf.endian = None
    inf.confidence = 0.2
    inf.reason = "raw binary ambiguous; no safe auto-architecture"
    return inf.to_dict()
