#!/usr/bin/env python3
"""
Architecture profile normalization and raw-binary inference.

Pure-python helpers (no IDA imports) so host + server_script can share logic.
"""

from __future__ import annotations

from dataclasses import dataclass
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "processor": self.processor,
            "bitness": self.bitness,
            "endian": self.endian,
            "file_kind": self.file_kind,
            "confidence": round(float(self.confidence), 3),
            "reason": self.reason,
        }


def infer_binary_arch_profile(binary_path: str) -> Dict[str, Any]:
    """
    Lightweight architecture inference for session bootstrap.
    Uses magic headers and Cortex-M vector-table heuristics for raw blobs.
    """
    inf = ArchInference()
    try:
        with open(binary_path, "rb") as f:
            head = f.read(64)
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

    # Conservative fallback for raw blobs: ARM32 little is most common in embedded dumps.
    inf.processor = "arm"
    inf.bitness = 32
    inf.endian = "little"
    inf.confidence = 0.45
    inf.reason = "raw binary fallback (low confidence)"
    return inf.to_dict()

