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

from .patterns import looks_like_code

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
    # IDA's RISC-V processor module is canonically named "riscv" (there is no
    # separate riscv64/riscv32 module).  Aliasing the suffixed forms here means
    # set_processor_type('riscv64') resolves to the canonical module with the
    # bitness carried through as an option, instead of IDA silently failing to
    # find a "riscv64" processor module on an opaque blob.
    "riscv64": ("riscv", 64),
    "rv64": ("riscv", 64),
    "riscv32": ("riscv", 32),
    "rv32": ("riscv", 32),
    "riscv": ("riscv", None),
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
    load_base: int | None = None         # confirmed load base address (e.g. from a known header)
    looks_like_code: bool = False        # entropy/instruction-validity gate on the raw sample
    warning: str | None = None           # honest caveat for raw blobs / provisional guesses
    ambiguous: bool = False              # top candidates are indistinguishable (same-score tie)
    provider_error: dict[str, Any] | None = None  # advisory failure, never a policy decision

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "processor": self.processor,
            "bitness": self.bitness,
            "endian": self.endian,
            "file_kind": self.file_kind,
            "confidence": round(float(self.confidence), 3),
            "reason": self.reason,
            "candidates": self.candidates,
            "looks_like_code": bool(self.looks_like_code),
            "ambiguous": bool(self.ambiguous),
        }
        if self.loader is not None:
            d["loader"] = self.loader
        if self.load_base is not None:
            d["load_base"] = self.load_base
        if self.warning:
            d["warning"] = self.warning
        if self.provider_error:
            d["provider_error"] = dict(self.provider_error)
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


# Absolute-signal calibration for raw-blob confidence. Confidence is derived
# from the raw opcode-density strength and the max byte-2gram cosine — never
# from a relative "best-of-N" ratio, which made weak blobs claim ~0.95.
_OD_CONF_SATURATION = 20.0     # od_best == 20  ->  od_conf == 1.0
_EM_CONF_SATURATION = 0.30     # em_best == 0.3 ->  em_conf == 1.0
_OD_MIN_FOR_EMBED = 1.0        # embedding only counts once real opcode evidence exists
# RISC-V is intentionally absent from the raw heuristic candidate set. Its
# architecture/bitness choices are delegated to the explicit advisory provider
# and verified by IDA's processor module.
_OD_W = 0.45
_EM_W = 0.20


def _raw_arch_candidates(data: bytes) -> list[dict[str, Any]]:
    """
    Blended architecture candidates for raw blobs.

    Combines bounded opcode density (primary) with byte-2gram similarity
    (secondary) for non-RISC-V formats. RISC-V is intentionally not inferred
    from host-side instruction heuristics.
    Confidence is ABSOLUTE signal strength (od_best + max embedding cosine),
    not relative-to-best, so a weak/noisy blob reports a low confidence instead
    of an inflated one.  Cross-architecture candidates whose blended score ties
    the top are dropped as contradictory.
    """
    if not data:
        return []
    sample = data[: min(len(data), 8192)]

    # --- non-RISC-V opcode-density signal ---
    od_raw = _opcode_density_scores(sample)
    code_ok = looks_like_code(sample)
    od_best = max(od_raw.values()) if od_raw else 0.0

    # --- deterministic byte-2gram signal ---
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

    def _blended(arch: str) -> float:
        od_norm = (od_raw.get(arch, 0.0) / (od_best + 1e-9)) if od_best > 0 else 0.0
        em_norm = (em_raw.get(arch, 0.0) / (em_best + 1e-9)) if em_best > 0 else 0.0
        return _OD_W * od_norm + _EM_W * em_norm

    rows: list[tuple[float, str]] = []
    for arch in ("metapc", "arm", "mipsl", "mipsb"):
        rows.append((_blended(arch), arch))
    rows.sort(key=lambda x: x[0], reverse=True)

    if not rows or rows[0][0] <= 0.0:
        return []

    top_blended = rows[0][0]
    # Absolute confidence from raw signal strength.
    od_conf = min(1.0, od_best / _OD_CONF_SATURATION)
    em_conf = min(1.0, em_best / _EM_CONF_SATURATION)
    # The embedding alone (e.g. a lone common byte) must not confer confidence
    # when there is no real opcode evidence.
    em_effective = em_conf if od_best >= _OD_MIN_FOR_EMBED else 0.0
    abs_conf = min(1.0, 0.7 * od_conf + 0.3 * em_effective)

    method = "opcode-density + byte-2gram blend" if od_best > 0 else "byte-2gram similarity"

    out: list[dict[str, Any]] = []
    for blended, arch in rows:
        if blended <= 0.0:
            continue
        meta = arch_meta[arch]
        # Drop a runner-up with a DIFFERENT processor that ties the top — that
        # is a genuine contradiction, not a usable suggestion.  Same-processor
        # candidates (riscv32 vs riscv64) legitimately coexist as bitness
        # ambiguity.
        if (
            arch != rows[0][1]
            and meta["processor"] != arch_meta[rows[0][1]]["processor"]
            and (top_blended - blended) < 0.05
        ):
            continue
        conf = abs_conf * (blended / (top_blended + 1e-9))
        out.append(
            {
                "processor": meta["processor"],
                "bitness": meta["bitness"],
                "endian": meta["endian"],
                "confidence": round(conf, 3),
                "reason": method,
                "inference_method": method,
                "looks_like_code": bool(code_ok),
            }
        )
    return out


def _cortex_m_vector_plausible(head: bytes, rv_le: int) -> bool:
    """
    Validate a Cortex-M vector-table guess before accepting it at high confidence.

    A little-endian Cortex-M vector table starts with the initial SP followed by
    the reset-vector pointer.  A genuine table has a reset vector that lands in a
    plausible code region and a burst of subsequent entries that either are zero
    or decode as Thumb (odd) pointers into flash/RAM.  A random file can satisfy
    the SP+Thumb-bit sniff by chance, but its following words will be garbage, so
    the scan of the following words separates a real table from noise.
    """
    reset = rv_le & ~1
    if not (
        (0x08000000 <= reset <= 0x08200000)   # flash (Cortex-M common)
        or (0x00000000 <= reset <= 0x00200000)  # boot ROM / alias
        or (0x20000000 <= reset <= 0x40080000)  # RAM-resident image
    ):
        return False
    # Inspect the words after the reset vector.  Only a handful of entries are
    # typically populated; the rest are zero.  Accept when most words are either
    # zero or plausible Thumb pointers / flash-RAM addresses.
    plausible = 0
    total = 0
    for off in range(8, len(head) - 3, 4):
        (word,) = struct.unpack_from("<I", head, off)
        total += 1
        if word == 0 or (word & 1) == 1 or (word & ~1) in range(0x40200000):
            plausible += 1
    return total == 0 or (plausible / total) >= 0.5


def prepared_profile(inferred: dict[str, Any], options: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Build a ready-to-open architecture profile from an inference plus any
    explicit user options, applying proc aliases / endian synonyms.

    This is the single entry point for turning a raw-blob inference (or an
    explicit selection) into the option dict that gets merged with
    open-binary options.  It is used by the prepared-profile helper on the
    host side and is the hand-off point for the server_session.py revamp wave
    to auto-apply a high-confidence inference before opening an opaque blob.
    """
    opts, meta = normalize_arch_options(dict(options or {}))
    inf = dict(inferred or {})

    processor = opts.get("processor") or inf.get("processor")
    bitness = opts.get("bitness") or inf.get("bitness")
    endian = opts.get("endian") or inf.get("endian")
    loader = opts.get("loader") or inf.get("loader")

    profile: dict[str, Any] = {
        "processor": processor,
        "bitness": bitness,
        "endian": endian,
    }
    if loader is not None:
        profile["loader"] = loader
    load_base = opts.get("baseaddr") or opts.get("load_base") or inf.get("load_base")
    if load_base is not None:
        profile["load_base"] = load_base
    if inf.get("confidence") is not None:
        profile["confidence"] = inf.get("confidence")
    if inf.get("warning"):
        profile["warning"] = inf.get("warning")
    profile["file_kind"] = inf.get("file_kind", "unknown")
    profile["meta"] = meta
    return profile


def prepare_profile_from_inference(binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Run infer_binary_arch_profile on a binary and turn it into a prepared
    profile (see prepared_profile).  Convenience used by callers that want a
    single call.
    """
    return prepared_profile(infer_binary_arch_profile(binary_path), options)


def _jev_raw_architecture_advisory(
    sample: bytes,
    *,
    file_kind: str,
    candidates: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Ask the explicit provider about a raw architecture hypothesis.

    IDA loaders and processor modules remain authoritative for recognized
    formats.  This hook is used only for opaque raw blobs and sends bounded
    byte metadata/candidate summaries, never decompilation or strings.
    ``None`` means the provider is explicitly disabled; an error mapping is
    returned so callers can surface unavailable Jev rather than silently
    treating it as a successful model decision.
    """
    try:
        from ..intelligence.advisory import ask_architecture
        from ..intelligence.providers.config import resolve_provider_config

        mode = resolve_provider_config().mode
        if mode == "disabled":
            return None
        state = {
            "file_kind": str(file_kind)[:32],
            "byte_sample_hex": sample[:512].hex(),
            "sample_length": len(sample),
            "candidate_summaries": [
                {
                    "processor": str(row.get("processor") or "")[:32],
                    "bitness": row.get("bitness"),
                    "endian": str(row.get("endian") or "")[:16],
                    "confidence": row.get("confidence"),
                }
                for row in candidates[:12]
                if isinstance(row, dict)
            ],
        }
        return ask_architecture(state, operation="raw_architecture")
    except Exception as exc:
        code = str(getattr(exc, "code", "PROVIDER_ERROR"))
        return {"error": True, "code": code, "message": "raw architecture advisory failed"}


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
    inf.looks_like_code = looks_like_code(sample)

    # --- Standard Cortex-M vector-table heuristic (little-endian) ---
    if len(head) >= 8:
        sp_le, rv_le = struct.unpack_from("<II", head, 0)
        # Typical RAM ranges + Thumb reset vector.
        if 0x20000000 <= sp_le <= 0x40080000 and (rv_le & 1) == 1:
            inf.processor = "arm"
            inf.bitness = 32
            inf.endian = "little"
            inf.loader = "bin"
            inf.load_base = rv_le & ~1
            if _cortex_m_vector_plausible(head, rv_le):
                inf.confidence = 0.92
                inf.reason = "raw Cortex-M vector table heuristic"
            else:
                # Reset vector points oddly or the following words are not
                # Thumb pointers — keep the guess but report it as provisional
                # instead of asserting it at high confidence.
                inf.confidence = 0.55
                inf.reason = "raw Cortex-M vector table heuristic (provisional)"
                inf.warning = (
                    "Cortex-M vector-table guess is provisional (reset vector or "
                    "vector entries look off); verify the architecture explicitly."
                )
            return inf.to_dict()

    candidates = _raw_arch_candidates(sample)
    inf.candidates = candidates
    advisory = _jev_raw_architecture_advisory(
        sample, file_kind=inf.file_kind, candidates=candidates
    )
    if advisory is None:
        # Disabled mode must not retain the removed host-side RISC-V guesses.
        candidates = [
            row for row in candidates
            if not (isinstance(row, dict) and row.get("processor") == "riscv")
        ]
        inf.candidates = candidates
    if isinstance(advisory, dict) and advisory.get("error"):
        inf.provider_error = {
            "code": str(advisory.get("code") or "PROVIDER_ERROR")[:64],
            "message": str(advisory.get("message") or "raw architecture advisory failed")[:256],
        }
        # Explicit provider modes fail closed: do not silently fall back to
        # the removed MCP RISC-V heuristic when Jev/custom is unavailable.
        inf.processor = None
        inf.bitness = None
        inf.endian = None
        inf.candidates = []
        inf.load_base = None
        inf.confidence = 0.0
        inf.warning = "provider architecture advisory failed; set architecture explicitly"
        return inf.to_dict()
    elif isinstance(advisory, dict) and advisory.get("ok") and advisory.get("choice") == "unknown":
        inf.processor = None
        inf.bitness = None
        inf.endian = None
        inf.candidates = []
        inf.confidence = float(advisory.get("confidence") or 0.0)
        inf.warning = "provider returned unknown architecture; set architecture explicitly"
        return inf.to_dict()
    elif isinstance(advisory, dict) and advisory.get("ok") and advisory.get("choice") not in {None, "unknown"}:
        # Jev/custom is advisory only: expose its bounded hypothesis, but do
        # not auto-select an IDA processor or mutate an IDB here.
        inf.processor = advisory.get("processor")
        inf.bitness = advisory.get("bitness")
        inf.endian = advisory.get("endian")
        inf.confidence = float(advisory.get("confidence") or 0.0)
        inf.reason = "typed-question provider architecture advisory"
        inf.warning = "provider advisory; verify architecture explicitly before IDA analysis"
        return inf.to_dict()
    if candidates:
        # Keep candidate ranking only for raw ambiguous blobs.
        # Avoid forcing architecture from an arbitrary confidence threshold.
        inf.processor = None
        inf.bitness = None
        inf.endian = None
        inf.confidence = float(candidates[0].get("confidence") or 0.2)
        inf.reason = candidates[0].get("reason") or "raw candidates available; explicit selection recommended"
        inf.looks_like_code = bool(candidates[0].get("looks_like_code", inf.looks_like_code))
        inf.warning = "raw blob; arch unverified — set architecture explicitly or apply a high-confidence inference"
        return inf.to_dict()

    # Unknown raw: avoid forcing a wrong processor. Keep suggestions only.
    inf.processor = None
    inf.bitness = None
    inf.endian = None
    inf.confidence = 0.2
    inf.reason = "raw binary ambiguous; no safe auto-architecture"
    inf.warning = "raw blob; arch unverified — no safe auto-architecture, set one explicitly"
    return inf.to_dict()
