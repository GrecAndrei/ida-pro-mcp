"""q02 regression tests: reliable arch/bitness/load-base inference on opaque
raw-.bin device firmware, with RISC-V as a first-class candidate.

Covers (each maps to a q02 directive):
- Opaque RISC-V raw-blob scenarios: RV32C / RV64C / non-C RV32 / non-C RV64
  blobs are ranked riscv-first with an honest absolute confidence (never > 1.0
  and never inflated on weak noise).
- RISC-V gating: ASCII text, all-zero, and random blobs never emit riscv
  candidates (the entropy/printable looks_like_code gate + od/validity floors).
- load_base population: dominant lui/auipc hi20 scan and the Cortex-M reset
  vector (& ~1), plus the provisional downgrade when the vector table is fishy.
- proc aliases: riscv64/rv32/riscv32 normalize to the canonical "riscv" module.
- idb.py: the architecture-profile action reuses the idb_meta inference
  (single file scan), surfaces raw-blob warning/load_base/entrypoints notes,
  and keys the RISC-V GP probe off the processor name (works without
  is_riscv_family(), including riscv64/riscv32 alias strings).
- context_density: RISC-V ABI registers (a0-a7, t0-t6, s0-s11, ra, gp, tp,
  zero) count as useful tokens.
"""

import os
import random
import struct
import sys
import tempfile
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.analysis.arch_profile import (
    _cortex_m_vector_plausible,
    _dominant_hi20,
    infer_binary_arch_profile,
    normalize_arch_options,
    prepared_profile,
)
from ida_pro_mcp.host.analysis.context_density import (
    _USEFUL_TOKEN_RE,
    measure_information_density,
)
from ida_pro_mcp.host.analysis.patterns import (
    byte_entropy,
    looks_like_code,
    riscv_instruction_validity,
)

# ---------------------------------------------------------------------------
# Deterministic synthetic RISC-V raw-blob builders
# ---------------------------------------------------------------------------

def _w32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _h16(v: int) -> bytes:
    return struct.pack("<H", v)


def _rv32c(n: int = 400) -> bytes:
    """RV32 with the C extension, compressed-only (no lw/sw/ld/sd words).  The
    alignment-blind ld/sd-vs-lw/sw bitness scan sees no load/store evidence, so
    this reports riscv with an undecided bitness (ambiguous), NOT a confident
    64 — the honest outcome on compressed-only firmware."""
    out = bytearray()
    out += _w32(0x00001097)  # auipc gp, 0x10000
    out += _w32(0x00018193)  # addi gp, gp, 0
    for _ in range(n):
        out += _h16(0x0004)  # c.addi4spn a0, sp, 0
        out += _h16(0x4084)  # c.addi4spn a1, sp, 4
        out += _h16(0x00E1)  # c.addi a0, 0xe
        out += _h16(0x40C1)  # c.addi a1, 0xc
        out += _h16(0x9082)  # c.jalr ra
        out += _h16(0x8082)  # c.jr ra
    return bytes(out)


def _rv64c(n: int = 400) -> bytes:
    """RV64 with the C extension plus ld (funct3=011) — clear 64-bit evidence."""
    out = bytearray()
    out += _w32(0x00001097)
    out += _w32(0x00018193)
    for _ in range(n):
        out += _h16(0x0004)
        out += _h16(0x4084)
        out += _h16(0x00E1)
        out += _h16(0x40C1)
        out += _w32(0x0002B303)  # ld t1, 0(t0)  funct3=011 (RV64)
        out += _w32(0x0002B383)  # ld t2, 0(t0)
        out += _h16(0x9082)
        out += _h16(0x8082)
    return bytes(out)


def _rv_noc(n: int, load_funct3: int, store_funct3: int, seed: int = 7) -> bytes:
    """Realistic non-C RISC-V blob: addi/lui bursts, loads/stores, jalr tails.
    Immediates vary by a seeded PRNG so the entropy clears looks_like_code
    while every word is a valid RISC-V instruction."""
    rng = random.Random(seed)
    out = bytearray()
    out += _w32(0x00001097)
    out += _w32(0x00018193)
    for _ in range(n):
        for rd in (5, 6, 7, 10, 11, 12, 13, 14, 15):
            imm = rng.randrange(0, 4096)
            out += _w32(((imm & 0xFFF) << 20) | (rd << 7) | 0x13)  # addi rd,x0,imm
        for rd in (5, 6, 7):
            imm = rng.randrange(-2048, 2048) & 0xFFF
            rs1 = rng.randrange(10, 16)
            out += _w32((imm << 20) | (rs1 << 15) | (load_funct3 << 12) | (rd << 7) | 0x03)
        for rs2 in (5, 6):
            imm = rng.randrange(-2048, 2048) & 0xFFF
            rs1 = rng.randrange(10, 16)
            out += _w32((((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15)
                        | (store_funct3 << 12) | ((imm & 0x1F) << 7) | 0x23)
        imm = rng.randrange(-2048, 2048) & 0xFFF
        rs1 = rng.randrange(10, 16)
        out += _w32((imm << 20) | (rs1 << 15) | (1 << 7) | 0x67)  # jalr ra,imm(rs1)
    return bytes(out)


def _rv32_noc() -> bytes:
    return _rv_noc(600, load_funct3=2, store_funct3=2)


def _rv64_noc() -> bytes:
    return _rv_noc(600, load_funct3=3, store_funct3=3)


def _rv64_highbase() -> bytes:
    """RV64C blob whose lui/auipc immediates concentrate on hi20 0x80000000
    (SoC-class absolute base) — exercises the dominant-hi20 load_base scan."""
    out = bytearray()
    out += _w32(0x80000B37)  # lui t6, 0x80000
    out += _w32(0x80000117)  # auipc gp, 0x80000
    out += _w32(0x00018193)  # addi gp, gp, 0
    for _ in range(400):
        out += _h16(0x0004) + _h16(0x4084) + _h16(0x00E1) + _h16(0x40C1)
        out += _h16(0x9082) + _h16(0x8082)
        for rd in (5, 6, 7):
            out += _w32(((0x80000 & 0xFFFFF) << 12) | (rd << 7) | 0x37)  # lui rd,0x80000
    return bytes(out)


@pytest.fixture()
def tmp_blob(tmp_path):
    """Write a blob to a temp file and return the path."""

    def _write(data: bytes, name: str = "blob.bin") -> str:
        p = tmp_path / name
        p.write_bytes(data)
        return str(p)

    return _write


def _top_candidate(inf):
    cands = inf.get("candidates") or []
    return cands[0] if cands else {}


# ---------------------------------------------------------------------------
# Opaque RISC-V raw-blob scenarios
# ---------------------------------------------------------------------------

def test_opaque_rv32_raw_blob_detected_riscv_first(tmp_blob):
    path = tmp_blob(_rv32_noc())
    inf = infer_binary_arch_profile(path)
    assert inf["file_kind"] == "raw"
    assert inf.get("looks_like_code") is True
    top = _top_candidate(inf)
    assert top.get("processor") == "riscv", inf
    assert top.get("bitness") == 32, inf
    # Clear bitness: riscv32 is confidently above riscv64, nothing else ranks
    # close.
    rv64 = next((c for c in inf["candidates"]
                 if c["processor"] == "riscv" and c["bitness"] == 64), None)
    assert rv64 is not None and top["confidence"] > rv64["confidence"]
    non_riscv_top = max((c["confidence"] for c in inf["candidates"]
                         if c["processor"] != "riscv"), default=0.0)
    assert top["confidence"] > non_riscv_top


def test_opaque_rv64_raw_blob_detected_riscv64(tmp_blob):
    path = tmp_blob(_rv64_noc())
    inf = infer_binary_arch_profile(path)
    top = _top_candidate(inf)
    assert top.get("processor") == "riscv", inf
    assert top.get("bitness") == 64, inf
    rv32 = next((c for c in inf["candidates"]
                 if c["processor"] == "riscv" and c["bitness"] == 32), None)
    assert rv32 is not None and top["confidence"] > rv32["confidence"]


def test_opaque_rv32c_raw_blob_riscv_known_bitness_ambiguous(tmp_blob):
    """Mixed C-extension RV32 code: the alignment-blind ld/sd-vs-lw/sw scan
    cannot resolve bitness, so the inference must say riscv with an honest
    ambiguous flag rather than pick a confident (and wrong) 64."""
    path = tmp_blob(_rv32c())
    inf = infer_binary_arch_profile(path)
    top = _top_candidate(inf)
    assert top.get("processor") == "riscv", inf
    assert inf.get("ambiguous") is True, inf
    confs = {c["bitness"]: c["confidence"] for c in inf["candidates"]
             if c["processor"] == "riscv"}
    assert 32 in confs and 64 in confs
    assert abs(confs[32] - confs[64]) < 0.05, inf


def test_opaque_rv64c_raw_blob_riscv64_clear(tmp_blob):
    path = tmp_blob(_rv64c())
    inf = infer_binary_arch_profile(path)
    top = _top_candidate(inf)
    assert top.get("processor") == "riscv", inf
    assert top.get("bitness") == 64, inf
    rv32 = next((c for c in inf["candidates"]
                 if c["processor"] == "riscv" and c["bitness"] == 32), None)
    assert rv32 is not None and top["confidence"] - rv32["confidence"] >= 0.4, inf
    # A clear bitness call must NOT be flagged ambiguous.
    assert inf.get("ambiguous") is not True, inf


# ---------------------------------------------------------------------------
# Absolute-signal confidence: capped, never inflated, and riscv gated off
# non-code samples
# ---------------------------------------------------------------------------

def test_absolute_confidence_is_capped_and_weak_blob_stays_low(tmp_blob):
    path = tmp_blob((b"\xe8" + (b"\x00" * 63)) * 8)
    inf = infer_binary_arch_profile(path)
    assert inf["file_kind"] == "raw"
    assert float(inf["confidence"]) < 0.1, inf
    for c in inf.get("candidates") or []:
        assert 0.0 <= c["confidence"] <= 1.0
    # The mostly-zero weak blob is not code and must not surface riscv.
    assert inf.get("looks_like_code") is False
    assert all(c["processor"] != "riscv" for c in inf.get("candidates") or [])
    assert inf.get("warning")


def test_riscv_gated_for_text_and_random(tmp_blob):
    text = (b"hello world this is a test of the emergency broadcast system "
            b"invoking a function call and returning a computed result " * 300)[:8192]
    random_blob = bytes(random.Random(99).randrange(256) for _ in range(8192))
    for name, blob in (("text", text), ("random", random_blob)):
        path = tmp_blob(blob, name=f"{name}.bin")
        inf = infer_binary_arch_profile(path)
        assert not any(c["processor"] == "riscv" for c in inf.get("candidates") or []), name
        assert inf.get("looks_like_code") is False, name


# ---------------------------------------------------------------------------
# load_base population (dominant lui/auipc + Cortex-M reset vector)
# ---------------------------------------------------------------------------

def test_load_base_from_dominant_lui_auipc(tmp_blob):
    blob = _rv64_highbase()
    assert _dominant_hi20(blob) == 0x80000000
    path = tmp_blob(blob)
    inf = infer_binary_arch_profile(path)
    assert inf.get("load_base") == 0x80000000
    assert "0x80000000" in inf["reason"]


def test_cortex_m_load_base_high_confidence_when_vector_table_plausible(tmp_blob):
    blob = struct.pack("<II", 0x20001000, 0x08000101) + (b"\x00" * 64)
    path = tmp_blob(blob)
    inf = infer_binary_arch_profile(path)
    assert inf["processor"] == "arm"
    assert inf["bitness"] == 32
    assert inf["load_base"] == 0x08000100
    assert float(inf["confidence"]) >= 0.9
    assert inf.get("warning") is None


def test_cortex_m_provisional_downgrade_on_garbage_vector_entries(tmp_blob):
    # Reset vector is Thumb-set, but the following words are even non-pointer
    # garbage — the guess is reported provisional at reduced confidence.
    blob = struct.pack("<II", 0x20001000, 0x08000101) + (struct.pack("<I", 0x41414140) * 14)
    head = blob[:64]
    assert _cortex_m_vector_plausible(head, 0x08000101) is False
    path = tmp_blob(blob)
    inf = infer_binary_arch_profile(path)
    assert inf["processor"] == "arm"
    assert inf["load_base"] == 0x08000100
    assert float(inf["confidence"]) < 0.7, inf
    assert "provisional" in inf["reason"]
    assert inf.get("warning")


# ---------------------------------------------------------------------------
# Proc aliases + prepared profile
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,canon,bits", [
    ("riscv64", "riscv", 64), ("rv64", "riscv", 64),
    ("riscv32", "riscv", 32), ("rv32", "riscv", 32),
    ("riscv", "riscv", None),
])
def test_riscv_proc_aliases_normalize(raw, canon, bits):
    out, _meta = normalize_arch_options({"processor": raw})
    assert out["processor"] == canon
    assert out.get("bitness") == bits


def test_prepared_profile_merges_inference_and_explicit_options():
    prof = prepared_profile(
        {"processor": "riscv", "bitness": 32, "endian": "little",
         "load_base": 0x10000000, "warning": "raw blob; arch unverified"},
        {"processor": "riscv64", "baseaddr": "0x20000000"},
    )
    # Explicit alias normalizes; explicit baseaddr overrides the inferred base.
    assert prof["processor"] == "riscv"
    assert prof["bitness"] == 64
    assert prof["load_base"] == 0x20000000
    assert "warning" in prof


# ---------------------------------------------------------------------------
# patterns.py helpers (shared entropy / instruction-validity)
# ---------------------------------------------------------------------------

def test_patterns_riscv_validity_and_entropy_helpers():
    rv32 = _rv32c()
    rv = riscv_instruction_validity(rv32)
    assert rv["valid_ratio"] > 0.5, rv
    assert rv["looks_like_riscv"] is True
    assert 3.0 <= byte_entropy(rv32) <= 7.9
    assert looks_like_code(rv32) is True
    # ASCII prose fails the printable gate.
    assert looks_like_code(b"the quick brown fox jumps over the lazy dog " * 40) is False
    # All zeros fail the zero-ratio gate.
    assert looks_like_code(b"\x00" * 4096) is False


# ---------------------------------------------------------------------------
# context_density.py: RISC-V ABI registers count as useful tokens
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("reg", [
    "a0", "a7", "t0", "t6", "s0", "s9", "s10", "s11", "ra", "gp", "tp", "zero",
])
def test_context_density_riscv_registers_are_useful(reg):
    assert _USEFUL_TOKEN_RE.search(reg)
    # A RISC-V-annotated line scores higher density than generic prose.
    riscv_line = f"addi {reg}, {reg}, 1 ; c.jr ra ; ld t0, 0(sp)"
    prose = "the system will compute a result and then return"
    d_rv = measure_information_density(riscv_line)
    d_prose = measure_information_density(prose)
    assert d_rv["useful_token_ratio"] > d_prose["useful_token_ratio"]


# ---------------------------------------------------------------------------
# idb.py: single-inference reuse, raw surfaces, GP probe off processor name
# ---------------------------------------------------------------------------

def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def test_idb_architecture_profile_dedup_and_raw_surfaces(monkeypatch):
    from tests._isolated_repo_loader import load_tool_module

    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_idb = lambda: None
    idaapi.get_inf_structure = lambda: None
    idc = types.ModuleType("idc")
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0
    ida_ida.inf_get_max_ea = lambda: 0x2000
    ida_ida.inf_get_cc_id = lambda: 0
    ida_ida.inf_get_baseaddr = lambda: 0
    ida_ida.inf_is_dll = lambda: False
    ida_ida.inf_is_be = lambda: False
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_input_file_path = lambda: "input.bin"
    ida_entry = types.ModuleType("ida_entry")
    _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
                    "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                    "ida_dbg", "idautils"])
    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_ida"] = ida_ida
    sys.modules["ida_nalt"] = ida_nalt
    sys.modules["ida_entry"] = ida_entry

    mod = load_tool_module(
        "idb",
        common_overrides={
            "idaapi": idaapi, "idc": idc,
            "_inf_filetype_id": lambda: 17,
            "_filetype_name": lambda ft: "raw",
            "_inf_procname": lambda: "riscv",
            "_inf_bitness": lambda: 64,
        },
    )
    # Star-imports skip underscore names; assign these helpers post-load.
    mod._inf_filetype_id = lambda: 17
    mod._filetype_name = lambda ft: "raw"
    mod._inf_procname = lambda: "riscv"
    mod._inf_bitness = lambda: 64
    mod.detect_riscv_gp = lambda: {"found": False}
    calls = {"n": 0}

    def _fake_infer(binary_path):
        calls["n"] += 1
        return {
            "file_kind": "raw",
            "processor": "riscv",
            "bitness": 64,
            "endian": "little",
            "load_base": 0x80000000,
            "warning": "raw blob; arch unverified",
            "candidates": [],
        }

    mod.infer_binary_arch_profile = _fake_infer

    meta = mod.idb_meta()
    assert calls["n"] == 1
    assert meta["inferred_arch_profile"]["file_kind"] == "raw"
    result = mod.idb_architecture_profile(meta=meta, summary={"imports": 0, "exports": 0})
    # Reuse: the profile action did NOT re-scan the file.
    assert calls["n"] == 1
    assert result["raw_binary_mode"] is True
    assert result["inferred_load_base"] == 0x80000000
    assert "raw blob; arch unverified" in result["raw_binary_warning"]
    assert "entrypoints_note" in result
    # GP probe fired from processor name "riscv" without is_riscv_family().
    assert result["riscv_gp"] == {"found": False}


def test_idb_gp_probe_fires_for_riscv_alias_processor(monkeypatch):
    """GP recommendation keys off the processor name; riscv64/riscv32 alias
    strings work and no is_riscv_family() dependency remains."""
    from tests._isolated_repo_loader import load_tool_module

    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_idb = lambda: None
    idaapi.get_inf_structure = lambda: None
    idc = types.ModuleType("idc")
    ida_ida = types.ModuleType("ida_ida")
    ida_entry = types.ModuleType("ida_entry")
    ida_nalt = types.ModuleType("ida_nalt")
    _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
                    "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                    "ida_dbg", "idautils"])
    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_ida"] = ida_ida
    sys.modules["ida_entry"] = ida_entry
    sys.modules["ida_nalt"] = ida_nalt

    mod = load_tool_module("idb", common_overrides={"idaapi": idaapi, "idc": idc})
    mod.detect_riscv_gp = lambda: {"found": True, "gp": 0x2A1000}

    def _meta(processor):
        return {
            "binary_path": "",
            "file_type_id": 17,
            "file_type_info": {"effective": "raw", "loader": "raw"},
            "file_type_effective": "raw",
            "processor": processor,
            "bitness": 64,
            "is_be": False,
        }

    for processor in ("riscv", "riscv64"):
        result = mod.idb_architecture_profile(meta=_meta(processor), summary={"imports": 0})
        gp_recs = [r for r in result["recommendations"] if "set_reg_value" in r]
        assert gp_recs, (processor, result["recommendations"])
        assert 'idc.set_reg_value("gp", 0x2a1000, idc.BADADDR)' in gp_recs[0]

    result = mod.idb_architecture_profile(meta=_meta("arm"), summary={"imports": 0})
    gp_recs = [r for r in result["recommendations"] if "set_reg_value" in r]
    assert not gp_recs


def test_idb_state_raw_blob_indicators(tmp_blob):
    from tests._isolated_repo_loader import load_tool_module

    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_idb_path = lambda: ""
    idaapi.get_input_file_path = lambda: ""
    idaapi.get_func_qty = lambda: 0
    idaapi.get_strlist_qty = lambda: 0
    idaapi.auto_state = lambda: 1
    idaapi.get_auto_display = lambda: ""
    idaapi.auto_is_ok = lambda: False
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_import_module_qty = lambda: 0
    ida_entry = types.ModuleType("ida_entry")
    ida_entry.get_entry_qty = lambda: 0
    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.get_cursor_ea = lambda: 0xFFFFFFFFFFFFFFFF
    idc = types.ModuleType("idc")
    _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
                    "ida_struct", "ida_ua", "ida_loader", "ida_dbg", "idautils"])
    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_nalt"] = ida_nalt
    sys.modules["ida_entry"] = ida_entry
    sys.modules["ida_kernwin"] = ida_kernwin
    # idb.py imports ida_ida at module scope; without a stub the real IDA
    # install on sys.path is loaded and fails on the native _ida_ida bindings.
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0
    ida_ida.inf_get_max_ea = lambda: 0x2000
    ida_ida.inf_get_cc_id = lambda: 0
    ida_ida.inf_get_baseaddr = lambda: 0
    ida_ida.inf_is_dll = lambda: False
    ida_ida.inf_is_be = lambda: False
    sys.modules["ida_ida"] = ida_ida

    mod = load_tool_module("idb", common_overrides={"idaapi": idaapi, "idc": idc})

    # A raw blob whose input path exists on disk (magic probe sees no known
    # container header) plus zero functions -> raw_blob + arch_unverified.
    path = tmp_blob(b"\x11\x22\x33\x44\x55\x66\x77\x88" + bytes(range(256)) * 4)
    idaapi.get_input_file_path = lambda: path
    state = mod.idb_state()
    ind = state["indicators"]
    assert ind["raw_blob"] is True
    assert ind["arch_unverified"] is True
    assert ind["looks_empty"] is True

    # A known container (ELF magic) is NOT a raw blob.
    elf = b"\x7fELF" + (b"\x00" * 64)
    elf_path = tmp_blob(elf, name="elf.bin")
    idaapi.get_input_file_path = lambda: elf_path
    state2 = mod.idb_state()
    assert state2["indicators"]["raw_blob"] is False
