"""Regression tests for swarm/q01_riscv — RISC-V / opaque raw-blob reliability.

q01 makes the MCP more reliable, faster, and more useful than radare2 on opaque
device binaries (raw headerless .bin firmware, especially RISC-V).  Each test
pins one of the fixes:

1. arch_utils RISC-V operand-aware return classification — ``jalr x0, 0(ra)``
   and ``c.jr ra`` are returns; ``jalr ra, 0(t0)`` is a call; ``c.jalr`` is
   always a call.  Numeric ``x0/x1`` register forms and the raw ``jalr x0,x1,0``
   immediate form are classified identically to the ABI-name forms.
2. arch_utils mnemonic-set completeness for RISC-V (c.jal/c.jalr calls, beq/bne
   conditional branches, slt/sltu comparisons, li/lui/lui MOVs, compressed C
   extension under UNCONDITIONAL_JUMP / TERMINATOR).  ``c.jal`` stays RV32C-only
   in get_tail_call_mnemonics.
3. arch_utils detect_riscv_gp recovers GP from both ``lui``+``addi`` and
   ``auipc``+``addi`` prologues and emits a crisp hint on opaque raw blobs.
4. query_lang MATCH call / MATCH instruction route to exact-mnemonic
   ``search_insns`` (arch-aware call-alias set) instead of the loose semantic
   search, dedup by address, and propagate tool errors instead of a false
   ``{ok: True, total: 0}`` success.
5. funcs metrics driven by the arch-aware classifier sets — a RISC-V function
   counts jal/c.jalr as calls, jalr-zero/c.jr-ra as returns, beq as a
   conditional branch, and does not double-count conditional branches as jumps.
6. funcs create failure hint is arch-aware (RISC-V note + raw-blob note).
7. segments add derives permissions from ``sclass`` so a CODE segment added to
   an opaque .bin is analyzed as code (READ|EXEC) instead of silently as data.
8. analysis get_options warns on raw blobs (bytes may misdecode under the
   current processor); set_architecture emits RISC-V arch hints; reanalysis of
   a raw blob with no executable segment falls back to the whole mapped range
   and reports a warning; _bootstrap_raw_entry_points seeds RISC-V reset
   ``j``/``jal`` branches and ISR pointer tables (LE u32/BE u32/LE u16) and
   registers them via ida_entry.add_entry.

Host-side tests: ida_* modules are stubbed; no live IDA session required.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import (
    install_common_stub,
    load_ida_module,
    load_support_module,
    load_tool_module,
)

_EH_CACHE = {}


def _real_eh_overrides():
    """Real IDA-side error envelope so assertions match production make_error().

    funcs/analysis return real {error, code, category, message, hint, ...} dicts;
    the isolated-loader stub's make_error only takes (code, message) and would
    raise on the 3-arg create-failure hint call.
    """
    eh = _EH_CACHE.get("eh")
    if eh is None:
        eh = load_ida_module("error_handling")
        _EH_CACHE["eh"] = eh
    return {
        "make_error": eh.make_error,
        "MCPError": eh.MCPError,
        "handle_error": eh.handle_error,
        "ERROR_HINTS": eh.ERROR_HINTS,
    }


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def _riscv_inf(procname="RISCV:RVA", is_64=False, filetype=17, min_ea=0x1000, max_ea=0x2000):
    return types.SimpleNamespace(
        procname=procname,
        is_64bit=lambda: is_64,
        filetype=filetype,
        min_ea=min_ea,
        max_ea=max_ea,
    )


def _fresh_arch():
    """install_common_stub + load arch_utils so get_arch() sees the stubbed
    idaapi (arch_utils.idaapi binds at import time)."""
    install_common_stub()
    return load_support_module("arch_utils")


# ---------------------------------------------------------------------------
# arch_utils: RISC-V operand-aware return classification
# ---------------------------------------------------------------------------

def test_riscv_c_jr_ra_return_vs_c_jr_t0_jump():
    au = _fresh_arch()
    assert au.is_return_mnemonic("c.jr", "c.jr ra", "riscv") is True
    assert au.is_return_mnemonic("c.jr", "c.jr x1", "riscv") is True
    assert au.is_return_mnemonic("c.jr", "c.jr t0", "riscv") is False
    assert au.is_return_mnemonic("c.jr", "c.jr a0", "riscv") is False


def test_riscv_numeric_jalr_x0_x1_0_is_return():
    au = _fresh_arch()
    # IDA renders jalr in both `jalr rd, imm(rs1)` and `jalr rd, rs1, imm` forms;
    # numeric x0/x1 must classify identically to ABI-name zero/ra.
    for disasm in (
        "jalr zero, 0(ra)",
        "jalr x0, 0(x1)",
        "jalr zero, ra, 0",
        "jalr x0, x1, 0",
    ):
        assert au.is_return_mnemonic("jalr", disasm, "riscv") is True, disasm
    # jalr with a link register (rd=ra) is a call; rd=x0 with rs1!=ra is a jump.
    assert au.is_return_mnemonic("jalr", "jalr ra, 0(t0)", "riscv") is False
    assert au.is_return_mnemonic("jalr", "jalr x0, 0(t0)", "riscv") is False


def test_riscv_c_jalr_is_always_a_call_never_a_return():
    au = _fresh_arch()
    # c.jalr always links to ra — a CALL, never a return, even when the
    # disasm shows only the ra operand.
    assert au.is_return_mnemonic("c.jalr", "c.jalr ra", "riscv") is False
    assert au.is_call_mnemonic("c.jalr", "riscv") is True


def test_riscv_mret_sret_uret_are_returns():
    au = _fresh_arch()
    for m in ("ret", "mret", "sret", "uret"):
        assert au.is_return_mnemonic(m, m, "riscv") is True


# ---------------------------------------------------------------------------
# arch_utils: RISC-V mnemonic sets
# ---------------------------------------------------------------------------

def test_riscv_call_and_jump_sets():
    au = _fresh_arch()
    # Calls
    for m in ("jal", "jalr", "c.jal", "c.jalr"):
        assert m in au.CALL_MNEMONICS, m
        assert au.is_call_mnemonic(m, "riscv") is True, m
    # Register-indirect / unconditional transfer stays in the jump + terminator
    # sets (is_return_mnemonic does the operand-aware reclassification).
    for m in ("jal", "jalr", "c.j", "c.jr", "c.jal", "c.jalr"):
        assert m in au.UNCONDITIONAL_JUMP_MNEMONICS, m
        assert m in au.TERMINATOR_MNEMONICS, m


def test_riscv_conditional_branches_and_comparisons():
    au = _fresh_arch()
    for m in ("beq", "bne", "blt", "bge"):
        assert m in au.CONDITIONAL_BRANCH_MNEMONICS, m
    for m in ("slt", "sltu"):
        assert m in au.COMPARISON_MNEMONICS, m


def test_riscv_mov_arithmetic_and_xor_sets():
    au = _fresh_arch()
    for m in ("li", "lui", "la", "mv"):
        assert m in au.MOV_MNEMONICS, m
    for m in ("addi", "add", "sub", "mul", "mulhu", "lui", "li", "xori", "andi", "ori"):
        assert m in au.ARITHMETIC_MNEMONICS, m
    for m in ("xor", "xori"):
        assert m in au.XOR_MNEMONICS, m


def test_tail_call_mnemonics_keep_c_jal_rv32c_only():
    au = _fresh_arch()
    # c.jal is a compressed call (RV32C only) — RV64C omits it.
    assert au.get_tail_call_mnemonics("riscv") == {"j", "jal", "c.j", "c.jal"}
    assert au.get_tail_call_mnemonics("riscv64") == {"j", "jal", "c.j"}


# ---------------------------------------------------------------------------
# arch_utils: detect_riscv_gp — lui+addi, auipc+addi, raw-blob fallback
# ---------------------------------------------------------------------------

class _GpFakeIda:
    """Minimal IDA fakes for detect_riscv_gp."""

    def __init__(self, seq):
        install_common_stub()
        self.idc = sys.modules["idc"]
        self.idc.BADADDR = -1
        self.idc.INF_MIN_EA = 0x1000
        self.idc.get_inf_attr = lambda attr: 0x1000
        self.idc.next_head = lambda ea, end: ea + 4
        self.idc.get_name_ea_simple = lambda name: -1
        sys.modules["idautils"].Entries = lambda: iter([])
        self._seq = seq

    def install(self):
        seq = self._seq
        self.idc.print_insn_mnem = lambda ea: seq.get(ea, ("", "", 0))[0]
        self.idc.print_operand = lambda ea, n: (
            seq.get(ea, ("", "", 0))[1] if n == 0 else ""
        )
        # Immediate operands are the RAW field bits: the detector sign-extends
        # the 12-bit addi immediate and the 20-bit lui/auipc immediate itself.
        self.idc.get_operand_value = lambda ea, n: seq.get(ea, ("", "", 0))[2]


def test_detect_riscv_gp_lui_addi_prologue():
    au = _fresh_arch()
    au._apply_riscv_gp = lambda gp_val: (True, None, False, {})
    au._riscv_gp_note = lambda *a: "gp-note"
    fake = _GpFakeIda({
        0x1000: ("lui", "gp", 0x20),       # gp = 0x20 << 12
        0x1004: ("addi", "gp", 0xFEE),     # raw 12-bit field of -0x12
    })
    fake.install()
    res = au.detect_riscv_gp()
    assert res["found"] is True, res
    assert res["gp"] == 0x20000 - 0x12, res  # 0x1FFEE
    assert res["gp_hex"] == hex(0x1FFEE), res


def test_detect_riscv_gp_auipc_addi_prologue():
    au = _fresh_arch()
    au._apply_riscv_gp = lambda gp_val: (True, None, False, {})
    au._riscv_gp_note = lambda *a: "gp-note"
    fake = _GpFakeIda({
        0x1000: ("auipc", "gp", 0x2),
        0x1004: ("addi", "gp", 0x30),
    })
    fake.install()
    res = au.detect_riscv_gp()
    assert res["found"] is True, res
    assert res["gp"] == 0x1000 + (2 << 12) + 0x30, res


def test_detect_riscv_gp_raw_blob_fallback_hint():
    au = _fresh_arch()
    fake = _GpFakeIda({})
    fake.install()
    res = au.detect_riscv_gp()
    assert res["found"] is False, res
    assert "GP not found" in res["note"]
    assert "set_gp" in res["note"]
    # The hint proposes candidate bases derived from the load base (INF_MIN_EA).
    assert "0x1000" in res["note"]


# ---------------------------------------------------------------------------
# query_lang: MATCH call / MATCH instruction exact-mnemonic routing
# ---------------------------------------------------------------------------

def _ql_plan(target, identifier, conditions=None):
    return {
        "target": target, "identifier": identifier,
        "conditions": conditions or [], "limit": 100,
        "sort_key": None, "sort_order": "ASC", "group_key": None,
    }


def test_query_call_alias_set_is_arch_aware():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    assert ql.QueryExecutor()._call_alias_set() == sorted({"jal", "jalr", "c.jal", "c.jalr"})
    ql._get_arch = lambda: "x64"
    assert ql.QueryExecutor()._call_alias_set() == ["call"]
    ql._get_arch = lambda: "unknown"
    assert set(ql.QueryExecutor()._call_alias_set()) == set(ql._CALL_MNEMONICS)


def test_query_call_star_routes_to_exact_search_insns_over_riscv_aliases():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True,
        "results": "0x1000  [jal]\n0x1004  [jalr]\n0x1008  [c.jal]",
    }
    res = ql.QueryExecutor()._execute_call(_ql_plan("call", "*"))
    assert res["ok"] is True and res["returned"] == 3, res
    # Every alias searched with exact-mnemonic search_insns.
    searched = {c[1]["pattern"] for c in calls}
    assert searched == {"jal", "jalr", "c.jal", "c.jalr"}, searched
    assert all(c[0] == "search" and c[1]["action"] == "insns" for c in calls), calls


def test_query_call_named_alias_searches_only_that_alias():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True, "results": "0x1000  [jalr]",
    }
    res = ql.QueryExecutor()._execute_call(_ql_plan("call", "jalr"))
    assert res["returned"] == 1, res
    assert len(calls) == 1 and calls[0][1]["pattern"] == "jalr", calls


def test_query_call_dedups_by_address_across_aliases():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    ql._call_tool = lambda name, **kw: {
        "ok": True, "results": "0x1000  [jal]\n0x1000  [jalr]",
    }
    res = ql.QueryExecutor()._execute_call(_ql_plan("call", "*"))
    assert res["returned"] == 1, res


def test_query_call_propagates_tool_error():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    ql._call_tool = lambda name, **kw: {
        "error": True, "code": "IDA_ERROR", "message": "search failed",
    }
    res = ql.QueryExecutor()._execute_call(_ql_plan("call", "*"))
    assert res.get("error") is True and res.get("code") == "IDA_ERROR", res
    assert res.get("ok") is not True


def test_query_instruction_routes_to_exact_search_insns():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True, "matches": "0x1000  [ecall]",
    }
    res = ql.QueryExecutor()._execute_instruction(_ql_plan("instruction", "ecall"))
    assert res["returned"] == 1, res
    assert calls[0][1]["action"] == "insns" and calls[0][1]["pattern"] == "ecall", calls


def test_query_instruction_wildcard_uses_star_pattern():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True, "results": "",
    }
    ql.QueryExecutor()._execute_instruction(_ql_plan("instruction", "*"))
    assert calls[0][1]["pattern"] == "*", calls


def test_query_instruction_propagates_tool_error():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: {
        "error": True, "code": "TOOL_ERROR", "message": "x",
    }
    res = ql.QueryExecutor()._execute_instruction(_ql_plan("instruction", "ecall"))
    assert res.get("error") is True and res.get("code") == "TOOL_ERROR", res


# ---------------------------------------------------------------------------
# funcs metrics: arch-aware classification of a RISC-V function
# ---------------------------------------------------------------------------

# c.* instructions are 2 bytes; standard RISC-V insns are 4 bytes.
_RISCV_FN_INSNS = [
    (0x1000, "addi",   "addi sp, sp, -16", 4),
    (0x1004, "jal",    "jal 0x2000", 4),          # call
    (0x1008, "jalr",   "jalr ra, 0(t0)", 4),      # call
    (0x100c, "c.jalr", "c.jalr ra", 2),           # call
    (0x100e, "beq",    "beq a0, a1, 0x1010", 4),  # conditional branch
    (0x1012, "jalr",   "jalr zero, 0(ra)", 4),    # return
    (0x1016, "c.jr",   "c.jr ra", 2),             # return
]


class _MetricsFC:
    def __init__(self, fn):
        self._blocks = [_MetricsBB(fn.start_ea, fn.end_ea)]

    def __iter__(self):
        return iter(self._blocks)


class _MetricsBB:
    def __init__(self, s, e):
        self.start_ea = s
        self.end_ea = e

    def succs(self):
        return []


def _load_funcs_with_riscv(au, idaapi, idc, ida_funcs, overrides=None, module_attrs=None):
    """load_tool_module('funcs') with the real arch_utils classifier injected.

    The isolated _common stub has no __all__, so the ``from ._common import *``
    in funcs.py skips underscore-prefixed helpers (_inf_filetype_id etc.); set
    those directly on the loaded module (``module_attrs``) as the production
    package's real __all__ would.
    """
    common_overrides = {
        "get_arch": lambda: "riscv",
        "is_riscv_family": au.is_riscv_family,
        "is_call_mnemonic": au.is_call_mnemonic,
        "is_return_mnemonic": au.is_return_mnemonic,
        "UNCONDITIONAL_JUMP_MNEMONICS": au.UNCONDITIONAL_JUMP_MNEMONICS,
        "CONDITIONAL_BRANCH_MNEMONICS": au.CONDITIONAL_BRANCH_MNEMONICS,
        "idaapi": idaapi,
        "idc": idc,
        "ida_funcs": ida_funcs,
    }
    if overrides:
        common_overrides.update(overrides)
    mod = load_tool_module("funcs", common_overrides=common_overrides)
    if module_attrs:
        for key, value in module_attrs.items():
            setattr(mod, key, value)
    return mod


def test_funcs_metrics_riscv_classification():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    ida_funcs = sys.modules["ida_funcs"]

    idaapi.get_inf_structure = _riscv_inf
    idaapi.f_BIN = 17
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.FlowChart = _MetricsFC

    imap = {ea: (m, d) for ea, m, d, _ in _RISCV_FN_INSNS}
    addrs = sorted(imap)

    def _next(ea, end):
        for a in addrs:
            if a > ea and a < end:
                return a
        return end

    idc.print_insn_mnem = lambda ea: imap.get(ea, ("", ""))[0]
    idc.generate_disasm_line = lambda ea, flags: imap.get(ea, ("", ""))[1]
    ida_funcs.get_func = lambda ea: types.SimpleNamespace(
        start_ea=0x1000, end_ea=0x1018, flags=0,
    )
    ida_funcs.get_func_name = lambda ea: "fn_1000"
    idc.get_func_name = lambda ea: "fn_1000"

    mod = _load_funcs_with_riscv(au, idaapi, idc, ida_funcs)
    # install_common_stub inside load_tool_module resets idc.next_head — set it
    # AFTER load so the metrics loop walks actual instruction boundaries.
    idc.next_head = _next

    res = mod.funcs(action="metrics", addr="0x1000")
    m = res["metrics"]
    assert m["call_count"] == 3, m
    assert m["return_count"] == 2, m
    assert m["conditional_jump_count"] == 1, m
    assert m["jump_count"] == 0, m  # beq is a conditional branch, not a jump
    assert m["instruction_count"] == 7, m


def test_funcs_create_failure_hint_is_riscv_and_raw_aware():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    ida_funcs = sys.modules["ida_funcs"]

    idaapi.get_inf_structure = _riscv_inf
    idaapi.f_BIN = 17
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    ida_funcs.get_func = lambda ea: None
    # _ensure_code_at: is_code False, and instruction creation always fails.
    idc.create_insn = lambda ea: 0
    ida_bytes = sys.modules["ida_bytes"]
    ida_bytes.get_flags = lambda ea: 0
    ida_bytes.is_code = lambda flags: False
    ida_bytes.del_items = lambda *a, **k: True

    mod = _load_funcs_with_riscv(
        au, idaapi, idc, ida_funcs,
        overrides=_real_eh_overrides(),
        module_attrs={
            "_inf_filetype_id": lambda: 17,
            "_inf_procname": lambda: "RISCV:RVA",
        },
    )
    res = mod.funcs(action="create", addr="0x1000", name="handler")
    assert res.get("error") is True, res
    assert res.get("code") == "ADDRESS_INVALID", res
    hint = res.get("hint", "")
    assert "RISC-V" in hint and "set_gp" in hint, hint
    assert "Raw blob" in hint and "set_architecture" in hint, hint


# ---------------------------------------------------------------------------
# segments add: perms derived from sclass
# ---------------------------------------------------------------------------

def _segment_t():
    class _SegT:
        def __init__(self):
            self.start_ea = 0
            self.end_ea = 0
            self.perm = 0

    return _SegT()


def _load_segments(record):
    install_common_stub()
    # parse_address_safe is imported by segments from error_handling directly.
    load_ida_module("error_handling")
    idaapi = sys.modules["idaapi"]
    idaapi.SEGPERM_READ = 1
    idaapi.SEGPERM_WRITE = 2
    idaapi.SEGPERM_EXEC = 4
    idaapi.segment_t = _segment_t
    idaapi.getseg = lambda ea: None
    idaapi.add_segm_ex = lambda seg, name, sclass, flags: record.append(
        (seg, name, sclass)
    ) or True
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    sys.modules["ida_segment"].getseg = idaapi.getseg
    sys.modules["ida_segment"].get_segm_name = lambda seg: "seg"
    return load_tool_module("segments")


def _add_code(record):
    seg, name, sclass = record[0]
    assert name == ".mmio" and sclass == "CODE"
    return seg


def test_segments_add_code_sets_read_exec_perms():
    record = []
    mod = _load_segments(record)
    res = mod.segments(action="add", start="0x1000", end="0x2000", name=".mmio", sclass="CODE")
    assert res["ok"] is True, res
    seg = _add_code(record)
    assert seg.perm == (1 | 4), seg.perm  # READ | EXEC
    assert res["perms"] == "rx", res
    assert "READ|EXEC" in res["note"], res


def test_segments_add_xtrn_sets_read_exec_perms():
    record = []
    mod = _load_segments(record)
    res = mod.segments(action="add", start="0x1000", end="0x2000", name="ext", sclass="XTRN")
    assert res["ok"] is True, res
    seg = record[0][0]
    assert seg.perm == (1 | 4), seg.perm


def test_segments_add_bss_sets_read_write_perms():
    record = []
    mod = _load_segments(record)
    res = mod.segments(action="add", start="0x1000", end="0x2000", name=".bss", sclass="BSS")
    assert res["ok"] is True, res
    seg = record[0][0]
    assert seg.perm == (1 | 2), seg.perm  # READ | WRITE


def test_segments_add_data_defaults_to_read_only():
    record = []
    mod = _load_segments(record)
    res = mod.segments(action="add", start="0x1000", end="0x2000", name=".data", sclass="DATA")
    assert res["ok"] is True, res
    seg = record[0][0]
    assert seg.perm == 1, seg.perm  # READ only


def test_segments_add_empty_sclass_hints_set_perms():
    record = []
    mod = _load_segments(record)
    res = mod.segments(action="add", start="0x1000", end="0x2000", name=".rom", sclass="")
    assert res["ok"] is True, res
    assert "set_perms" in res.get("note", ""), res


# ---------------------------------------------------------------------------
# analysis: raw-blob warnings, RISC-V arch hints, raw-no-exec reanalysis,
#           RISC-V entry seeding
# ---------------------------------------------------------------------------

def _blank_analysis_ida_modules():
    # analysis.py imports ida_ida and ida_entry at module top; the loader stub
    # only provides the rest.
    _blank_modules(["ida_ida", "ida_entry"])


def _load_analysis(au, idc, idaapi, overrides=None, module_attrs=None):
    _blank_analysis_ida_modules()
    idaapi.f_BIN = 17
    idaapi.f_BINARY = 17
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.SEGPERM_EXEC = 4
    idaapi.SETPROC_LOADER = 0
    idaapi.SETPROC_LOADER_NON_FATAL = 1
    common_overrides = {
        "get_arch": lambda: "riscv",
        "is_riscv_family": au.is_riscv_family,
        "is_arm_family": au.is_arm_family,
        "idaapi": idaapi,
        "idc": idc,
        **_real_eh_overrides(),
    }
    if overrides:
        common_overrides.update(overrides)
    mod = load_tool_module("analysis", common_overrides=common_overrides)
    # Underscore helpers are skipped by the star import (stub _common has no
    # __all__); bind them directly as production's real __all__ would.
    defaults = {"_inf_is_64bit": lambda: False}
    if module_attrs:
        defaults.update(module_attrs)
    for key, value in defaults.items():
        setattr(mod, key, value)
    return mod


def test_analysis_get_options_warns_on_raw_blob():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    idaapi.inf_get_start_ea = lambda: 0x1000
    idaapi.inf_get_min_ea = lambda: 0x1000
    idaapi.inf_get_max_ea = lambda: 0x2000
    mod = _load_analysis(
        au, idc, idaapi,
        module_attrs={
            "_inf_procname": lambda: "RISCV:RVA",
            "_inf_filetype_id": lambda: 17,
            "_inf_bitness": lambda: 32,
            "_inf_is_be": lambda: False,
            "_filetype_name": lambda ft: "raw" if ft == 17 else f"type_{ft}",
        },
    )
    res = mod.analysis(action="get_options")
    assert res["ok"] is True, res
    assert res["file_type_info"]["loader"] == "raw", res
    assert res["warnings"], res
    assert "raw blob" in res["warnings"][0], res
    assert "set_architecture" in res["warnings"][0], res


def test_analysis_set_architecture_riscv_arch_hints():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    inf = _riscv_inf(procname="")
    idaapi.get_inf_structure = lambda: inf
    idaapi.set_processor_type = lambda proc, flags: True
    mod = _load_analysis(au, idc, idaapi)
    res = mod.analysis(action="set_architecture", processor="riscv:rv32", bitness=32)
    assert res["ok"] is True, res
    hints = res["applied"].get("arch_hints", {})
    assert hints.get("ptr_size") == 4, hints
    assert hints.get("default_int_width") == 4, hints
    assert "riscv_note" in hints, hints
    assert "set_gp" in hints["riscv_note"], hints


def test_analysis_set_architecture_riscv64_ptr_size():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    inf = _riscv_inf(procname="", is_64=False)
    idaapi.get_inf_structure = lambda: inf
    idaapi.set_processor_type = lambda proc, flags: True
    mod = _load_analysis(
        au, idc, idaapi,
        module_attrs={"_inf_is_64bit": lambda: True},
    )
    res = mod.analysis(action="set_architecture", processor="riscv:rv64", bitness=64)
    assert res["ok"] is True, res
    hints = res["applied"].get("arch_hints", {})
    assert hints.get("ptr_size") == 8, hints


def _raw_filetype_idc(idc):
    """Apply idc fakes so _is_raw_bin_filetype() sees f_BIN and
    _raw_mapped_range() sees the mapped range via INF_* attrs.

    Must run AFTER load_tool_module: install_common_stub resets
    ``idc.get_inf_attr``/``idc.next_head`` unconditionally."""
    idc.INF_FILETYPE = 1
    idc.INF_MIN_EA = 2
    idc.INF_MAX_EA = 3
    idc.get_inf_attr = lambda attr: {1: 17, 2: 0x1000, 3: 0x3000}.get(attr, 0)
    idc.print_insn_mnem = lambda ea: ""
    idc.next_head = lambda ea, end: ea + 4
    idc.create_insn = lambda ea: 4
    return idc


def test_find_text_segments_raw_blob_falls_back_to_mapped_range():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    sys.modules["idautils"].Segments = lambda: iter([])
    mod = _load_analysis(au, idc, idaapi)
    _raw_filetype_idc(idc)
    ranges = mod._find_text_segments()
    # Whole mapped range (from the inf structure's min/max EA) is returned as
    # a single "<raw-mapped>" pseudo-range once no executable segment exists.
    assert ranges == [(0x1000, 0x2000, "<raw-mapped>")], ranges


def test_auto_reanalyze_text_segments_raw_warning():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    idaapi.get_func_qty = lambda: 0
    idaapi.getseg = lambda ea: None
    idaapi.auto_is_ok = lambda: True
    sys.modules["idautils"].Segments = lambda: iter([])
    ida_auto = types.ModuleType("ida_auto")
    ida_auto.plan_range = lambda s, e: None
    ida_auto.AU_FINAL = 1
    sys.modules["ida_auto"] = ida_auto
    # _bootstrap_raw_entry_points runs first; feed it bytes that yield no
    # candidates so seeding is a deterministic no-op.
    sys.modules["ida_bytes"].get_bytes = lambda ea, size: b"\x00" * size

    mod = _load_analysis(au, idc, idaapi)
    _raw_filetype_idc(idc)
    res = mod._auto_reanalyze_text_segments(wait_seconds=0)
    assert res["scheduled"] == 1, res
    assert res["eligible_ranges"][0]["name"] == "<raw-mapped>", res
    assert res["warning"], res
    assert "no executable segments" in res["warning"], res
    assert "set_perms" in res["warning"], res


def _bootstrap_ida(au, idaapi, idc, data, mnem_map=None, operand_map=None):
    """Fakes so _bootstrap_raw_entry_points runs against a raw RISC-V blob."""
    _blank_modules(["ida_entry", "ida_ida"])
    idaapi.get_func = lambda ea: None
    sys.modules["ida_bytes"].get_bytes = lambda ea, size: data
    idc.print_insn_mnem = lambda ea: (mnem_map or {}).get(ea, "")
    idc.get_operand_value = lambda ea, n: (operand_map or {}).get((ea, n), 0)
    idc.next_head = lambda ea, end: ea + 4 if ea + 4 < end else end
    idc.create_insn = lambda ea: 4
    ida_funcs = sys.modules["ida_funcs"]
    ida_funcs.add_func = lambda ea: True
    # compat.get_func_* resolves ida_funcs via sys.modules and may run either
    # feature-detection branch; expose the legacy get_func plus the 9.4 EA
    # surface (these fixtures seed no existing functions, so lookups miss).
    ida_funcs.get_func = idaapi.get_func
    ida_funcs.get_func_start = lambda ea: -1
    ida_funcs.ida_idaapi = types.ModuleType("ida_idaapi")
    ida_funcs.ida_idaapi.BADADDR = -1
    ida_funcs.func_entry_info_t = types.SimpleNamespace
    ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False
    ida_funcs.get_func_flags = lambda ea: None
    ida_funcs.set_func_flags = lambda ea, flags: True
    ida_entry = sys.modules["ida_entry"]
    added = []
    ida_entry._q01_added = added
    ida_entry.get_entry_qty = lambda: len(added)
    ida_entry.add_entry = lambda ordinal, ea, name, flags: added.append(
        (ordinal, ea, name, flags)
    ) or True
    return added


def test_bootstrap_raw_entry_points_riscv_reset_j():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    data = b"\x00" * 0x40
    # Reset `j` at the image head jumps to 0x1800 (inside the image).
    added = _bootstrap_ida(
        au, idaapi, idc, data,
        mnem_map={0x1000: "j"},
        operand_map={(0x1000, 0): 0x1800},
    )
    mod = _load_analysis(au, idc, idaapi)
    boot = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert boot["seeded_entries"] == 1, boot
    assert added, added
    assert added[0][1] == 0x1800, added
    assert added[0][3] == 0, added  # flags arg passed positionally


def test_bootstrap_raw_entry_points_riscv_isr_table():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    import struct
    data = bytearray(b"\x00" * 0x40)
    # ISR pointer table: an LE u32 target at offset 4 (vector tables usually
    # skip the first entry/reset slot).
    data[4:8] = struct.pack("<I", 0x1500)
    added = _bootstrap_ida(au, idaapi, idc, bytes(data))
    mod = _load_analysis(au, idc, idaapi)
    boot = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert boot["seeded_entries"] >= 1, boot
    # The LE u32 ISR pointer at offset 4 is seeded (the dual-endian scan may
    # additionally map the image base from the BE interpretation of the same
    # word — that is expected noise, not a missing candidate).
    seeded_eas = [ea for _, ea, _, _ in added]
    assert 0x1500 in seeded_eas, added


def test_bootstrap_raw_entry_points_riscv_auipc_jalr_branch():
    au = _fresh_arch()
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure = _riscv_inf
    data = b"\x00" * 0x40
    # auipc ra, 0 ; jalr ra, 0x100(ra) -> target = 0x1000 + 0x100 = 0x1100
    _bootstrap_ida(
        au, idaapi, idc, data,
        mnem_map={0x1000: "auipc", 0x1004: "jalr"},
        operand_map={(0x1000, 1): 0, (0x1004, 2): 0x100},
    )
    mod = _load_analysis(au, idc, idaapi)
    # install_common_stub inside load_tool_module resets idc.next_head — restore
    # the boundary walker so the auipc->jalr long-branch probe finds the jalr.
    idc.next_head = lambda ea, end: ea + 4 if ea + 4 < end else end
    added = sys.modules["ida_entry"]._q01_added
    boot = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert boot["seeded_entries"] == 1, boot
    assert added[0][1] == 0x1100, added
