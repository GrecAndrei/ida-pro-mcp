"""Cross-mode offline coverage for code-helper analysis boundaries."""

from __future__ import annotations

import importlib
import sys
import types

import ida_hexrays

from tests.fakes.ida_fake import (
    BADADDR,
    FakeTinfo,
    cexpr_t,
    cfunc_t,
    cot_call,
    cot_obj,
    lvar_t,
    var_ref_t,
)
from tests.test_ida_mcp.test_code_helpers_ctree_modes import (
    _Args,
    _body,
    _call,
    _install_ctree_surface,
    _num,
    _var,
)


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_expression_rows_and_dataflow_cover_empty_duplicate_and_call_edges(monkeypatch):
    helpers = _helpers()
    _install_ctree_surface(monkeypatch)
    cfunc = cfunc_t(
        entry_ea=0x1000,
        body=_body([_num(1)]),
        lvars=[lvar_t("dst", FakeTinfo()), lvar_t("src", FakeTinfo(), is_arg_var=True)],
    )
    rows = helpers._collect_expr_rows_from_cfunc(cfunc, max_items=1)
    assert rows and rows[0][1] == "1"

    monkeypatch.setattr(
        helpers,
        "_collect_expr_rows_from_cfunc",
        lambda *_a, **_k: [
            (BADADDR, "dst = src"),
            (0x1001, "dst = src"),
            (0x1002, "consume(src)"),
            (0x1003, ""),
        ],
    )
    graph = helpers._build_decompiler_dataflow(cfunc)
    assert graph["assignment_edges"] == 1
    assert graph["call_edges"] == 1
    assert graph["argument_variables"] == ["src"]

    class BrokenLvars:
        @property
        def lvars(self):
            raise RuntimeError("lvars unavailable")

    assert helpers._build_decompiler_dataflow(BrokenLvars())["nodes"] == []


def test_rename_and_type_helpers_cover_argument_fallbacks_and_sdk_failures():
    helpers = _helpers()

    class BadType:
        def __call__(self):
            raise RuntimeError("type unavailable")

    class Cfunc:
        type = "char * data size"

        def __str__(self):
            return ""

        lvars = [
            types.SimpleNamespace(name="a1", type=BadType()),
            types.SimpleNamespace(name="a2", type=None),
        ]

    hints = helpers._extract_var_rename_hints(Cfunc())
    assert {hint["suggested"] for hint in hints} == {"buf", "size"}

    class BrokenCfunc:
        @property
        def lvars(self):
            raise RuntimeError("lvars unavailable")

    assert helpers._extract_var_rename_hints(BrokenCfunc()) == []

    class BrokenTinfo:
        def dstr(self):
            raise RuntimeError("dstr unavailable")

    class BrokenType:
        def __call__(self):
            return BrokenTinfo()

    assert helpers._lvar_type_str(types.SimpleNamespace(type=BrokenType())) == ""
    assert helpers._lvar_type_str(types.SimpleNamespace(type=None)) == ""


def test_firmware_signal_scan_handles_instruction_failures_fallback_and_safety(monkeypatch):
    helpers = _helpers()
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: True)
    mnemonics = {0x1000: "ecall", 0x1001: "csrrw", 0x1002: "sw", 0x1003: "lui"}
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnemonics.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 1)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda *_a: 0x50000000)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(helpers, "_store_memory_target", lambda _ea: 0x50001000)
    signals = helpers._detect_firmware_signals(0x1000)
    assert {"syscall:ecall", "csr_access:csrrw", "mmio_store:0x50001000", "large_constant_load:0x50000000"} <= set(signals)

    calls = iter([RuntimeError("bad instruction"), ""])

    def failing_mnem(_ea):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=1, end_ea=3))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", failing_mnem)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 1)
    fallback = helpers._detect_firmware_signals(1, "refs 0x40000001 0x50000002 0x60000003")
    assert fallback[:2] == ["constant_ref:0x40000001", "constant_ref:0x50000002"]

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=1, end_ea=100000))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "")
    assert helpers._detect_firmware_signals(1) == []


def test_decompile_diagnostics_retries_and_reports_failure_details(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True, raising=False)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)

    class Failure:
        def __init__(self):
            self.code = 50735
            self.errea = 0x1234
            self.str = "opcode unavailable"

    monkeypatch.setattr(helpers.ida_hexrays, "hexrays_failure_t", Failure, raising=False)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=1, end_ea=5))
    monkeypatch.setattr(helpers._compat, "decompile_function", lambda *_a: None)
    auto = types.ModuleType("ida_auto")
    auto.AU_FINAL = 1
    auto.auto_mark_range = lambda *_a: None
    monkeypatch.setitem(sys.modules, "ida_auto", auto)
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)
    cfunc, error = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is None
    assert error["code"] == helpers.MCPError.DECOMPILER_FAILED
    assert error["details"]["failure_code"] == 50735
    assert error["details"]["failure_ea"] == "0x1234"

    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: (_ for _ in ()).throw(RuntimeError("init boom")), raising=False)
    _cfunc, init_error = helpers._decompile_with_diagnostics(0x1000)
    assert init_error["code"] == helpers.MCPError.DECOMPILER_UNAVAILABLE


def test_structured_disassembly_and_flow_targets_include_optional_fields(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "_is_flow_control_mnemonic", lambda _mnem: True)
    monkeypatch.setattr(helpers, "ida_ua", types.SimpleNamespace(o_near=7, o_far=6))
    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda _ea, _flags: "jmp loc_2000")
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "jmp")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, index: "loc_2000" if index == 0 else "")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, index: 7 if index == 0 else 0)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda *_a: 0x2000)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: "target" if ea == 0x2000 else "")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda _ea, repeatable: "comment" if repeatable == 0 else "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda ea: ea & 0xFF)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 1, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_dref", lambda _ea, _index: 0x3000, raising=False)
    result = helpers._format_disasm_structured(0x1000)
    assert result["branch_target"] == "0x2000"
    assert result["branch_name"] == "target"
    assert result["comment"] == "comment"
    assert result["bytes"]
    assert result["data_refs"] == [{"addr": "0x3000"}]
    formatted = helpers._format_disasm_line(0x1000, style="annotated", include_bytes=True, include_comments=True, annotate_branches=True)
    assert "; // comment" in formatted and "bytes=" in formatted

    monkeypatch.setattr(helpers.idc, "next_head", lambda _ea, _end: BADADDR)
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    assert len(helpers._disasm_range_structured(0x1000, 0x1002, 2)) == 1
    assert len(helpers._disasm_range(0x1000, 0x1002, max_items=2, style="classic", include_bytes=False)) == 1


def test_argument_trace_covers_unknown_prototype_and_argument_classification(monkeypatch):
    helpers = _helpers()
    func = types.SimpleNamespace(start_ea=0x1000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "target")
    class FewData:
        items = [types.SimpleNamespace(name="arg0"), types.SimpleNamespace(name="arg1")]

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    class FewProto:
        def get_func_details(self, data):
            data.items = self.items
            return True

        items = FewData.items

    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "proto")
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_a: (FewProto(), "target"))
    monkeypatch.setattr(helpers.idc, "PT_SILENT", 0, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FewData, raising=False)
    unknown = helpers._trace_argument_origin(func, 3, 0, 2)
    assert unknown["trace_tree"] == [] and "exceeds" in unknown["note"]

    class FunctionData:
        items = [types.SimpleNamespace(name=f"arg{i}") for i in range(5)]

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    class Proto:
        def get_func_details(self, data):
            data.items = FunctionData.items
            return True

    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "proto")
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_a: (Proto(), "target"))
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FunctionData, raising=False)
    monkeypatch.setattr(
        helpers.idautils,
        "XrefsTo",
        lambda *_a: [
            types.SimpleNamespace(frm=0x9000, iscode=False),
            types.SimpleNamespace(frm=0x9001, iscode=True),
            types.SimpleNamespace(frm=0x9002, iscode=True),
            types.SimpleNamespace(frm=0x9003, iscode=True),
        ],
    )
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: None if ea == 0x9001 else 0x2000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: "target" if ea == 0x1000 else "caller")
    sources = 'target("str", 0x20, make_value(), &ptr, variable)'
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: sources)
    for index, expected in enumerate(("string_literal", "constant", "function_call", "address_of", "variable")):
        traced = helpers._trace_argument_origin(func, index, 0, 2)
        assert traced["trace_tree"][0]["arg_type"] == expected


def test_custom_detector_catalog_and_positive_scans_cover_limits(monkeypatch, fresh_fake_idb):
    helpers = _helpers()
    helpers._CUSTOM_DETECTORS.clear()
    assert helpers.register_detector("Demo", {"type": "xor_threshold"})["ok"] is True
    assert helpers.list_detectors()[0]["name"] == "demo"
    assert helpers.delete_detector("Demo") is True
    assert helpers.delete_detector("Demo") is False
    assert helpers._run_custom_detector({"register": True, "name": "bad", "rule": "no"}, 2)["error"] is True
    assert helpers._run_custom_detector({}, 2)["error"] is True

    _install_ctree_surface(monkeypatch)
    db = fresh_fake_idb
    target = 0x2000
    chain_func = cfunc_t(
        entry_ea=0x1000,
        body=_body([_call(db, "recv", [_var(0)], 0x1010, target), _call(db, "memcpy", [_var(0)], 0x1011, target + 1)]),
        lvars=[lvar_t("input_data", FakeTinfo())],
    )
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
    monkeypatch.setattr(helpers, "_function_may_reference_apis", lambda *_a: True)
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda _name: target)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "chain")
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: chain_func)
    strict = helpers._detect_api_chains(["recv", "memcpy"], strict_order=True, max_items=1)
    unordered = helpers._detect_api_chains(["memcpy", "recv"], strict_order=False, max_items=1)
    assert strict and unordered
    assert helpers._run_custom_detector({"rule_type": "api_chain", "apis": "recv,memcpy"}, 1)["count"] == 1

    class StringObject:
        ea = 0x4000

        def __str__(self):
            return "password reset"

    monkeypatch.setattr(helpers.idautils, "Strings", lambda: [StringObject()], raising=False)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [types.SimpleNamespace(frm=0x5000)])
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1000)
    assert helpers._detect_string_refs("[", max_items=1) == []
    assert helpers._detect_string_refs("password", max_items=1)

    class TypeData:
        def size(self):
            return 1

        def __getitem__(self, _index):
            return types.SimpleNamespace(name="buf", type="char *")

    class Tinfo:
        def get_func_details(self, data):
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", TypeData, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda *_a: True)
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x1001]))
    assert helpers._detect_type_matches("[", max_items=1) == []
    assert helpers._detect_type_matches("char", max_items=1)

    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: None if ea == 1 else 0x1000)
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([1, 2]))
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([1, 2, 3]))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "XOR")
    assert helpers._detect_xor_heavy(threshold=2, max_items=1)

    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: BADADDR if name == "target" else 0x1000)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([1]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_a: iter([2, 3]))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: f"f{ea}")
    assert len(helpers._detect_callers_of("target", max_items=1)) == 1
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_a: iter([4, 5]))
    assert len(helpers._detect_callees_of("target", max_items=1)) == 1


def test_ctree_nested_helpers_cover_indirect_calls_strings_sizes_and_failures(monkeypatch, fresh_fake_idb):
    helpers = _helpers()
    _install_ctree_surface(monkeypatch)
    monkeypatch.setattr(ida_hexrays, "cot_ref", 90, raising=False)
    monkeypatch.setattr(ida_hexrays, "cot_ptr", 91, raising=False)
    monkeypatch.setattr(ida_hexrays, "cot_sizeof", 92, raising=False)
    db = fresh_fake_idb

    ref = cexpr_t(op=90, x=cexpr_t(op=cot_obj, obj_ea=0x7000), ea=0x1020)
    ref.x.print1 = lambda _tag=None: "fmt_ref"
    sizeof = cexpr_t(op=92, ea=0x1021)
    sizeof.print1 = lambda _tag=None: "sizeof(buf)"
    pointer = cexpr_t(op=91, x=_var(1), ea=0x1022)
    pointer.print1 = lambda _tag=None: "*input_data"
    computed = cexpr_t(op=999, ea=0x1023)
    computed.print1 = lambda _tag=None: "n * m"
    broken_callee = cexpr_t(op=999, ea=0x1024)

    def broken_print(_tag=None):
        raise RuntimeError("callee text unavailable")

    broken_callee.print1 = broken_print
    bad_arg = cexpr_t(op=999, ea=0x1025)
    bad_arg.print1 = broken_print
    var_callee = cexpr_t(op=ida_hexrays.cot_var, v=var_ref_t(99), ea=0x1026)

    expressions = [
        _call(db, "strcpy", [_var(0), _num(7)], 0x1010, 0x2001),
        _call(db, "printf", [ref], 0x1011, 0x2002),
        _call(db, "memcpy", [_var(0), _var(1), sizeof], 0x1012, 0x2003),
        _call(db, "memcpy", [_var(0), _var(1), pointer], 0x1013, 0x2004),
        _call(db, "malloc", [computed], 0x1014, 0x2005),
        _call(db, "free", [bad_arg], 0x1015, 0x2006),
        cexpr_t(op=cot_call, x=var_callee, a=_Args([]), ea=0x1016),
        cexpr_t(op=cot_call, x=broken_callee, a=_Args([]), ea=0x1017),
    ]
    cfunc = cfunc_t(
        entry_ea=0x1000,
        body=_body(expressions),
        lvars=[
            lvar_t("dst", FakeTinfo()),
            lvar_t("input_data", FakeTinfo(), is_arg_var=True),
            lvar_t("n", FakeTinfo()),
        ],
    )
    monkeypatch.setattr(helpers.idc, "get_str_type", lambda _ea: 1, raising=False)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_a: b"%s %n", raising=False)
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {item["pattern"] for item in findings}
    assert {
        "strcpy_unbounded",
        "format_arg_mismatch",
        "format_string_write",
        "integer_overflow_alloc",
    } <= patterns


def test_constant_and_string_entry_fallbacks_cover_pcrel_limits_and_errors(monkeypatch):
    helpers = _helpers()
    real_reader = helpers._read_candidate_string
    func = types.SimpleNamespace(start_ea=1, end_ea=3)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    mnem = {1: "auipc", 2: "lw"}
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnem.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 1)
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, index: "r0" if index in (0, 1) else "")
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, index: 1 if index == 1 else 4)
    monkeypatch.setattr(helpers, "_read_candidate_string", lambda _target: "resolved")
    assert helpers._scan_constant_load_strings(1) == [{"addr": 0x1005, "value": "resolved"}]

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: (_ for _ in ()).throw(RuntimeError("func info failed")))
    assert helpers._scan_constant_load_strings(1) == []
    monkeypatch.setattr(helpers, "_read_candidate_string", real_reader)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: "text")
    assert helpers._read_candidate_string(0x1000) == "text"
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda *_a: (_ for _ in ()).throw(RuntimeError("read failed")))
    assert helpers._read_candidate_string(0x1000) is None

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([1, 2, 3]))
    monkeypatch.setattr(helpers.idautils, "XrefsFrom", lambda ea, _flags: [types.SimpleNamespace(iscode=True, to=ea), types.SimpleNamespace(iscode=False, to=0x4000 + ea)])
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda _ea: b"value")
    assert len(helpers._collect_function_string_entries(1, result_limit=1)) == 1
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: (_ for _ in ()).throw(RuntimeError("items failed")))
    assert helpers._collect_function_string_entries(1) == []


def test_disasm_window_exercises_forward_fallback_and_tight_slice(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "_format_disasm_line", lambda ea, **_kwargs: f"line-{ea:x}")
    monkeypatch.setattr(helpers.idc, "prev_head", lambda ea, _minimum: ea - 1 if ea > 0x1000 else BADADDR)
    calls = []

    def next_head(ea, _maximum):
        if ea == 0x1001:
            calls.append(ea)
            return ea if len(calls) == 1 else ea + 1
        return BADADDR

    monkeypatch.setattr(helpers.idc, "next_head", next_head)
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 1)
    assert helpers._disasm_window(0x1001, radius=3, max_items=3, style="classic", include_bytes=False) == [
        "line-1000", "line-1001", "line-1002"
    ]
