"""Cross-mode ctree vulnerability scanning coverage."""

from __future__ import annotations

import sys
import types

import ida_hexrays

from tests.fakes.ida_fake import (
    BT_INT8,
    BT_INT32,
    FakeTinfo,
    cexpr_t,
    cfunc_t,
    cinsn_t,
    cnumber_t,
    cot_asg,
    cot_call,
    cot_eq,
    cot_num,
    cot_obj,
    cot_ref,
    cot_var,
    ctree_visitor_t,
    lvar_t,
    var_ref_t,
)


def _var(index: int) -> cexpr_t:
    names = ("dst", "input_data", "input_size", "p", "cmd", "fmt")
    name = names[index] if index < len(names) else f"var_{index}"
    expr = cexpr_t(op=cot_var, v=var_ref_t(index), ea=0x140001010)
    expr.print1 = lambda _tag=None, value=name: value
    return expr


def _num(value: int) -> cexpr_t:
    expr = cexpr_t(op=cot_num, n=cnumber_t(value), ea=0x140001010)
    expr.print1 = lambda _tag=None, value=str(value): value
    return expr


class _Args(list):
    def size(self) -> int:
        return len(self)

    def at(self, index: int) -> cexpr_t:
        return self[index]


def _call(db, name: str, args: list[cexpr_t], ea: int, target: int) -> cexpr_t:
    db.set_name(target, name)
    call = cexpr_t(
        op=cot_call,
        ea=ea,
        x=cexpr_t(op=cot_obj, obj_ea=target),
        a=_Args(args),
    )
    call.a = _Args(args)
    return call


def _body(expressions: list[cexpr_t]) -> cinsn_t:
    return cinsn_t(
        op=ida_hexrays.cit_block,
        ea=0x140001000,
        cblock=[cinsn_t(op=ida_hexrays.cit_expr, cexpr=expr) for expr in expressions],
    )


def _install_ctree_surface(monkeypatch):
    for name, value in {
        "cot_obj": cot_obj,
        "cot_asg": cot_asg,
        "cot_eq": cot_eq,
        "cot_ne": cot_eq + 1,
        "cot_ule": cot_eq + 2,
        "cot_sle": cot_eq + 4,
    }.items():
        monkeypatch.setattr(ida_hexrays, name, value, raising=False)
    monkeypatch.setattr(ida_hexrays, "ctree_visitor_t", ctree_visitor_t)


def test_ctree_scanner_covers_realistic_dangerous_call_mix(monkeypatch, fresh_fake_idb):
    """A single decompiled function can expose several independent risks."""
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    _install_ctree_surface(monkeypatch)
    db = fresh_fake_idb
    db.segments[0].perm |= 2  # write + execute, for the segment-risk branch
    target = 0x140010000
    lvars = [
        lvar_t("dst", FakeTinfo(kind=BT_INT8), is_arg_var=True),
        lvar_t("input_data", FakeTinfo(kind=BT_INT8), is_arg_var=True),
        lvar_t("input_size", FakeTinfo(kind=BT_INT32), is_arg_var=True),
        lvar_t("p", FakeTinfo(kind=BT_INT8), is_arg_var=False),
        lvar_t("cmd", FakeTinfo(kind=BT_INT8), is_arg_var=True),
        lvar_t("fmt", FakeTinfo(kind=BT_INT8), is_arg_var=True),
    ]
    expressions = [
        _call(db, "gets", [_var(0)], 0x140001011, target + 1),
        _call(db, "strcpy", [_var(0), _var(1)], 0x140001012, target + 2),
        _call(db, "memcpy", [_var(0), _var(1), _var(2)], 0x140001013, target + 3),
        _call(db, "sprintf", [_var(0), _var(5)], 0x140001014, target + 4),
        _call(db, "system", [_var(4)], 0x140001015, target + 5),
        _call(db, "malloc", [_var(2)], 0x140001016, target + 6),
        _call(db, "free", [_var(3)], 0x140001017, target + 7),
        _var(3),
        cexpr_t(op=ida_hexrays.cot_str, string="https://10.0.0.1/c2", ea=0x140001018),
    ]
    cfunc = cfunc_t(entry_ea=0x140001000, body=_body(expressions), lvars=lvars)

    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {item["pattern"] for item in findings}

    assert {
        "gets_always_overflow",
        "strcpy_user_input",
        "user_controlled_copy_size",
        "sprintf_unbounded",
        "command_injection",
        "user_controlled_alloc_size",
        "unchecked_malloc",
        "use_after_free",
        "hardcoded_url",
        "hardcoded_ip",
        "writable_executable_segment",
    } <= patterns


def test_ctree_scanner_handles_safe_size_checks_and_nulling(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    _install_ctree_surface(monkeypatch)
    db = fresh_fake_idb
    target = 0x140011000
    lvars = [lvar_t("p", FakeTinfo(kind=BT_INT8)), lvar_t("n", FakeTinfo(kind=BT_INT32))]
    alloc = _call(db, "malloc", [_num(16)], 0x140001021, target)
    checked = cexpr_t(
        op=ida_hexrays.cot_eq,
        ea=0x140001022,
        x=alloc,
        y=_num(0),
    )
    free = _call(db, "free", [_var(0)], 0x140001023, target + 1)
    nulling = cexpr_t(
        op=ida_hexrays.cot_asg,
        ea=0x140001024,
        x=_var(0),
        y=_num(0),
    )
    body = _body([checked, free, nulling, _var(0)])
    findings = helpers._scan_ctree_vulns(
        cfunc_t(entry_ea=0x140001000, body=body, lvars=lvars)
    )
    patterns = {item["pattern"] for item in findings}
    assert "zero_alloc" not in patterns
    assert "unchecked_malloc" not in patterns
    assert "use_after_free" not in patterns


def test_ctree_scanner_returns_empty_for_missing_cfunc():
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    assert helpers._scan_ctree_vulns(None) == []


def test_ctree_scanner_exercises_api_argument_and_prototype_modes(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    _install_ctree_surface(monkeypatch)
    db = fresh_fake_idb

    class FunctionData:
        def __init__(self):
            self.items = []

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    class CalleeType:
        def get_func_details(self, data):
            data.items = [
                types.SimpleNamespace(name="dst", type="char *"),
                types.SimpleNamespace(name="src", type="int *"),
                types.SimpleNamespace(name="size", type="unsigned int"),
            ]
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FunctionData, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", CalleeType, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter(()))
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 0)
    monkeypatch.setattr(helpers._compat, "frame_members", lambda _ea: [])

    def _string(value):
        expr = cexpr_t(op=ida_hexrays.cot_str, string=value, ea=0x140001010)
        expr.print1 = lambda _tag=None, value=value: repr(value)
        return expr

    def _number(value):
        expr = _num(value)
        expr.n.value = lambda _index=0, stored=value: stored
        return expr

    # Keep the expressions varied: each call selects a different argument
    # convention and exercises both safe and dangerous branches.
    expressions = [
        _call(db, "strcat", [_var(0), _var(1)], 0x140001100, 0x140010001),
        _call(db, "lstrcpy", [_var(0), _var(1)], 0x140001101, 0x140010002),
        _call(db, "memcpy", [_number(0x10), _number(0x20), _number(4)], 0x140001102, 0x140010003),
        _call(db, "fprintf", [_number(2), _var(5)], 0x140001103, 0x140010004),
        _call(db, "dprintf", [_number(2), _string("%s %n"), _string("x")], 0x140001104, 0x140010005),
        _call(db, "snprintf", [_var(0), _number(-1), _string("x")], 0x140001105, 0x140010006),
        _call(db, "system", [_string("echo safe")], 0x140001106, 0x140010007),
        _call(db, "calloc", [_num(2), _var(2)], 0x140001107, 0x140010008),
        _call(db, "HeapAlloc", [_number(1), _number(2), _number(0)], 0x140001108, 0x140010009),
        _call(db, "free", [], 0x140001109, 0x14001000A),
        _call(db, "WriteProcessMemory", [_var(3)], 0x14000110A, 0x14001000B),
        _call(db, "NtCreateThreadEx", [_var(3)], 0x14000110B, 0x14001000C),
        _call(db, "free", [_var(3)], 0x14000110C, 0x14001000D),
        _var(3),
        cexpr_t(
            op=cot_asg,
            ea=0x14000110D,
            x=_var(3),
            y=_num(0),
        ),
    ]
    lvars = [
        lvar_t("dst", FakeTinfo(kind=BT_INT8), is_arg_var=True),
        lvar_t("input_data", FakeTinfo(kind=BT_INT8), is_arg_var=True),
        lvar_t("input_size", FakeTinfo(kind=BT_INT32), is_arg_var=True),
        lvar_t("p", FakeTinfo(kind=BT_INT8), is_arg_var=False),
        lvar_t("unused", FakeTinfo(kind=BT_INT32), is_arg_var=False),
        lvar_t("fmt", FakeTinfo(kind=BT_INT8), is_arg_var=True),
    ]
    cfunc = cfunc_t(
        entry_ea=0x140001000,
        body=_body(expressions),
        lvars=lvars,
    )
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {item["pattern"] for item in findings}
    assert {
        "strcat_unbounded",
        "strcpy_user_input",
        "type_mismatch_copy",
        "format_string_injection",
        "format_arg_mismatch",
        "format_string_write",
        "snprintf_zero_size",
        "user_controlled_alloc_size",
        "zero_alloc",
        "process_injection_write",
        "remote_thread_injection",
        "use_after_free",
        "int_as_pointer",
    } <= patterns, sorted(patterns)


def test_ctree_scanner_runs_post_analysis_and_processor_modes(monkeypatch, fresh_fake_idb):
    import importlib

    import idautils
    import idc

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    _install_ctree_surface(monkeypatch)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_ref", cot_ref, raising=False)
    db = fresh_fake_idb
    target = 0x140010100

    suspicious_ref = cexpr_t(
        op=cot_ref,
        x=cexpr_t(op=cot_obj, obj_ea=0x140020000),
        ea=0x140001010,
    )
    cfunc = cfunc_t(
        entry_ea=0x140001000,
        body=_body([_call(db, "gets", [_var(0)], 0x140001001, target), suspicious_ref]),
        lvars=[lvar_t("input_data", FakeTinfo(kind=BT_INT8), is_arg_var=True)],
    )

    class Block:
        def __init__(self, start):
            self.start_ea = start
            self.end_ea = start + 4

        def succs(self):
            return [self]

    flow = [Block(0x140001000)] + [Block(0x140003000 + i * 4) for i in range(21)]
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: flow)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter([0x140002004]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x140003000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "network_dispatch")
    monkeypatch.setattr(helpers.idc, "get_func_attr", lambda *_args: 4, raising=False)
    monkeypatch.setattr(helpers.idaapi, "FUNC_LIB", 4, raising=False)
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 2 | 4)
    monkeypatch.setattr(helpers._compat, "get_segment_name", lambda _ea: ".data")
    monkeypatch.setattr(
        helpers._compat,
        "frame_members",
        lambda _ea: [
            (0, "large_buffer", 0, 512, "char[512]"),
            (1, "password", 0, 16, "char[16]"),
            (2, "__stack_chk_guard", 0, 8, "uint64_t"),
        ],
    )
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\x90\x90\x90\x90")
    monkeypatch.setattr(helpers.idc, "get_str_type", lambda _ea: 1, raising=False)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda _ea, _length, _type: b"http://admin/cmd")
    monkeypatch.setattr(
        helpers.idautils,
        "XrefsTo",
        lambda _ea: [types.SimpleNamespace(frm=0x140004000)],
    )
    monkeypatch.setattr(helpers.idaapi, "INF_PROCNAME", 1, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: "metapc", raising=False)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter((0x140001000, 0x140001004)))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "gets_handler", raising=False)
    monkeypatch.setattr(helpers.ida_name, "demangle_name", lambda name, _flags: name)
    monkeypatch.setattr(helpers, "_detect_firmware_signals", lambda *_args, **_kwargs: ["mmio_store:0x5000"])

    class Decoder:
        o_displ = 4
        o_mem = 2

        def insn_t(self):
            return types.SimpleNamespace()

        def decode_insn(self, _insn, _ea):
            return 1

    decoder = Decoder()
    monkeypatch.setitem(sys.modules, "ida_ua", decoder)
    monkeypatch.setattr(idc, "get_operand_type", lambda _ea, index: decoder.o_displ if index == 0 else decoder.o_mem if index == 1 else 0, raising=False)
    monkeypatch.setattr(
        idc,
        "print_operand",
        lambda ea, index: "fs:[0]" if ea in (0x140001000, 0x140001004) else "[rbp-0x10]" if index == 0 else "global",
        raising=False,
    )
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, _index: 0x5000, raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: "mov" if ea == 0x140001000 else "nop", raising=False)

    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {item["pattern"] for item in findings}
    assert {
        "network_reachable_vuln",
        "library_func_with_vuln",
        "danger_in_loop",
        "complex_func_with_vuln",
        "writable_executable_segment",
        "large_stack_buffer",
        "stack_canary_present",
        "sensitive_stack_var",
        "global_writable_ref",
        "nop_sled",
        "shared_suspicious_string",
        "seh_with_vuln",
        "vulnerable_function_name",
        "firmware_signal",
    } <= patterns, sorted(patterns)
