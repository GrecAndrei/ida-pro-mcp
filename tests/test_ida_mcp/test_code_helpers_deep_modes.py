"""Deep behavior tests for ctree, disassembly, and detector helper paths."""

from __future__ import annotations

import importlib
import types

import ida_hexrays
import pytest

from tests.fakes.ida_fake import (
    BADADDR,
    BT_FUNC,
    FakeTinfo,
    cexpr_t,
    cfunc_t,
    cinsn_t,
    cit_for,
    cit_if,
    cit_switch,
    cit_while,
    cnumber_t,
    cot_asg,
    cot_call,
    cot_eq,
    cot_ne,
    cot_num,
    cot_obj,
    cot_ref,
    cot_str,
    cot_var,
    ctree_visitor_t,
    lvar_t,
    var_ref_t,
)

helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


class Args(list):
    def size(self):
        return len(self)

    def at(self, index):
        return self[index]


def var(index, name, ea=0x140001010):
    expr = cexpr_t(op=cot_var, v=var_ref_t(index), ea=ea)
    expr.print1 = lambda _tag=None, value=name: value
    return expr


def number(value, ea=0x140001010):
    expr = cexpr_t(op=cot_num, n=cnumber_t(value), ea=ea)
    expr.n.value = lambda _index=0, stored=value: stored
    expr.print1 = lambda _tag=None, value=str(value): value
    return expr


def string(value, ea=0x140001010):
    expr = cexpr_t(op=cot_str, string=value, ea=ea)
    expr.print1 = lambda _tag=None, value=value: repr(value)
    return expr


def call(db, name, args, ea, target):
    db.set_name(target, name)
    expr = cexpr_t(op=cot_call, ea=ea, x=cexpr_t(op=cot_obj, obj_ea=target), a=Args(args))
    expr.a = Args(args)
    return expr


def body(expressions):
    return cinsn_t(
        op=ida_hexrays.cit_block,
        ea=0x140001000,
        cblock=[cinsn_t(op=ida_hexrays.cit_expr, cexpr=expr) for expr in expressions],
    )


@pytest.fixture(autouse=True)
def sample_idb():
    from tests.fakes.ida_fake import create_sample_c_binary_idb, install_fake_idb

    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    return db


def test_structure_and_dataflow_helpers_cover_limits_and_control_nodes(monkeypatch):
    for name, value in {
        "cit_if": cit_if,
        "cit_while": cit_while,
        "cit_for": cit_for,
        "cit_switch": cit_switch,
    }.items():
        monkeypatch.setattr(ida_hexrays, name, value, raising=False)

    class Control:
        def __init__(self, op, ea, expression):
            self.op = op
            self.ea = ea
            setattr(self, {ida_hexrays.cit_if: "cif", ida_hexrays.cit_while: "cwhile", ida_hexrays.cit_for: "cfor", ida_hexrays.cit_switch: "cswitch"}[op], types.SimpleNamespace(expr=expression, cond=expression))

    controls = [
        Control(ida_hexrays.cit_if, 0x1000, string("x")),
        Control(ida_hexrays.cit_while, 0x1004, string("ready")),
        Control(ida_hexrays.cit_for, 0x1008, string("i < n")),
        Control(ida_hexrays.cit_switch, BADADDR, string("tag")),
    ]
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [])
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter(()))
    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", ctree_visitor_t)
    control_body = types.SimpleNamespace(children=controls)
    cfunc = types.SimpleNamespace(
        body=control_body,
        lvars=[types.SimpleNamespace(name="src", is_arg_var=True), types.SimpleNamespace(name="dst")],
    )

    # The fake visitor traverses cblock nodes; supply an authentic visitor
    # implementation that visits our control objects for this compatibility
    # test, just as IDA's ctree visitor does.
    class Visitor(ctree_visitor_t):
        def apply_to(self, _body, _parent=None):
            for node in controls:
                self.visit_insn(node)

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    summary = helpers._build_function_structure_summary(cfunc, cfunc=cfunc, details=True)
    assert [item["kind"] for item in summary["control_points"]] == ["if", "while", "for", "switch"]
    assert "control:" in summary["evidence"]

    monkeypatch.setattr(helpers, "_collect_expr_rows_from_cfunc", lambda *_a, **_k: [
        (0x1000, "dst = src"),
        (0x1004, "send(dst, src)"),
        (0x1008, "dst = src"),
    ])
    graph = helpers._build_decompiler_dataflow(cfunc, max_items=2)
    assert graph["assignment_edges"] == 1
    assert graph["call_edges"] == 2
    assert graph["top_hubs"]


def test_variable_usage_hints_and_firmware_text_fallbacks(monkeypatch):
    class TypeInfo:
        def __init__(self, value):
            self.value = value

        def dstr(self):
            return self.value

    names_and_text = [
        ("v1", "v1 = send(v1, n)", None),
        ("v2", "v2 = socket(v2)", None),
        ("v3", "v3 = malloc(v3)", None),
        ("v4", "v4 = aes_encrypt(v4, key)", None),
        ("v5", "v5 = packet + v5", None),
        ("v6", "v6 = strcpy(v6, src)", None),
        ("v7", "v7->next", None),
        ("v8", "v8[4]", None),
        ("v9", "dispatch(v9)", None),
        ("v10", "unknown(v10)", TypeInfo("plain_record_t")),
    ]
    lvars = [types.SimpleNamespace(name=name, type=typ, is_arg_var=True) for name, _text, typ in names_and_text]
    pseudo = " ".join(text for _name, text, _type in names_and_text)
    cfunc = types.SimpleNamespace(lvars=lvars)
    monkeypatch.setattr(helpers, "_lvar_type_str", lambda value: str(value.type.dstr()) if value.type else "")
    # The helper reads str(cfunc); expose the realistic decompiler text.
    class DecompiledFunction:
        def __init__(self):
            self.lvars = lvars

        def __str__(self):
            return pseudo

    cfunc = DecompiledFunction()
    hints = helpers._extract_var_rename_hints(cfunc)
    suggested = {item["suggested"] for item in hints}
    assert {"send_buf", "sock_fd", "heap_buf", "key_buf", "pkt_buf", "str_buf"} <= suggested
    assert any(item["suggested"] == "record" for item in hints)

    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "nop")
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1004 else BADADDR)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    assert helpers._detect_firmware_signals(0x1000, "value at 0x40001000") == ["constant_ref:0x40001000"]

    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\xff\x00\x01")
    assert helpers._read_candidate_string(0x5000) is None
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: "hello\x00")
    assert helpers._read_candidate_string(0x5000) == "hello"


def test_ctree_detector_covers_format_alloc_prototype_and_interprocedural_checks(monkeypatch, sample_idb):
    db = sample_idb
    target = 0x140010000
    lvars = [
        lvar_t("stable", FakeTinfo(kind=1, size=4), is_arg_var=False),
        lvar_t("input_data", FakeTinfo(kind=1, size=1), is_arg_var=True),
        lvar_t("size", FakeTinfo(kind=1, size=4), is_arg_var=False),
        lvar_t("p", FakeTinfo(kind=1, size=1), is_arg_var=False),
    ]
    mul = var(2, "size * 4", 0x140001020)
    expressions = [
        call(db, "strcpy", [var(0, "stable"), var(0, "stable")], 0x140001011, target + 1),
        call(db, "memcpy", [var(0, "stable"), var(0, "stable"), var(2, "size")], 0x140001012, target + 2),
        call(db, "malloc", [mul], 0x140001013, target + 3),
        call(db, "printf", [var(0, "fmt")], 0x140001014, target + 4),
        call(db, "printf", [string("%s %n")], 0x140001015, target + 5),
        call(db, "snprintf", [var(0, "out"), number(0), string("x")], 0x140001016, target + 6),
        call(db, "WriteProcessMemory", [var(3, "p")], 0x140001017, target + 7),
        call(db, "CreateRemoteThread", [var(3, "p")], 0x140001018, target + 8),
        call(db, "free", [var(3, "p")], 0x140001019, target + 9),
        var(3, "p", 0x14000101A),
        cexpr_t(op=cot_ref, x=cexpr_t(op=cot_obj, obj_ea=0x140002010), ea=0x14000101B),
    ]
    cfunc = cfunc_t(entry_ea=0x140001000, body=body(expressions), lvars=lvars)

    class FunctionType(FakeTinfo):
        def get_func_details(self, data):
            data._items = [types.SimpleNamespace(name="dst", type="char *"), types.SimpleNamespace(name="src", type="int *")]
            return True

    cfunc.type = FunctionType(kind=BT_FUNC)
    monkeypatch.setattr(
        db,
        "get_func",
        lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 4, flags=0x04)
        if ea == 0x140001000 else None,
    )
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda tif, _ea: setattr(tif, "get_func_details", lambda data: (setattr(data, "_items", [types.SimpleNamespace(name="dst", type="char *"), types.SimpleNamespace(name="src", type="int *")]) or True)) or True)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x140001004]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x140001000 if ea == 0x140001004 else 0x140001000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "network_dispatch")
    monkeypatch.setattr(helpers.idc, "get_func_attr", lambda *_args: 0x04, raising=False)
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 2 | 4)
    monkeypatch.setattr(helpers._compat, "get_segment_name", lambda _ea: ".text")
    monkeypatch.setattr(helpers._compat, "frame_members", lambda _ea: [(0, "buffer", 0, 300, "char[300]"), (1, "password", 0, 8, "uint64_t"), (2, "__stack_chk_guard", 0, 8, "uint64_t")])
    monkeypatch.setattr(helpers.idaapi, "FUNC_LIB", 0x04, raising=False)
    for name, value in {
        "cot_obj": cot_obj,
        "cot_ref": cot_ref,
        "cot_str": cot_str,
        "cot_num": cot_num,
        "cot_eq": cot_eq,
        "cot_ne": cot_ne,
    }.items():
        monkeypatch.setattr(helpers.ida_hexrays, name, value, raising=False)

    seen_ops = []
    visitor_base = helpers.ida_hexrays.ctree_visitor_t

    class TracingVisitor(visitor_base):
        def apply_to(self, item, parent=None):
            if hasattr(item, "op"):
                seen_ops.append(item.op)
            return super().apply_to(item, parent)

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", TracingVisitor)
    assert helpers.idc.get_name(target + 7) == "WriteProcessMemory"
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {item["pattern"] for item in findings}
    assert cot_call in seen_ops
    assert {
        "unbounded_copy_size",
        "integer_overflow_alloc",
        "format_string_injection",
        "format_string_write",
        "snprintf_zero_size",
        "process_injection_write",
        "remote_thread_injection",
        "use_after_free",
        "library_func_with_vuln",
        "large_stack_buffer",
        "stack_canary_present",
        "sensitive_stack_var",
    } <= patterns, sorted(patterns)


def test_decompile_diagnostics_retry_and_disassembly_annotations(monkeypatch):
    failure_calls = []
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010))

    def decompile(_ea, failure, _flags):
        failure_calls.append(failure)
        failure.code = 7
        failure.errea = 0x1004
        failure.str = "analysis incomplete"
        return types.SimpleNamespace() if len(failure_calls) == 2 else None

    monkeypatch.setattr(helpers._compat, "decompile_function", decompile)
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)
    recovered, error = helpers._decompile_with_diagnostics(0x1000)
    assert recovered is not None and error is None
    assert len(failure_calls) == 2

    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "call")
    monkeypatch.setattr(helpers, "_flow_target_ea", lambda _ea: 0x140001040)
    monkeypatch.setattr(helpers, "_annotate_branch_target", lambda _ea, _text: "callee")
    assert "-> callee" in helpers._format_disasm_line(0x140001000, annotate_branches=True)
    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda *_args: "")
    assert "<data>" in helpers._format_disasm_line(0x140001000)


def test_custom_detector_inline_validation_and_flow_target_modes(monkeypatch):
    assert helpers._run_custom_detector({"rule_type": "api_chain"}, 5)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "string_ref"}, 5)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "type_match"}, 5)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "caller_of"}, 5)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "callee_of"}, 5)["error"] is True
    assert helpers._run_custom_detector({"register": True, "rule": "bad"}, 5)["error"] is True

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
        monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda _name: BADADDR)
        assert helpers._detect_api_chains(["recv"], max_items=1) == []
        assert helpers._detect_callers_of("missing") == []
        assert helpers._detect_callees_of("missing") == []
        assert helpers._is_flow_control_mnemonic("beq") is True
        assert helpers._is_flow_control_mnemonic("") is False
    finally:
        monkeypatch.undo()
