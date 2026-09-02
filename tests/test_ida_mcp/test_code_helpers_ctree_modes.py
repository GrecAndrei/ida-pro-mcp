"""Cross-mode ctree vulnerability scanning coverage."""

from __future__ import annotations

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
