"""CTree public actions exercised with a nested fake Hex-Rays tree."""

from __future__ import annotations

import importlib
import types

from tests.fakes.ida_fake import (
    cexpr_t,
    cfunc_t,
    cinsn_t,
    cit_block,
    cit_for,
    cit_if,
    cit_return,
    cit_while,
    cot_call,
    cot_obj,
    cot_str,
    cot_var,
    lvar_t,
    var_ref_t,
)

ctree_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.ctree")


def _expr(op, ea, text, **kwargs):
    node = cexpr_t(op=op, ea=ea, **kwargs)
    node.print1 = lambda _out=None, text=text: text
    return node


def _tree():
    arg = _expr(cot_var, 0x140001001, "arg", v=var_ref_t(0))
    literal = _expr(cot_str, 0x140001004, '"packet"')
    obj = _expr(cot_obj, 0x140001008, "marker", obj_ea=0x140002000)
    callee = _expr(cot_obj, 0x14000100C, "send", obj_ea=0x140002010)
    call = _expr(cot_call, 0x140001010, "send(arg, marker)", x=callee, a=[arg, literal])
    condition = _expr(cot_var, 0x140001014, "ready", v=var_ref_t(0))
    call_statement = cinsn_t(op=2, ea=0x140001010, cexpr=call)
    return cinsn_t(
        op=cit_block,
        ea=0x140001000,
        cblock=[
            cinsn_t(
                op=cit_if,
                ea=0x140001020,
                cif=types.SimpleNamespace(expr=condition),
                cblock=[call_statement],
            ),
            cinsn_t(
                op=cit_while,
                ea=0x140001030,
                cwhile=types.SimpleNamespace(expr=condition),
                cblock=[cinsn_t(op=cit_for, ea=0x140001034, cfor=types.SimpleNamespace(cond=condition))],
            ),
            cinsn_t(op=cit_return, ea=0x140001040),
            cinsn_t(op=2, ea=0x140001050, cexpr=obj),
        ],
    )


def test_ctree_public_actions_cover_nested_conditions_calls_and_strings(monkeypatch, fresh_fake_idb):
    cfunc = cfunc_t(
        entry_ea=0x140001000,
        body=_tree(),
        lvars=[lvar_t("arg", is_arg_var=True), lvar_t("result")],
    )
    monkeypatch.setattr(ctree_mod.ida_hexrays, "decompile", lambda *_args: cfunc)
    monkeypatch.setattr(ctree_mod.idc, "get_func_name", lambda _ea: "network_handler")
    monkeypatch.setattr(ctree_mod.idc, "get_strlit_contents", lambda ea: b"packet marker" if ea == 0x140002000 else "")
    monkeypatch.setattr(ctree_mod.ida_lines, "tag_remove", lambda value: value)
    monkeypatch.setattr(ctree_mod.ida_hexrays, "get_ctype_name", lambda op: f"op_{op}", raising=False)
    for name, value in {
        "cit_while": cit_while,
        "cit_for": cit_for,
        "cit_do": 6,
        "cit_if": cit_if,
        "cit_return": cit_return,
        "cit_switch": 7,
        "cot_obj": cot_obj,
        "cot_str": cot_str,
        "cot_var": cot_var,
        "cot_call": cot_call,
    }.items():
        monkeypatch.setattr(ctree_mod.ida_hexrays, name, value, raising=False)

    for action in ("get", "traverse", "find_calls", "find_vars", "find_conditions", "find_strings"):
        result = ctree_mod.ctree(action=action, address="0x140001000", query="send|packet|ready")
        assert result.get("ok") is True, (action, result)
        assert result["function"] == "network_handler"
    calls = ctree_mod.ctree(action="find_calls", addr="0x140001000", query="send")
    assert calls["count"] == 1 and "send" in calls["calls"]
    strings = ctree_mod.ctree(action="find_strings", addr="0x140001000", query="packet")
    assert strings["count"] >= 1

    logic = ctree_mod.ctree(action="get_logic_flow", addr="0x140001000", depth=3, query="if|send")
    assert logic["ok"] is True
    assert logic["logic_graph"]["node_count"] >= 2
    dominance = ctree_mod.ctree(action="dominance_map", addr="0x140001000")
    assert dominance["ok"] is True and dominance["dominance_map"]["condition_count"] >= 2
    dependency = ctree_mod.ctree(action="var_dependency_graph", addr="0x140001000")
    assert dependency["ok"] is True and "var_dependency_graph" in dependency


def test_ctree_dependency_and_decompiler_error_modes(monkeypatch, fresh_fake_idb):
    empty = cfunc_t(body=cinsn_t(op=cit_block), lvars=[])
    assert ctree_mod._ctree_build_var_dependency_graph(empty)["nodes"] == []
    monkeypatch.setattr(ctree_mod.ida_hexrays, "init_hexrays_plugin", lambda: False)
    unavailable = ctree_mod.ctree(action="get", addr="0x140001000")
    assert unavailable["error"] is True

    monkeypatch.setattr(ctree_mod.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(ctree_mod.ida_hexrays, "decompile", lambda *_args: None)
    failed = ctree_mod.ctree(action="get", addr="0x140001000")
    assert failed["error"] is True
    assert ctree_mod.ctree(action="unknown", addr="0x140001000")["error"] is True


def test_ctree_dependency_fallback_tracks_assignments_and_phi_merges(monkeypatch, fresh_fake_idb):
    cfunc = cfunc_t(
        entry_ea=ctree_mod.idaapi.BADADDR,
        lvars=[lvar_t("arg", is_arg_var=True), lvar_t("left"), lvar_t("right"), lvar_t("result")],
    )
    monkeypatch.setattr(
        ctree_mod,
        "_ctree_collect_expr_rows",
        lambda _cfunc, max_items: [
            (0x1000, "result = left"),
            (0x1004, "result = right"),
            (0x1008, "result = left"),
            (0x100C, "left == right"),
            (ctree_mod.idaapi.BADADDR, "result = arg"),
            (0x1010, ""),
        ],
    )

    result = ctree_mod._ctree_build_var_dependency_graph(cfunc, max_edges=10)
    assert result["nodes"] == ["arg", "left", "result", "right"]
    assert result["edge_count"] == 3
    assert result["assignment_edges"] == 3
    assert result["arg_vars"] == ["arg"]
    assert result["phi_like_merges"] == [{
        "var": "result",
        "incoming_sources": ["arg", "left", "right"],
        "source_count": 3,
    }]
