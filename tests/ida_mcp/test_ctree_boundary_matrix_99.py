"""Cross-action ctree coverage with a small deterministic AST fake."""

from __future__ import annotations

import sys
import types

import pytest

from tests._isolated_repo_loader import load_tool_module
from tests.ida_mcp.test_swarm_q03_tools import (
    CIT,
    COT,
    _expr,
    _insn,
    _set_up_ctree,
)


class _Lvar:
    def __init__(self, name, is_arg_var, type_value):
        self.name = name
        self.is_arg_var = is_arg_var
        self._type_value = type_value

    def type(self):
        return self._type_value


def _rich_cfunc():
    cond_a = _expr(COT["cot_cmp"], ea=0x1001, text="a > 0")
    cond_b = _expr(COT["cot_cmp"], ea=0x1005, text="b != 0")
    callee = _expr(COT["cot_obj"], ea=0x1007, text="helper")
    call = _expr(COT["cot_call"], ea=0x1008, text="helper(a)")
    call.x = callee
    call.a = [_expr(COT["cot_var"], ea=0x1009, text="a")]
    var = _expr(COT["cot_var"], ea=0x100A, text="b")
    var.v = types.SimpleNamespace(idx=1)
    string = _expr(COT["cot_str"], ea=0x100B, text='"hello"')
    obj = _expr(COT["cot_obj"], ea=0x100C, text="global_msg")
    obj.obj_ea = 0x2000
    assign_b = _expr(COT["cot_asg"], ea=0x100D, text="a = b")
    assign_c = _expr(COT["cot_asg"], ea=0x100E, text="a = c")

    inner_if = _insn(
        CIT["cit_if"],
        ea=0x1010,
        children=(cond_b,),
    )
    inner_if.cif = types.SimpleNamespace(expr=cond_b)
    while_node = _insn(CIT["cit_while"], ea=0x1020, children=(call,))
    while_node.cwhile = types.SimpleNamespace(expr=cond_b)
    for_node = _insn(CIT["cit_for"], ea=0x1030, children=())
    for_node.cfor = types.SimpleNamespace(cond=cond_a)
    do_node = _insn(CIT["cit_do"], ea=0x1040, children=())
    do_node.cdo = types.SimpleNamespace(expr=cond_b)
    root = _insn(
        CIT["cit_if"],
        ea=0x1000,
        children=(cond_a, inner_if, while_node, for_node, do_node, var, string, obj, assign_b, assign_c),
    )
    root.cif = types.SimpleNamespace(expr=cond_a)
    return types.SimpleNamespace(
        body=root,
        lvars=[_Lvar("a", True, "int"), _Lvar("b", False, "char *"), _Lvar("c", False, "long")],
    )


@pytest.fixture
def ctree_env(monkeypatch):
    cfunc = _rich_cfunc()
    _set_up_ctree(cfunc)
    ida_hexrays = sys.modules["ida_hexrays"]
    sys.modules["idc"].get_strlit_contents = lambda _ea: b"hello from data"
    module = load_tool_module("ctree")
    return module, cfunc, ida_hexrays


def test_ctree_public_actions_cover_ast_queries_and_structured_graphs(ctree_env):
    module, _cfunc, _ida_hexrays = ctree_env
    for action in ("get", "find_calls", "find_vars", "find_strings", "find_conditions", "traverse"):
        result = module.ctree(action=action, addr="0x1000", query="helper" if action == "find_calls" else None)
        assert result["ok"] is True, (action, result)
    assert module.ctree(action="unknown", addr="0x1000")["error"] is True

    calls = module.ctree(action="find_calls", address="0x1000", query="does-not-match")
    assert calls["count"] == 0
    variables = module.ctree(action="find_vars", address="0x1000", query="b")
    assert variables["count"] >= 1
    strings = module.ctree(action="find_strings", address="0x1000", query="hello")
    assert strings["count"] == 2
    conditions = module.ctree(action="find_conditions", address="0x1000", query="b")
    assert conditions["count"] >= 1

    flow = module.ctree(action="get_logic_flow", address="0x1000", depth=3)
    dominance = module.ctree(action="dominance_map", address="0x1000", depth=3)
    dependencies = module.ctree(action="var_dependency_graph", address="0x1000", depth=3)
    assert flow["ok"] and flow["logic_graph"]["node_count"] >= 1
    assert dominance["ok"] and dominance["dominance_map"]["condition_count"] >= 1
    assert dependencies["ok"] and dependencies["var_dependency_graph"]["assignment_edges"] == 2


def test_ctree_helpers_cover_empty_vocabulary_filters_and_visitor_failures(ctree_env, monkeypatch):
    module, cfunc, ida_hexrays = ctree_env
    empty = types.SimpleNamespace(body=None, lvars=[])
    assert module._ctree_build_var_dependency_graph(empty)["nodes"] == []
    assert module._ctree_collect_expr_rows(cfunc, max_items=0) == []
    assert module._ctree_build_dominance_map(cfunc, max_nodes=0)["truncated"] is True
    assert module._ctree_build_logic_graph(cfunc, max_nodes=0)["truncated"] is True

    class _BrokenVisitor:
        def __init__(self, *_args):
            raise RuntimeError("visitor unavailable")

    monkeypatch.setattr(ida_hexrays, "ctree_visitor_t", _BrokenVisitor)
    assert module._ctree_collect_expr_rows(cfunc) == []
    assert module._ctree_build_dominance_map(cfunc)["conditions"] == []
    assert module._ctree_build_logic_graph(cfunc)["nodes"] == []


def test_ctree_actions_return_init_decompile_and_unknown_action_errors(ctree_env, monkeypatch):
    module, _cfunc, ida_hexrays = ctree_env
    ida_hexrays.init_hexrays_plugin = lambda: False
    failed = module.ctree(action="get", addr="0x1000")
    assert failed["code"] == "IDA_ERROR"

    ida_hexrays.init_hexrays_plugin = lambda: True
    ida_hexrays.decompile = lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
    failed = module.ctree(action="get", addr="0x1000")
    assert failed["code"] == "DECOMPILER_FAILED"

    monkeypatch.setattr(module, "validate_addr", lambda *_args, **_kwargs: (None, {"error": True}))
    assert module.ctree(action="get", addr="0x1000")["error"] is True


def test_ctree_edge_branches_and_truncations(ctree_env, monkeypatch):
    module, cfunc, ida_hexrays = ctree_env

    # 1. lines 43-44: expr.print1 raises Exception in _ctree_collect_expr_rows
    broken_expr = _expr(COT["cot_var"], ea=0x1000, text="x")
    broken_expr.print1 = lambda *_a: (_ for _ in ()).throw(RuntimeError("print fail"))
    cf_broken_expr = types.SimpleNamespace(body=_insn(CIT["cit_if"], ea=0x1000, children=(broken_expr,)), lvars=[])
    rows = module._ctree_collect_expr_rows(cf_broken_expr)
    assert len(rows) >= 1
    assert rows[0][1] == ""

    # 2. lines 63-65 (empty lvar name), line 106 (src == dst), line 122 (max_edges break)
    self_asg = _expr(COT["cot_asg"], ea=0x1000, text="a = a")
    asg2 = _expr(COT["cot_asg"], ea=0x1004, text="b = a")
    cf_self = types.SimpleNamespace(
        body=_insn(CIT["cit_if"], ea=0x1000, children=(self_asg, asg2)),
        lvars=[_Lvar("", False, "int"), _Lvar("a", True, "int"), _Lvar("b", False, "int")],
    )
    dep = module._ctree_build_var_dependency_graph(cf_self, max_edges=1)
    assert len(dep["edges"]) == 1

    # 3. lines 155-156: _ctree_visitor_flags exception
    class BadCV:
        @property
        def CV_PARENTS(self):
            raise RuntimeError("no CV_PARENTS")

    monkeypatch.setattr(module, "ida_hexrays", BadCV(), raising=False)
    assert module._ctree_visitor_flags() == 0
    monkeypatch.setattr(module, "ida_hexrays", ida_hexrays, raising=False)

    # 4. lines 191-192: CondVisitor print1 exception
    bad_cond_insn = _insn(CIT["cit_if"], ea=0x1000, children=())
    bad_cond_insn.cif = types.SimpleNamespace(expr=broken_expr)
    cf_bad_cond = types.SimpleNamespace(body=bad_cond_insn, lvars=[])
    dom_bad = module._ctree_build_dominance_map(cf_bad_cond)
    assert dom_bad["conditions"][0]["expr"] == "complex"

    # 5. lines 295-296 & 312-313 & 337-338 & 264 (duplicate edge) in LogicGraphVisitor
    bad_while = _insn(CIT["cit_while"], ea=0x1004, children=())
    bad_while.cwhile = types.SimpleNamespace(expr=broken_expr)
    bad_root = _insn(CIT["cit_if"], ea=0x1000, children=(bad_cond_insn, bad_while))
    bad_root.cif = types.SimpleNamespace(expr=broken_expr)
    cf_bad_logic = types.SimpleNamespace(body=bad_root, lvars=[])
    logic_bad = module._ctree_build_logic_graph(cf_bad_logic)
    assert len(logic_bad["nodes"]) >= 1

    # visit_expr truncation (lines 337-338)
    call_expr = _expr(COT["cot_call"], ea=0x1000, text="call()")
    cf_call = types.SimpleNamespace(body=_insn(CIT["cit_if"], ea=0x1000, children=(call_expr, call_expr)), lvars=[])
    logic_trunc = module._ctree_build_logic_graph(cf_call, max_nodes=1)
    assert logic_trunc["truncated"] is True

    # 6. lines 405-406: init_hexrays_plugin exception
    monkeypatch.setattr(ida_hexrays, "init_hexrays_plugin", lambda: (_ for _ in ()).throw(RuntimeError("plugin crash")))
    err_init = module.ctree(action="get", addr="0x1000")
    assert err_init["code"] == "IDA_ERROR"
    monkeypatch.setattr(ida_hexrays, "init_hexrays_plugin", lambda: True)

    # 7. lines 459-461 & 481-482: get_logic_flow truncation when nodes > 1200
    monkeypatch.setattr(
        module,
        "_ctree_build_logic_graph",
        lambda _cf, **_kw: {
            "nodes": [{"id": f"n_{i}", "ea": "0x1000", "kind": "call", "depth": 0, "text": "f()"} for i in range(1300)],
            "edges": [{"from": f"n_{i}", "to": f"n_{i+1}", "relation": "controls"} for i in range(1300)],
            "truncated": False,
        },
    )
    flow_trunc = module.ctree(action="get_logic_flow", addr="0x1000")
    assert flow_trunc["truncated"] is True
    assert flow_trunc["count"] == 1200

    # 8. lines 494-495, 501-502, 511-512: action="get" truncation (> 200 nodes)
    many_exprs = [_expr(COT["cot_var"], ea=0x1000 + i, text=f"v{i}") for i in range(210)]
    many_insns = [_insn(CIT["cit_return"], ea=0x2000 + i, children=()) for i in range(210)]
    cf_many = types.SimpleNamespace(body=_insn(CIT["cit_if"], ea=0x1000, children=(*many_exprs, *many_insns)), lvars=[])
    _set_up_ctree(cf_many)
    get_trunc = module.ctree(action="get", addr="0x1000")
    assert get_trunc["truncated"] is True
    assert get_trunc["total"] > 200

    # 9. lines 529-530: find_calls arg.print1 raises Exception
    bad_arg_call = _expr(COT["cot_call"], ea=0x1008, text="foo(arg)")
    bad_arg_call.x = _expr(COT["cot_obj"], ea=0x1007, text="foo")
    bad_arg_call.a = [broken_expr]
    cf_bad_call = types.SimpleNamespace(body=_insn(CIT["cit_if"], ea=0x1000, children=(bad_arg_call,)), lvars=[])
    _set_up_ctree(cf_bad_call)
    res_calls = module.ctree(action="find_calls", addr="0x1000")
    assert res_calls["ok"] is True

    # 10. lines 550-551 (v.type() exception) & 568-569 (cfunc.lvars idx error) in find_vars
    class BrokenTypeLvar:
        name = "bad_type_var"
        is_arg_var = False

        def type(self):
            raise RuntimeError("type fail")

    var_oob = _expr(COT["cot_var"], ea=0x100A, text="oob")
    var_oob.v = types.SimpleNamespace(idx=999)
    cf_bad_vars = types.SimpleNamespace(body=_insn(CIT["cit_if"], ea=0x1000, children=(var_oob,)), lvars=[BrokenTypeLvar()])
    _set_up_ctree(cf_bad_vars)
    res_vars = module.ctree(action="find_vars", addr="0x1000")
    assert res_vars["ok"] is True
    assert "bad_type_var  ?" in res_vars["variables"]

    # 11. lines 641 & 654: traverse pruning when depth > max_depth
    _set_up_ctree(cfunc)
    res_trav = module.ctree(action="traverse", addr="0x1000", depth=0)
    assert res_trav["ok"] is True

    # 12. lines 675-676 & 690-691: dominance_map truncation when edges > 500
    monkeypatch.setattr(
        module,
        "_ctree_build_dominance_map",
        lambda _cf, **_kw: {
            "conditions": [],
            "dominance_edges": [{"from": f"c_{i}", "to": f"c_{i+1}", "relation": "dominates"} for i in range(600)],
            "condition_count": 600,
            "edge_count": 600,
            "truncated": False,
        },
    )
    dom_trunc = module.ctree(action="dominance_map", addr="0x1000")
    assert dom_trunc["truncated"] is True
    assert dom_trunc["count"] == 500

    # 13. lines 711-712: handle_error on unhandled exception
    monkeypatch.setattr(module, "public_arg", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fatal ctree error")))
    err_fatal = module.ctree(action="get", addr="0x1000")
    assert err_fatal["ok"] is False
    assert "fatal ctree error" in str(err_fatal.get("error") or err_fatal.get("message"))
