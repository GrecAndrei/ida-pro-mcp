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
