"""Behavior matrix for batch orchestration and its macro language."""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def batch_mod():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.batch")


def test_macro_paths_and_conditions_cover_dict_list_and_scalar_shapes(batch_mod):
    assert batch_mod._macro_get_path({"a": {"b": [1, {"c": 3}]}}, "a.b.1.c") == 3
    assert batch_mod._macro_get_path(["x"], "0") == "x"
    assert batch_mod._macro_get_path({}, ".") == {}
    assert batch_mod._macro_get_path({"a": 1}, "missing") is None
    assert batch_mod._macro_get_path("x", "a") is None
    for expression in ("n == 4", "n != 5", "n < 5", "n > 3", "n <= 4", "n >= 4"):
        assert batch_mod._macro_eval_cond({"n": 4}, expression)
    assert batch_mod._macro_eval_cond({"ok": True}, "ok")
    assert not batch_mod._macro_eval_cond({"n": "x"}, "n > 2")
    assert not batch_mod._macro_eval_cond({}, "missing == 1")


def test_macro_pipe_operators_are_deterministic(batch_mod):
    rows = [{"name": "b", "score": 2}, {"name": "a", "score": 3}, {"name": "b", "score": 2}]
    assert batch_mod._macro_apply_pipe_op(rows, "count") == 3
    assert batch_mod._macro_apply_pipe_op(rows, "first(2)") == rows[:2]
    assert batch_mod._macro_apply_pipe_op(rows, "first(bad)") == rows
    assert batch_mod._macro_apply_pipe_op(rows, "sort(score)")[0]["name"] == "b"
    assert batch_mod._macro_apply_pipe_op(rows, "sort(-score)")[0]["name"] == "a"
    assert len(batch_mod._macro_apply_pipe_op(rows, "unique")) == 2
    assert batch_mod._macro_apply_pipe_op(rows, "pluck(name)") == ["b", "a", "b"]
    assert batch_mod._macro_apply_pipe_op(rows, "reverse")[0]["name"] == "b"
    assert len(batch_mod._macro_apply_pipe_op(rows, "filter(score >= 3)")) == 1
    assert set(batch_mod._macro_apply_pipe_op(rows, "group_by(name)")) == {"a", "b"}
    assert batch_mod._macro_apply_pipe_op(3, "count") == 0
    assert batch_mod._macro_apply_pipe_op(rows, "unknown") == rows


def test_macro_interpreter_runs_set_filter_loop_if_return_and_errors(monkeypatch, batch_mod):
    interpreter = batch_mod.MacroDSLInterpreter()
    interpreter.tools_registry["fake"] = lambda value=0: {"value": value, "ok": True}
    script = """
    set rows = [{"n": 1}, {"n": 3}]
    filter rows where n > 1
    for row in rows: fake(value=row.n)
    if rows: fake(value=9)
    rows | pluck(n) | count
    return _
    """
    result = interpreter.run(script)
    assert result["ok"] is True
    assert result["vars"]["rows"] == [{"n": 3}]
    assert interpreter.vars["_"] == 1
    assert len(result["results"]) == 2
    monkeypatch.setattr(interpreter, "_get_tool", lambda _name: None)
    error = interpreter.run("missing_tool(value=1)")
    assert error["ok"] is False


def test_macro_argument_parser_preserves_quoted_commas(batch_mod):
    interpreter = batch_mod.MacroDSLInterpreter()
    parsed = interpreter._parse_args('query="a,b", count=2, flag=true, ignored')
    assert parsed == {"query": "a,b", "count": 2, "flag": True}
    assert interpreter._get_tool("bad-name") is None


def test_dependencies_pipes_and_conditions_cover_validation_edges(batch_mod):
    order, error = batch_mod._resolve_dependencies([{"tool": "a"}, {"tool": "b", "depends_on": 0}])
    assert error is None and order == [0, 1]
    assert batch_mod._resolve_dependencies([{"tool": "a", "depends_on": 2}])[1]
    assert batch_mod._resolve_dependencies([{"tool": "a", "depends_on": "x"}])[1]
    source = [{"data": [1, 2]}, {"value": 4}, "scalar"]
    assert batch_mod._pipe_result({"pipe_from": 0, "x": "$pipe"}, source)["x"] == [1, 2]
    assert batch_mod._pipe_result({"pipe_from": 1, "pipe_field": "value", "x": "$pipe"}, source)["x"] == 4
    assert batch_mod._pipe_result({"pipe_from": 2, "x": "$pipe"}, source)["x"] == "$pipe"
    assert batch_mod._check_condition({}, source) == (True, None)
    assert batch_mod._check_condition({"if_result": {"index": 0, "field": "data", "op": "contains", "value": 2}}, source)[0]
    numeric = [{"n": 4}]
    assert batch_mod._check_condition({"if_result": {"index": 0, "field": "n", "op": "gt", "value": 0}}, numeric)[0]
    assert batch_mod._check_condition({"if_result": {"index": 0, "field": "n", "op": "lt", "value": 5}}, numeric)[0]
    assert not batch_mod._check_condition({"if_result": {"index": 8}}, source)[0]
    assert not batch_mod._check_condition({"if_result": {"index": 2}}, source)[0]


def test_template_expansion_and_batch_dry_run_validate_both_surfaces(batch_mod):
    template = [{"tool": "code", "addr": "$addr", "action": "decompile"}]
    assert batch_mod._resolve_template(template, {"addr": "0x1000"})[0]["addr"] == "0x1000"
    assert batch_mod._resolve_template(template, {}) is template
    script = batch_mod.batch(script="data(action='strings')", dry_run=True)
    assert script["mode"] == "script" and "data" in script["tool_calls_detected"]
    dry = batch_mod.batch(
        calls=[{"tool": "calc", "action": "eval", "expr": "1+1"}, {"action": "bad"}],
        dry_run=True,
    )
    assert dry["dry_run"] is True
    assert dry["validated"] == 1
    assert dry["errors"]
    unknown = batch_mod.batch(template="no_such_template")
    assert unknown.get("ok") is not True


def test_batch_stop_on_error_and_malformed_calls_are_reported(batch_mod):
    result = batch_mod.batch(
        calls=[
            {"tool": "no_such_tool", "action": "x"},
            {"tool": "calc", "action": "eval", "expr": "2+2"},
        ],
        stop_on_error=True,
    )
    assert result["ok"] is False
    assert result["executed"] == 0
    malformed = batch_mod.batch(calls=[None])
    assert malformed["ok"] is False
    assert malformed["results"][0].get("error") is True


def test_batch_deep_boundary_matrix_99(monkeypatch, batch_mod):
    # 1. Line 34: _macro_get_path with empty part between dots
    assert batch_mod._macro_get_path({"a": {"b": 10}}, "a..b") == 10

    # 2. Line 96 & 107: pipe ops with non-list data
    assert batch_mod._macro_apply_pipe_op("scalar", "first(2)") == "scalar"
    assert batch_mod._macro_apply_pipe_op(123, "sort(field)") == 123

    # 3. Line 159: MacroDSLInterpreter loading existing tool
    interpreter = batch_mod.MacroDSLInterpreter()
    tool_fn = interpreter._get_tool("calc")
    assert callable(tool_fn)

    # 4. Line 248: single-quoted string in _eval_expr
    assert interpreter._eval_expr("'single_quoted'") == "single_quoted"

    # 5. Line 254: _parse_args with empty string
    assert interpreter._parse_args("   ") == {}

    # 6. Lines 295, 308, 310, 313-316, 319: _eval_cond branches
    interpreter.vars["n"] = 5
    assert not interpreter._eval_cond("missing_var == 1")
    assert interpreter._eval_cond("n != 4")
    assert interpreter._eval_cond("n > 4")
    interpreter.vars["n"] = 2
    assert interpreter._eval_cond("n < 4")
    interpreter.vars["n"] = 4
    assert interpreter._eval_cond("n <= 4")
    assert interpreter._eval_cond("n >= 4")
    interpreter.vars["n"] = "not_a_num"
    assert not interpreter._eval_cond("n < 4")

    # 7. Line 602 & 399, 401, 407: Dependency error and circular dependency detection
    inv_calls = [
        {"tool": "calc", "depends_on": 1},
        {"tool": "calc", "action": "eval", "expr": "1+1"},
    ]
    res_inv = batch_mod.batch(calls=inv_calls)
    assert res_inv.get("error") is True
    assert "must refer to an earlier call" in res_inv["message"]

    class FakeDep(int):
        def __ge__(self, other):
            return False

    circ_calls = [
        {"tool": "calc", "depends_on": FakeDep(1)},
        {"tool": "calc", "depends_on": FakeDep(0)},
    ]
    order, err = batch_mod._resolve_dependencies(circ_calls)
    assert order is None
    assert "Circular dependency" in err

    # Lines 80 & 319: Unmatched operator in eval_cond via regex match override
    class FakeMatch:
        def group(self, n):
            return {1: "a", 2: "~=", 3: "1"}[n]

    real_match = batch_mod.re.match
    monkeypatch.setattr(batch_mod.re, "match", lambda pat, s: FakeMatch() if "~=" in s else real_match(pat, s))
    assert not batch_mod._macro_eval_cond({"a": 1}, "a ~= 1")
    interpreter.vars["a"] = 1
    assert not interpreter._eval_cond("a ~= 1")

    # 8. Lines 471 & 484-485: _check_condition exists op and lt exception
    assert batch_mod._check_condition({"if_result": {"index": 0, "field": "val", "op": "exists"}}, [{"val": 1}])[0]
    assert not batch_mod._check_condition({"if_result": {"index": 0, "field": "val", "op": "lt", "value": 10}}, [{"val": "str"}])[0]

    # 9. Lines 580-581: Non-dry-run script execution
    res_script = batch_mod.batch(script="set x = 42\nreturn x")
    assert res_script["ok"] is True
    assert res_script["final"] == 42

    # 10. Line 593: Empty calls list after template resolution
    monkeypatch.setattr(batch_mod, "_resolve_template", lambda _tmpl, _vars: [])
    res_empty = batch_mod.batch(template="analyze_function")
    assert res_empty.get("error") is True
    assert "calls list is required and cannot be empty" in res_empty["message"]

    # 11. Lines 608-621 & 626: Tool name normalization and validation
    calls_norm = [
        {"tool": 123},
        {"tool": "   "},
        {"tool": "pkg.calc", "action": "eval", "expr": "1+1"},
        {"tool": "mcp:calc", "action": "eval", "expr": "2+2"},
        {"tool": "path/calc", "action": "eval", "expr": "3+3"},
        {"tool": "ida-pro-mcp_calc", "action": "eval", "expr": "4+4"},
        {"tool": "bad tool!"},
    ]
    res_norm = batch_mod.batch(calls=calls_norm, stop_on_error=False)
    assert res_norm["total"] == 7

    # 12. Line 668: stop_on_error with non-dict call
    res_stop_nondict = batch_mod.batch(calls=[None, {"tool": "calc"}], stop_on_error=True)
    assert res_stop_nondict["executed"] == 0

    # 13. Line 685: stop_on_error with missing tool key
    res_stop_notool = batch_mod.batch(calls=[{"action": "eval"}, {"tool": "calc"}], stop_on_error=True)
    assert res_stop_notool["executed"] == 0

    # 14. Line 708: stop_on_error when tool raises exception
    def boom_calc(**_kwargs):
        raise RuntimeError("calc boom")

    import ida_pro_mcp.ida_mcp.tools.calc as calc_mod
    monkeypatch.setattr(calc_mod, "calc", boom_calc)
    res_stop_boom = batch_mod.batch(calls=[{"tool": "calc", "action": "eval"}, {"tool": "calc", "action": "eval"}], stop_on_error=True)
    assert res_stop_boom["executed"] == 0
    assert res_stop_boom["failed"] == 1
