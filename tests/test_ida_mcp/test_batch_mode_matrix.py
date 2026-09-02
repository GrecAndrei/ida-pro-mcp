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
