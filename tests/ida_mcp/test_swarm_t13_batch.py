"""Regression tests for swarm/t13_batch audit fixes.

Covers three findings on the IDA-side batch tool:
1. Top-level ``ok`` envelope now reflects sub-call failures (was always True),
   matching the host ``_handle_batch`` ``ok: errors == 0`` semantics.
2. The macro-DSL interpreter no longer lets exceptions escape:
   ``first(...)`` swallows a malformed count like ``sort(...)`` does, and
   ``batch()`` wraps ``interpreter.run`` in the error envelope.
3. ``batch`` is classified as a write operation (``@idawrite``), so its
   result is not stored in the read cache and read caches are invalidated —
   consistent with the host WRITE_IDB policy classification.
"""

from __future__ import annotations

import contextlib
import importlib as _real_importlib
import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

class _MCPErrorStub:
    INVALID_ARGS = "INVALID_ARGS"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    UNKNOWN = "UNKNOWN"


def _real_make_error(code, message, recoverable=False, details=None, hint=None):
    res = {
        "error": True,
        "code": code,
        "category": "internal",
        "message": message,
        "recoverable": recoverable,
    }
    if hint:
        res["hint"] = hint
    if details:
        res["details"] = details
    return res


def _real_handle_error(e, context=None):
    msg = f"[{context}] {e}" if context else str(e)
    return {
        "error": True,
        "code": "UNKNOWN",
        "category": "internal",
        "message": msg,
        "recoverable": False,
    }


def _mark_write(fn):
    fn._ida_write = True
    return fn


def _mark_read(fn):
    fn._ida_read = True
    return fn


BATCH = load_tool_module(
    "batch",
    common_overrides={
        "MCPError": _MCPErrorStub,
        "make_error": _real_make_error,
        "handle_error": _real_handle_error,
        "idaread": _mark_read,
        "idawrite": _mark_write,
    },
)


@contextlib.contextmanager
def _resolved_tool(name: str, func):
    """Make batch()'s local get_tool resolve `name` to `func`.

    batch() resolves sub-tools via ``importlib.import_module(".<name>")`` into
    a per-call registry; patch that lookup so the calls path can be exercised
    without importing the real (IDA-bound) tool modules.
    """
    orig = _real_importlib.import_module

    def _fake(fqname, package=None):
        if fqname == name or fqname.endswith("." + name):
            fake = types.ModuleType(f"_fake_{name}")
            setattr(fake, name, func)
            return fake
        return orig(fqname, package)

    BATCH.importlib.import_module = _fake
    try:
        yield
    finally:
        BATCH.importlib.import_module = orig


def _list_ok(**kwargs):
    return {"ok": True, "data": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}


def _bare_list(**kwargs):
    return [{"name": "a"}, {"name": "b"}, {"name": "c"}]


# ---------------------------------------------------------------------------
# Finding 2: DSL first(...) pipe op swallows a malformed count
# ---------------------------------------------------------------------------

def test_pipe_first_valid_slices():
    assert BATCH._macro_apply_pipe_op([1, 2, 3], "first(2)") == [1, 2]


def test_pipe_first_malformed_passes_through():
    # `int("abc")` used to raise ValueError out of the interpreter.
    assert BATCH._macro_apply_pipe_op([1, 2, 3], "first(abc)") == [1, 2, 3]


def test_pipe_first_hex_literal_passes_through():
    # `int("0x10")` raises without base 0; must not escape either.
    assert BATCH._macro_apply_pipe_op([1, 2, 3], "first(0x10)") == [1, 2, 3]


def test_pipe_first_malformed_on_non_list():
    assert BATCH._macro_apply_pipe_op("hello", "first(abc)") == "hello"


def test_dsl_script_with_malformed_first_does_not_raise():
    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry["data"] = _list_ok
    res = interp.run('data(action="strings") | first(abc)')
    assert res["ok"] is True
    # Malformed count passes the data through unchanged (no slice, no crash).
    assert interp.vars["_"] == {"ok": True, "data": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}


# ---------------------------------------------------------------------------
# Finding 1: top-level ok envelope reflects sub-result errors
# ---------------------------------------------------------------------------

def test_dsl_run_ok_false_when_subtool_raises():
    def boom(**kwargs):
        raise RuntimeError("boom")

    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry["data"] = boom
    res = interp.run('data(action="strings")')
    assert res["ok"] is False
    assert res["results"][0]["result"]["error"] is True


def test_dsl_run_ok_false_when_subtool_returns_error_dict():
    def err_ret(**kwargs):
        return {"error": True, "code": "X", "message": "failed"}

    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry["data"] = err_ret
    res = interp.run('data(action="strings")')
    assert res["ok"] is False


def test_dsl_run_ok_true_all_succeed():
    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry["data"] = _bare_list
    res = interp.run('data(action="strings") | first(2)')
    assert res["ok"] is True
    assert interp.vars["_"] == [{"name": "a"}, {"name": "b"}]


def test_batch_calls_ok_true_all_succeed():
    with _resolved_tool("data", _list_ok):
        resp = BATCH.batch(calls=[{"tool": "data", "action": "strings"}])
    assert resp["ok"] is True
    assert resp["failed"] == 0
    assert resp["succeeded"] == 1


def test_batch_calls_ok_false_on_subcall_failure():
    def boom(**kwargs):
        raise RuntimeError("boom")

    with _resolved_tool("data", boom):
        resp = BATCH.batch(calls=[{"tool": "data", "action": "strings"}])
    assert resp["ok"] is False
    assert resp["failed"] == 1
    assert resp["succeeded"] == 0


def test_batch_calls_ok_false_when_unknown_tool():
    # Unknown tool resolves to an error result per call; envelope must follow.
    resp = BATCH.batch(calls=[{"tool": "no_such_tool_xyz", "action": "strings"}])
    assert resp["ok"] is False
    assert resp["failed"] == 1


# ---------------------------------------------------------------------------
# Finding 2: batch() wraps interpreter.run in the error envelope
# ---------------------------------------------------------------------------

def test_batch_script_error_returns_error_envelope():
    orig_run = BATCH.MacroDSLInterpreter.run

    def boom_run(self, script):
        raise ValueError("interpreter boom")

    BATCH.MacroDSLInterpreter.run = boom_run
    try:
        resp = BATCH.batch(script='data(action="strings")')
    finally:
        BATCH.MacroDSLInterpreter.run = orig_run
    assert isinstance(resp, dict)
    assert resp.get("error") is True
    assert "interpreter boom" in resp.get("message", "")


# ---------------------------------------------------------------------------
# Finding 3: batch is a write operation (no read caching, cache invalidation)
# ---------------------------------------------------------------------------

def test_batch_decorated_as_write_not_read():
    assert getattr(BATCH.batch, "_ida_write", False) is True
    assert getattr(BATCH.batch, "_ida_read", False) is False


def test_macro_helpers_cover_paths_conditions_and_all_pipe_operators():
    assert BATCH._macro_get_path({"a": {"b": ["x", "y"]}}, "a.b.1") == "y"
    assert BATCH._macro_get_path(["x"], "0") == "x"
    assert BATCH._macro_get_path(["x"], "9") is None
    assert BATCH._macro_get_path("x", "a") is None
    assert BATCH._macro_get_path({"a": 1}, ".") == {"a": 1}

    item = {"value": 5, "text": "hello", "tags": ["a", "b"]}
    assert BATCH._macro_eval_cond(item, "value") is True
    assert BATCH._macro_eval_cond(item, "missing") is False
    for expr in ("value == 5", "value != 4", "value > 4", "value >= 5", "value < 6", "value <= 5", 'text == "hello"', "tags contains"):
        # The last expression intentionally exercises the unsupported operator
        # path and is expected to be false.
        if expr == "tags contains":
            assert BATCH._macro_eval_cond(item, expr) is False
        else:
            assert BATCH._macro_eval_cond(item, expr) is True
    assert BATCH._macro_eval_cond(item, "value > bad") is False
    assert BATCH._macro_eval_cond(item, "missing == 1") is False

    assert BATCH._macro_apply_pipe_op([1, 2], "count") == 2
    assert BATCH._macro_apply_pipe_op({"a": 1}, "count") == 1
    assert BATCH._macro_apply_pipe_op(4, "count") == 0
    assert BATCH._macro_apply_pipe_op([{"n": 2}, {"n": 1}], "sort(n)") == [{"n": 1}, {"n": 2}]
    assert BATCH._macro_apply_pipe_op([{"n": 1}, {"n": 2}], "sort(-n)") == [{"n": 2}, {"n": 1}]
    unsortable = [{"n": object()}, {"n": object()}]
    assert BATCH._macro_apply_pipe_op(unsortable, "sort(n)") is unsortable
    assert BATCH._macro_apply_pipe_op([1, 1, {"x": 1}, {"x": 1}], "unique") == [1, {"x": 1}]
    assert BATCH._macro_apply_pipe_op("x", "unique") == "x"
    data = [{"name": "a", "meta": {"kind": "x"}}, {"name": "b", "meta": {"kind": "y"}}]
    assert BATCH._macro_apply_pipe_op(data, "pluck(name)") == ["a", "b"]
    assert BATCH._macro_apply_pipe_op({"name": "a"}, "pluck(name)") == "a"
    assert BATCH._macro_apply_pipe_op([1, 2], "reverse") == [2, 1]
    assert BATCH._macro_apply_pipe_op("x", "reverse") == "x"
    assert BATCH._macro_apply_pipe_op(data, "filter(meta.kind == x)") == [data[0]]
    assert BATCH._macro_apply_pipe_op("x", "filter(name == x)") == "x"
    assert BATCH._macro_apply_pipe_op(data, "group_by(meta.kind)") == {"x": [data[0]], "y": [data[1]]}
    assert BATCH._macro_apply_pipe_op("x", "group_by(name)") == "x"
    assert BATCH._macro_apply_pipe_op([1], "not-an-op") == [1]


def test_macro_interpreter_runs_assignments_filters_loops_conditionals_and_args():
    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry["data"] = lambda **kwargs: {"ok": True, "data": [{"n": 1}, {"n": 2}]}
    result = interp.run(
        """# comments are ignored
        set numbers = [{"n": 1}, {"n": 2}]
        filter numbers where n > 1
        for entry in numbers: data(action="strings", note="a,b")
        if numbers: data(action="imports")
        return numbers | pluck(n) | count
        """
    )
    assert result["ok"] is True
    assert result["vars"]["numbers"] == [{"n": 2}]
    assert interp.vars["_"] == 1
    assert len(result["results"]) == 2
    assert result["results"][0]["args"] == {"action": "strings", "note": "a,b"}
    assert interp._eval_expr("numbers") == [{"n": 2}]
    assert interp._eval_expr('{"x": 1}') == {"x": 1}
    assert interp._eval_expr('"quoted"') == "quoted"
    assert interp._eval_expr("bare text") == "bare text"
    assert interp._parse_args('bad, x=1, y="a,b", z=true') == {"x": 1, "y": "a,b", "z": True}
    assert interp._eval_cond("numbers") is True
    assert interp._eval_cond("missing") is False
    assert interp._eval_cond("numbers == 0") is False
    assert interp._eval_cond("numbers > bad") is False
    assert interp._get_tool("bad-name") is None


def test_macro_tool_lookup_import_failure_is_cached(monkeypatch):
    interp = BATCH.MacroDSLInterpreter()
    interp.tools_registry.clear()
    original = BATCH.importlib.import_module

    def fail(name, package=None):
        if name.endswith(".missing_tool"):
            raise ImportError("missing")
        return original(name, package)

    monkeypatch.setattr(BATCH.importlib, "import_module", fail)
    assert interp._get_tool("missing_tool") is None
    assert interp._get_tool("missing_tool") is None
    assert interp.tools_registry["missing_tool"] is None


def test_batch_dependency_pipe_condition_and_template_helpers():
    assert BATCH._resolve_template([], {}) == []
    calls = [{"tool": "data", "addr": "$addr", "literal": "$missing"}]
    assert BATCH._resolve_template(calls, {"addr": "0x1"}) == [
        {"tool": "data", "addr": "0x1", "literal": "$missing"}
    ]
    assert BATCH._resolve_dependencies([]) == ([], None)
    assert BATCH._resolve_dependencies([{"tool": "a"}, {"tool": "b", "depends_on": 0}])[0] == [0, 1]
    assert BATCH._resolve_dependencies([{"tool": "a"}, {"tool": "b", "depends_on": [0]}])[0] == [0, 1]
    assert BATCH._resolve_dependencies([{"depends_on": 9}])[1]
    assert BATCH._resolve_dependencies([{"depends_on": "0"}])[1]
    assert BATCH._resolve_dependencies([{"depends_on": 1}, {}])[1]
    assert BATCH._resolve_dependencies([{"depends_on": [0]}, {}])[1]

    results = [{"results": [1, 2], "value": 9}, {"ok": True}]
    assert BATCH._pipe_result({"tool": "x"}, results) == {"tool": "x"}
    assert BATCH._pipe_result({"pipe_from": 9, "x": "$pipe"}, results)["x"] == "$pipe"
    assert BATCH._pipe_result({"pipe_from": 0, "x": "$pipe"}, results)["x"] == [1, 2]
    assert BATCH._pipe_result({"pipe_from": 0, "pipe_field": "value", "x": "$pipe"}, results)["x"] == 9
    assert BATCH._pipe_result({"pipe_from": 1, "x": "$pipe"}, results)["x"] is None
    assert BATCH._pipe_result({"pipe_from": 0, "x": "$pipe"}, ["not dict"])["x"] == "$pipe"

    assert BATCH._check_condition({}, results) == (True, None)
    assert BATCH._check_condition({"if_result": "bad"}, results) == (True, None)
    assert BATCH._check_condition({"if_result": {"index": 9}}, results)[0] is False
    assert BATCH._check_condition({"if_result": {"index": 0, "field": "value", "op": "eq", "value": 9}}, results) == (True, None)
    for op, value in (("ne", 8), ("gt", 8), ("lt", 10)):
        assert BATCH._check_condition({"if_result": {"index": 0, "field": "value", "op": op, "value": value}}, results)[0] is True
    assert BATCH._check_condition({"if_result": {"index": 0, "field": "results", "op": "contains", "value": 2}}, results)[0] is True
    assert BATCH._check_condition({"if_result": {"index": 0, "field": "value", "op": "bad"}}, results)[0] is False
    assert BATCH._check_condition({"if_result": {"index": 0, "field": "missing", "op": "gt", "value": 1}}, results)[0] is False
    assert BATCH._check_condition({"if_result": {"index": 0, "field": "value", "op": "contains", "value": "x"}}, results)[0] is False
    assert BATCH._check_condition({"if_result": {"index": 0}}, ["bad"])[0] is False


def test_batch_top_level_modes_validate_and_stop_as_requested():
    dry_script = BATCH.batch(script="data(action='strings')\nreturn _", dry_run=True)
    assert dry_script["ok"] is True and dry_script["mode"] == "script"
    assert BATCH.batch()["code"] == "INVALID_ARGS"
    assert BATCH.batch(template="not-a-template")["code"] == "INVALID_ARGS"
    assert BATCH.batch(calls=[{}], dry_run=True)["validated"] == 0
    assert BATCH.batch(calls=[{"tool": "no_such_tool_xyz"}], dry_run=True)["errors"]
    assert BATCH.batch(calls=[{"tool": "data"}] * 21)["code"] == "INVALID_ARGS"

    with _resolved_tool("code", _list_ok), _resolved_tool("data", _list_ok):
        template_result = BATCH.batch(template="analyze_function", template_vars={"addr": "0x401000"})
    assert template_result["ok"] is True

    with _resolved_tool("data", _list_ok):
        piped = BATCH.batch(
            calls=[
                {"tool": "data", "action": "strings"},
                {"tool": "data", "action": "functions", "query": "$pipe", "pipe_from": 0, "pipe_field": "data"},
                {"tool": "data", "action": "skipped", "if_result": {"index": 0, "field": "ok", "op": "eq", "value": False}},
            ]
        )
    assert piped["executed"] == 2 and piped["skipped"] == 1

    def error(**kwargs):
        return {"error": True, "code": "FAIL"}

    with _resolved_tool("data", error):
        stopped = BATCH.batch(
            calls=[{"tool": "data", "action": "one"}, {"tool": "data", "action": "two"}],
            stop_on_error=True,
        )
    assert stopped["failed"] == 1 and stopped["executed"] == 1

    with _resolved_tool("data", lambda **kwargs: {"ok": True}):
        malformed = BATCH.batch(calls=["not-a-call", {"action": "missing-tool"}])
    assert malformed["failed"] == 2
