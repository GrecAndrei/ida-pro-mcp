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
