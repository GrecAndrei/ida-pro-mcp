"""Cross-mode coverage for workflow batch normalization and execution."""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_workflow_batch as batch_module
from ida_pro_mcp.host.server.server_workflow_batch import ServerWorkflowBatchMixin


class _BatchHost(ServerWorkflowBatchMixin):
    def __init__(self, execute=None):
        self.executed = []
        self.cached = []
        self.activities = []
        self.fast_result = None
        self.execute = execute or (lambda _name, args: {"ok": True, "value": args.get("value", 1)})

    def _execute_tool(self, name, args):
        self.executed.append((name, dict(args)))
        return self.execute(name, args)

    def _extract_response_options(self, args):
        args = dict(args)
        opts = {key: args.pop(key) for key in ("max_tokens", "no_truncate") if key in args}
        return args, opts

    def _cache_next_page(self, name, args, result):
        self.cached.append((name, dict(args)))
        return result

    def _record_activity(self, name, args, result):
        self.activities.append((name, dict(args), result))

    def _try_batch_fast_path(self, _calls, _continue_on_error):
        return self.fast_result


def test_batch_normalization_and_reference_resolution_modes():
    host = _BatchHost()
    assert host._normalize_batch_call("idb:summary", 0) == ("idb", {"action": "summary"}, None)
    assert host._normalize_batch_call("idb", 0) == ("idb", {}, None)
    assert host._normalize_batch_call(" :summary", 0)[2]["error"] is True
    assert host._normalize_batch_call("", 0)[2]["error"] is True
    assert host._normalize_batch_call(4, 0)[2]["error"] is True

    name, args, err = host._normalize_batch_call(
        {"tool": "idb", "action": "meta", "args": {"value": 1}, "output_key": "meta", "source_count": 2, "extra": 3},
        0,
    )
    assert (name, err) == ("idb", None)
    assert args == {"value": 1, "action": "meta", "extra": 3}
    assert host._normalize_batch_call({"name": "idb", "arguments": "bad"}, 0)[1] == "bad"

    results = {"step0": {"nested": [{"addr": "0x10"}], "value": 7}, "long": {"value": 8}}
    known = {"step0", "step1"}
    assert host._resolve_batch_value({"a": ["$base", "step0_value"]}, {"base": 4}, results, known, 1)[0] == {"a": [4, 7]}
    assert host._resolve_batch_value("step0.result.nested.0.addr", {}, results, known, 1)[0] == "0x10"
    assert host._resolve_batch_value("step0.result", {}, results, known, 1)[0] == results["step0"]
    assert host._resolve_batch_value("literal text", {}, results, known, 1) == ("literal text", None)
    for value in ("$missing", "step0.result.absent", "step0_missing", "step1.result.x", "step99_value"):
        resolved, error = host._resolve_batch_value(value, {}, results, known, 1)
        assert resolved is None and error["code"] == MCPError.INVALID_ARGS
    assert host._dotted_path_get(["zero"], "0") == ("zero", True)
    assert host._dotted_path_get(["zero"], "bad") == (None, False)
    assert host._resolve_batch_step_args({"x": 1}, {}, {}, set(), 0) == ({"x": 1}, None)
    resolved, error = host._resolve_batch_step_args([], {}, {}, set(), 0)
    assert resolved is None and error["error"] is True


def test_run_batch_steps_covers_admission_errors_chaining_and_wrapped_failures():
    def execute(name, args):
        if args.get("value") == "boom":
            raise RuntimeError("boom")
        if name == "idb" and args.get("action") == "summary":
            return {"ok": True, "value": 9, "nested": {"addr": "0x20"}}
        return {"ok": True, "value": args.get("value", 1)}

    host = _BatchHost(execute)
    steps = host._run_batch_steps(
        [
            {"name": "idb", "arguments": {"action": "summary"}, "output_key": "summary"},
            {"name": "calc", "arguments": {"value": "summary.result.nested.addr"}},
            {"name": "missing", "arguments": {}},
            {"name": "batch", "arguments": {}},
            {"name": "idb", "arguments": "bad"},
            {"name": 4, "arguments": {}},
            {"name": "idb", "arguments": {"value": "$base"}},
            {"_precomputed_error": {"error": True, "code": "PRECOMPUTED"}},
            "",
            None,
            {"name": "idb", "arguments": {"value": "boom"}},
        ],
        True,
        bindings={"base": 3},
        wrap_errors=True,
    )
    assert steps[0]["result"]["ok"] is True
    assert host.executed[1][1]["value"] == "0x20"
    assert any(step["result"].get("code") == MCPError.INVALID_ARGS for step in steps if isinstance(step["result"], dict))
    assert steps[-1]["result"]["code"] == MCPError.INTERNAL

    stopped = host._run_batch_steps(
        [{"name": "missing", "arguments": {}}, {"name": "idb", "arguments": {}}],
        False,
    )
    assert len(stopped) == 1

    # Workflow execution intentionally defers unknown-tool validation.
    permissive = host._run_batch_steps([{"name": "custom", "arguments": {}}], True, validate_tools=False)
    assert permissive[0]["result"]["ok"] is True


def test_handle_batch_limits_bindings_fast_path_and_summary(monkeypatch):
    host = _BatchHost()
    assert host._handle_batch({"calls": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._handle_batch({"calls": []})["code"] == MCPError.BATCH_EMPTY

    monkeypatch.setattr(batch_module, "MAX_BATCH_CALLS", 1)
    assert host._handle_batch({"calls": [{}, {}]})["code"] == MCPError.BATCH_TOO_LARGE
    monkeypatch.setattr(batch_module, "MAX_BATCH_CALLS", 1000)
    monkeypatch.setattr(batch_module, "MAX_BATCH_PAYLOAD_BYTES", 1)
    assert host._handle_batch({"calls": [{"name": "idb"}]})["code"] == MCPError.INVALID_ARGS
    monkeypatch.setattr(batch_module, "MAX_BATCH_PAYLOAD_BYTES", 10_000_000)
    assert host._handle_batch({"calls": [{"name": "idb"}], "bindings": []})["code"] == MCPError.INVALID_ARGS

    host.fast_result = {"ok": True, "fast": True}
    assert host._handle_batch({"calls": [{"name": "idb"}, {"name": "idb"}]}) == {"ok": True, "fast": True}
    host.fast_result = None
    result = host._handle_batch({"calls": [{"name": "idb"}, {"name": "idb"}], "continue_on_error": "false"})
    assert result["ok"] is True
    assert result["summary"]["total"] == 2
    assert len(host.cached) == 2


@pytest.mark.parametrize(
    ("value", "known", "expected"),
    [("step0", {"step0"}, False), ("step0.result.x", {"step0"}, True), ("$x", set(), True), ("ordinary", set(), False)],
)
def test_batch_reference_detection_modes(value, known, expected):
    assert _BatchHost()._batch_value_is_reference(value, known) is expected
