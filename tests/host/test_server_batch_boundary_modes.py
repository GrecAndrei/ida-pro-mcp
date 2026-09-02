"""Composed coverage for background task admission and ownership boundaries."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.server import server_batch
from ida_pro_mcp.host.server.server_batch import BackgroundMixin


def test_semantic_index_scope_validation_covers_all_request_shapes():
    valid = {
        "limit": 4,
        "_index_total_limit": 10,
        "_index_slice_size": 2,
        "radius": 8,
        "addr": "0x401000",
        "start": "0x4000",
        "end": "0x5000",
        "ranges": [{"start": "0x6000", "end": "0x7000"}],
        "min_size": 0,
        "max_size": 20,
    }
    assert BackgroundMixin._validate_semantic_index_scope(valid) is None

    invalid = [
        ({"limit": "x"}, "limit"),
        ({"limit": 0}, "limit"),
        ({"radius": 4}, "address"),
        ({"start": "0x1000"}, "start and end"),
        ({"start": "bad", "end": "0x2000"}, "hexadecimal"),
        ({"start": "0x2000", "end": "0x1000"}, "greater"),
        ({"ranges": []}, "non-empty"),
        ({"ranges": "bad"}, "non-empty"),
        ({"ranges": [{"start": "0x1000"}]}, "exactly"),
        ({"ranges": [{"start": "bad", "end": "0x2000"}]}, "hexadecimal"),
        ({"min_size": 8, "max_size": 2}, "cannot exceed"),
    ]
    for args, text in invalid:
        error = BackgroundMixin._validate_semantic_index_scope(args)
        assert error and text in error["message"], (args, error)


class _TaskManager:
    def __init__(self):
        self.tasks = [{"task_id": "owned", "session_id": "S1", "state": "done"}]
        self.wait_args = []

    def status(self, task_id=None):
        if task_id is None:
            return list(self.tasks)
        return [task for task in self.tasks if task["task_id"] == task_id]

    def result(self, task_id):
        return {"ok": True, "task_id": task_id, "result": "ready"}

    def cancel(self, task_id):
        return {"ok": True, "task_id": task_id, "cancelled": True}

    def list_tasks(self, state=None):
        return [task for task in self.tasks if state is None or task["state"] == state]

    def wait(self, task_id, timeout=None):
        self.wait_args.append((task_id, timeout))
        return {"ok": True, "task_id": task_id, "state": "done"}

    def submit(self, **_kwargs):
        return "submitted"


class _BackgroundHarness(BackgroundMixin):
    def __init__(self):
        self._batch_mgr = _TaskManager()
        self.current_session = SimpleNamespace(session_id="S1")

    def _resolve_policy_mode(self):
        return "assist"


def test_background_policy_admission_and_task_lifecycle_modes(monkeypatch):
    host = _BackgroundHarness()
    assert host._handle_background({"action": "bogus"})["error"] is True
    assert host._background_policy_preflight(script="print(1)", tool_call=None)["error"] is True
    assert host._background_policy_preflight(script=None, tool_call="bad")["error"] is True
    assert host._background_policy_preflight(script=None, tool_call={"args": {}})["error"] is True
    assert host._background_policy_preflight(script=None, tool_call={"tool": "x", "args": []})["error"] is True

    # A read-only tool call is admitted; a mutation is gated until explicitly
    # acknowledged by the caller.
    assert host._background_policy_preflight(
        script=None, tool_call={"tool": "analysis", "args": {"action": "get_options"}}
    ) is None
    blocked = host._background_policy_preflight(
        script=None, tool_call={"tool": "modify", "args": {"action": "rename"}}
    )
    assert blocked and blocked["error"] is True
    assert host._background_policy_preflight(
        script=None,
        tool_call={"tool": "modify", "args": {"action": "rename", "_risk_ack": True}},
    ) is None

    assert host._bg_status({})["tasks"]
    assert host._bg_status({"task_id": "missing"})["error"] is True
    assert host._bg_result({})["error"] is True
    assert host._bg_result({"task_id": "owned"})["result"] == "ready"
    assert host._bg_cancel({})["error"] is True
    assert host._bg_cancel({"task_id": "owned"})["cancelled"] is True
    assert host._bg_list({"state": "done", "session_id": "S1"})["tasks"]
    assert host._bg_list({"session_id": "other"})["tasks"] == []
    assert host._bg_wait({})["error"] is True
    assert host._bg_wait({"task_id": "owned", "timeout": "bad"})["error"] is True
    monkeypatch.setattr(server_batch, "_BG_WAIT_MAX_SECONDS", 3.0)
    assert host._bg_wait({"task_id": "owned", "timeout": 99})["state"] == "done"
    assert host._bg_wait({"task_id": "owned"})["state"] == "done"
    assert host._batch_mgr.wait_args == [("owned", 3.0), ("owned", 3.0)]


def test_background_submit_validates_session_policy_and_runs_tool_call(monkeypatch):
    class _SubmitHarness(_BackgroundHarness):
        def __init__(self):
            super().__init__()
            self.session_mgr = SimpleNamespace(get_session=lambda sid: self.session if sid == "S1" else None)
            self.session = SimpleNamespace(session_id="S1")
            self.current_session = self.session
            self.executed = []

        def _ensure_client_owns_session(self, _session):
            return None

        def _execute_tool(self, tool, args):
            self.executed.append((tool, args))
            return {"ok": True, "tool": tool}

    host = _SubmitHarness()
    assert host._bg_submit({})["error"] is True
    assert host._bg_submit(
        {"tool_call": {"tool": "analysis", "args": {"action": "get_options"}}}
    )["state"] == "pending"
    # The task manager here is intentionally the real submission boundary only
    # in the production class; replace it with a deterministic submitter so the
    # worker closure itself is exercised without a timing race.
    submitted = []

    class _Submitter:
        def submit(self, **kwargs):
            submitted.append(kwargs)
            return "task-1"

    host._batch_mgr = _Submitter()
    result = host._bg_submit(
        {
            "session_id": "S1",
            "tool_call": {"tool": "analysis", "args": {"action": "get_options"}},
        }
    )
    assert result == {"task_id": "task-1", "state": "pending"}
    task = SimpleNamespace(session_id="S1", args=submitted[0]["args"])
    assert submitted[0]["run_fn"](task) == {"ok": True, "tool": "analysis"}
    assert host.executed == [("analysis", {"action": "get_options"})]
