"""Regression tests for workflow/batch fixes (package p08_workflow_batch).

Covers the audit findings: execute_plan error envelope + executed_steps
counting, stale audit_plan risk-hint actions, alias agreement between
audit_plan/execute_plan, plan pseudo-action validation, honest BatchManager
cancellation, per-instance persistence, running-task eviction, worker-state
isolation for background tasks, and defensive argument coercion.
"""

from __future__ import annotations

import threading
import time
import typing
from types import SimpleNamespace

import ida_pro_mcp.host.batch_manager as bm_module
from ida_pro_mcp.host.batch_manager import BatchManager
from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_batch import BackgroundMixin

# ---------------------------------------------------------------------------
# execute_plan
# ---------------------------------------------------------------------------

def test_execute_plan_step_raise_uses_error_envelope(monkeypatch):
    """A raised _execute_tool must surface as a full error envelope, not a
    bare {'error': True, 'message': ...} dict."""
    server = IDAMCPServer()

    def fake_execute(tool_name, args):
        if tool_name == "raises":
            raise RuntimeError("boom")
        return {"ok": True, "tool": tool_name}

    monkeypatch.setattr(server, "_execute_tool", fake_execute)

    result = server._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [{"name": "raises", "arguments": {"action": "x"}}],
            "continue_on_error": True,
        }
    )
    step_result = result["calls"][0]["result"]
    assert step_result.get("error") is True
    assert step_result.get("code") == MCPError.INTERNAL
    assert step_result.get("category") == "internal"
    assert "hint" in step_result
    assert "boom" in step_result.get("message", "")
    assert result["summary"]["error_steps"] == 1


def test_execute_plan_executed_steps_counts_real_runs(monkeypatch):
    """executed_steps must reflect steps actually executed, not the total plan
    length when continue_on_error=False halts early."""
    server = IDAMCPServer()
    calls_seen: list[str] = []

    def fake_execute(tool_name, args):
        calls_seen.append(tool_name)
        if tool_name == "fails":
            return {"error": True, "code": MCPError.INVALID_ARGS, "category": "user",
                    "message": "nope", "recoverable": False}
        return {"ok": True, "tool": tool_name}

    monkeypatch.setattr(server, "_execute_tool", fake_execute)

    result = server._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "fails", "arguments": {"action": "x"}},
                {"name": "idb", "arguments": {"action": "meta"}},
            ],
            "continue_on_error": False,
        }
    )
    summary = result["summary"]
    assert calls_seen == ["idb", "fails"]
    assert summary["executed_steps"] == 2
    assert summary["completed_steps"] == 1
    assert summary["error_steps"] == 1
    assert summary["skipped_steps"] == 0


# ---------------------------------------------------------------------------
# audit_plan / plan
# ---------------------------------------------------------------------------

def test_audit_plan_accepts_alias_tool_names():
    """audit_plan must resolve tool aliases the way execute_plan's dispatch
    does, so the two agree on what constitutes a valid plan."""
    server = IDAMCPServer()
    result = server._handle_workflow(
        {
            "action": "audit_plan",
            "planned_calls": [
                {"name": "searches", "arguments": {"action": "find", "query": "http"}},
            ],
        }
    )
    assert result.get("ok") is True
    assert result["audit"]["invalid_call_count"] == 0
    assert result["planned_calls"][0]["name"] == "search"


def test_audit_plan_risk_hint_only_for_valid_search_action():
    """Only search.vulnerable (a real TOOL_ACTIONS entry) may add a risk hint;
    the stale malware/vuln/api_hashing branches are unreachable."""
    server = IDAMCPServer()
    result = server._handle_workflow(
        {
            "action": "audit_plan",
            "planned_calls": [
                {"name": "search", "arguments": {"action": "vulnerable"}},
                {"name": "search", "arguments": {"action": "vuln"}},
            ],
        }
    )
    assert result.get("ok") is True
    assert any("search.vulnerable" in hint for hint in result["audit"]["risk_hints"])
    assert result["audit"]["invalid_call_count"] == 1


def test_plan_rejects_pseudo_action_targets():
    """plan must reject non-executable pseudo-actions (explain/catalog/...)
    instead of silently recursing into their handlers."""
    server = IDAMCPServer()
    for target in ("explain", "catalog", "estimate", "compose"):
        result = server._handle_workflow({"action": "plan", "workflow_action": target})
        assert result.get("error") is True, target
        assert result.get("code") == MCPError.INVALID_ARGS, target


# ---------------------------------------------------------------------------
# BatchManager cancellation
# ---------------------------------------------------------------------------

def test_cancel_cooperative_worker_reports_cancelled_with_result():
    """A cooperative worker that aborts (semantic-index style) must finalize as
    'cancelled' and keep its payload (e.g. a resume cursor)."""
    mgr = BatchManager(max_workers=1)
    ready = []

    def _coop(task):
        ready.append(1)
        while not task._cancel_event.is_set():
            time.sleep(0.005)
        return {"ok": True, "cancelled": True, "next_cursor": "0x20"}

    task_id = mgr.submit("semantic_index", {}, run_fn=_coop)
    while not ready:
        time.sleep(0.005)
    cancel_result = mgr.cancel(task_id)
    assert cancel_result["state"] == "cancelled"
    assert cancel_result["result"] == {"ok": True, "cancelled": True, "next_cursor": "0x20"}
    mgr.shutdown()


def test_cancel_does_not_report_completed_write_work_as_cancelled():
    """A task whose work ran to completion despite a cancel request must be
    reported as done with its result, not as a false cancellation."""
    mgr = BatchManager(max_workers=1)
    ready = []

    def _write(task):
        ready.append(1)
        task._cancel_event.wait(timeout=3)  # completes the "write" regardless
        return {"ok": True, "applied": 1}

    task_id = mgr.submit("tool_call", {}, run_fn=_write)
    while not ready:
        time.sleep(0.005)
    cancel_result = mgr.cancel(task_id)
    assert cancel_result["state"] == "done"
    assert cancel_result["result"] == {"ok": True, "applied": 1}
    mgr.shutdown()


def test_batch_manager_registers_atexit_shutdown(monkeypatch):
    """The executor's non-daemon worker threads must be reclaimed at process
    exit: BatchManager registers its own shutdown with atexit (the host has no
    teardown path that would call it otherwise)."""
    import atexit

    registered = []
    monkeypatch.setattr(
        atexit, "register", lambda func, *args, **kwargs: registered.append(func)
    )
    mgr = BatchManager(max_workers=1)
    try:
        assert any(
            getattr(getattr(func, "__self__", None), "_instance_id", None)
            == mgr._instance_id
            for func in registered
        )
    finally:
        mgr.shutdown()


def test_trim_history_never_evicts_running_task(monkeypatch):
    """Evicting the oldest tasks by created_at must skip pending/running tasks,
    or a live task's id would become NOT_FOUND while its future still runs."""
    monkeypatch.setattr(bm_module, "_MAX_TASK_HISTORY", 10)
    mgr = BatchManager(max_workers=2)
    release = threading.Event()
    started: list[str] = []

    def _slow(task):
        started.append(task.task_id)
        release.wait(timeout=5)
        return {"ok": True}

    running_id = mgr.submit("script", {}, run_fn=_slow)
    while not started:
        time.sleep(0.005)
    try:
        for _ in range(30):
            mgr.submit("script", {}, run_fn=lambda task: {"ok": True})
        time.sleep(0.2)  # let the terminal tasks finish
        status = mgr.status(running_id)
        assert status, "running task must not be evicted by _trim_history"
        assert status[0]["state"] == "running"
    finally:
        release.set()
        mgr.shutdown()


def test_batch_persistence_is_per_instance(tmp_path, monkeypatch):
    """Each BatchManager must persist to its own file so concurrent
    connections/processes never clobber each other's task state."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    mgr_a = BatchManager(max_workers=1)
    mgr_b = BatchManager(max_workers=1)
    assert mgr_a._persist_path() != mgr_b._persist_path()
    try:
        task_a = mgr_a.submit("tool_call", {"x": 1}, run_fn=lambda task: {"ok": True})
        mgr_a.wait(task_a, timeout=5)
        # mgr_b neither loads nor clobbers mgr_a's persisted tasks.
        assert mgr_b.status() == []
        task_b = mgr_b.submit("tool_call", {"x": 2}, run_fn=lambda task: {"ok": True})
        mgr_b.wait(task_b, timeout=5)
        assert mgr_b.status() and mgr_b.status()[0]["session_id"] is None
        persisted = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("tasks-"))
        assert len(persisted) == 2
        assert persisted[0] != persisted[1]
    finally:
        mgr_a.shutdown()
        mgr_b.shutdown()


# ---------------------------------------------------------------------------
# Background (server_batch) fixes
# ---------------------------------------------------------------------------

class _FakeSessionManager:
    def __init__(self, sessions):
        self._by_id = {str(s.session_id): s for s in sessions}

    def get_session(self, session_id):
        return self._by_id.get(str(session_id))


def _init_background_server(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server._ensure_runtime_and_idb = lambda session: None
    server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
    return server


def test_bg_submit_rejects_scripts(tmp_path, monkeypatch):
    """Scripts are rejected at preflight, so the dead in-worker script branch
    can never queue a script task."""
    server = _init_background_server(tmp_path, monkeypatch)
    try:
        result = server._bg_submit({"script": "print(1)"})
        assert result.get("error") is True
    finally:
        server.shutdown()


def test_bg_submit_does_not_switch_client_active_session(tmp_path, monkeypatch):
    """A background task targeting a different session must not permanently
    switch the client's active session (worker state must be isolated)."""
    session_a = SimpleNamespace(session_id="A", idb_path=str(tmp_path / "SID_A.i64"),
                                binary_path=str(tmp_path / "a.bin"), analysis_options={})
    session_b = SimpleNamespace(session_id="B", idb_path=str(tmp_path / "SID_B.i64"),
                                binary_path=str(tmp_path / "b.bin"), analysis_options={})
    server = _init_background_server(tmp_path, monkeypatch)
    server.session_mgr = _FakeSessionManager([session_a, session_b])

    token = server._begin_client_connection()
    try:
        server.current_session = session_a
        submitted = server._bg_submit(
            {
                "session_id": "B",
                "tool_call": {"tool": "idb", "args": {"action": "overview"}},
            }
        )
        assert submitted.get("error") is not True
        server._batch_manager.wait(submitted["task_id"], timeout=5)
        assert server.current_session.session_id == "A"
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_bg_wait_rejects_non_numeric_timeout(tmp_path, monkeypatch):
    """A non-numeric timeout must produce an error envelope, not a ValueError."""
    server = _init_background_server(tmp_path, monkeypatch)
    token = server._begin_client_connection()
    try:
        state = server._client_request_state()
        state.owned_session_ids.add("SID_TEST")
        task_id = server._batch_manager.submit(
            "tool_call", {"x": 1}, session_id="SID_TEST", run_fn=lambda task: {"ok": True}
        )
        server._batch_manager.wait(task_id, timeout=5)
        bad = server._bg_wait({"task_id": task_id, "timeout": "abc"})
        assert bad.get("error") is True
        assert bad.get("code") == MCPError.INVALID_ARGS
        good = server._bg_wait({"task_id": task_id, "timeout": "2"})
        assert good.get("error") is not True
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# Semantic index scope validation
# ---------------------------------------------------------------------------

class _SessionManager:
    def __init__(self, session):
        self.sessions = [session]

    def discover_sessions(self):
        return list(self.sessions)


class _IndexHarness(BackgroundMixin):
    def __init__(self, session):
        self.session_mgr = _SessionManager(session)
        self._batch_mgr = BatchManager(max_workers=1)
        self._client_request_state().owned_session_ids.add(str(session.session_id))

    def _resolve_session_from_idb_ref(self, ref):
        return next(
            (
                s
                for s in self.session_mgr.sessions
                if ref in {s.session_id, s.idb_path, s.binary_path}
            ),
            None,
        )

    def call_tool(self, tool, idb_path, **args):
        return {
            "ok": True,
            "indexed": 0,
            "attempted": 0,
            "failed": 0,
            "eligible": 0,
            "complete": True,
            "next_cursor": None,
            "index": {},
            "input": {},
        }


def test_semantic_index_rejects_non_numeric_total_limit(tmp_path, monkeypatch):
    """_index_total_limit is coerced with int(); it must be validated before
    that coercion so a non-numeric value returns an error envelope."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path / "batch"))
    session = SimpleNamespace(
        session_id="AAAAAAAA",
        binary_path=str(tmp_path / "a.bin"),
        idb_path=str(tmp_path / "SID_AAAAAAAA.a.i64"),
        analysis_options={},
    )
    harness = _IndexHarness(session)
    try:
        result = harness._submit_semantic_index(
            {
                "action": "index_fast",
                "mode": "fast",
                "_background": True,
                "_index_total_limit": "abc",
            },
            session.session_id,
        )
        assert result.get("error") is True
        assert result.get("code") == MCPError.INVALID_ARGS
    finally:
        harness._batch_mgr.shutdown()


def test_semantic_index_job_state_annotation_resolves():
    """_semantic_index_job_state's return annotation must be a valid generic.
    threading.RLock is a factory function (not a class) on CPython 3.14+, so
    using it inside tuple[...] makes typing.get_type_hints raise TypeError."""
    hints = typing.get_type_hints(BackgroundMixin._semantic_index_job_state)
    assert "dict" in str(hints["return"])
