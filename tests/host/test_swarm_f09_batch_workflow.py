"""Regression tests for package f09_batch_workflow.

Covers the audit findings:
- security/high: background(submit) must not grant worker ownership of a
  session the caller never adopted (a foreign-locked session is rejected).
- correctness/medium: compose annotation keys (sources/source_count/index)
  must not leak into step arguments through _normalize_batch_call.
- correctness/medium: compose dedup must key on tool+action+arguments so
  distinct steps sharing tool+action are preserved.
- race/medium: lazy background-state lock initialisation must be race-safe
  (one lock per server instance, even under concurrent submit threads).
- correctness/low: _handle_batch coerces continue_on_error with _coerce_bool.
- resource_leak/low: background.wait caps unbounded/huge timeouts.
- error_handling/low: background preflight uses the resolved policy mode.
- clarity/low: _handle_background lowercases the action.
- resource_leak/low: completed semantic-index jobs are dropped from the
  active-job map.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import ida_pro_mcp.host.server.server_batch as sb_module
from ida_pro_mcp.host.batch_manager import BatchManager
from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_batch import BackgroundMixin
from ida_pro_mcp.host.server.server_workflow_batch import (
    _NON_ARG_ANNOTATION_KEYS,
    ServerWorkflowBatchMixin,
)


def _make_server(tmp_path, monkeypatch):
    """A live-free IDAMCPServer with IDA discovery stubbed out."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path / "batch"))
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server._ensure_runtime_and_idb = lambda session: None
    # This helper never spawns real runtimes; a populated session_runtimes map
    # (used to simulate a foreign-locked session) must not be torn down.
    server._cleanup_runtime = lambda sid: None
    return server


def _workflow_execute(tool, args, seen):
    """Stub _execute_tool that records args and returns plan-friendly shapes."""
    seen.append((tool, dict(args)))
    if tool == "idb" and args.get("action") == "overview":
        return {"ok": True, "architecture_profile": {}, "file_type_effective": "elf"}
    if tool == "idb" and args.get("action") == "summary":
        return {"ok": True, "functions": 0, "imports": 0}
    return {"ok": True, "tool": tool}


# ---------------------------------------------------------------------------
# security/high — background(submit) ownership
# ---------------------------------------------------------------------------


def test_bg_submit_rejects_foreign_locked_session(tmp_path, monkeypatch):
    """A caller must not be able to queue background tool calls against a
    session locked by another connection (incl. misc.python)."""
    sessions = {
        "A": SimpleNamespace(
            session_id="A", idb_path=str(tmp_path / "SID_A.i64"),
            binary_path=str(tmp_path / "a.bin"), analysis_options={},
        ),
        "B": SimpleNamespace(
            session_id="B", idb_path=str(tmp_path / "SID_B.i64"),
            binary_path=str(tmp_path / "b.bin"), analysis_options={},
        ),
    }
    server = _make_server(tmp_path, monkeypatch)
    server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
    server.session_mgr = SimpleNamespace(
        get_session=lambda sid: sessions.get(str(sid))
    )
    token = server._begin_client_connection()
    try:
        server.current_session = sessions["A"]  # client owns A only
        # B is actively run by another connection: locked.
        server.session_runtimes = {"B": {"process": object()}}
        server._runtime_alive = lambda rec: True

        submitted = server._bg_submit(
            {
                "session_id": "B",
                "tool_call": {
                    "tool": "misc",
                    "args": {"action": "python", "code": "1", "_risk_ack": True},
                },
            }
        )
        assert submitted.get("error") is True
        assert submitted.get("code") == MCPError.FILE_LOCKED
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_bg_submit_allows_owned_or_adoptable_session(tmp_path, monkeypatch):
    """The ownership gate still permits the caller's own session and an
    unleased session (adoption), so the documented flow keeps working."""
    sessions = {
        "A": SimpleNamespace(
            session_id="A", idb_path=str(tmp_path / "SID_A.i64"),
            binary_path=str(tmp_path / "a.bin"), analysis_options={},
        ),
        "B": SimpleNamespace(
            session_id="B", idb_path=str(tmp_path / "SID_B.i64"),
            binary_path=str(tmp_path / "b.bin"), analysis_options={},
        ),
    }
    server = _make_server(tmp_path, monkeypatch)
    server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
    server.session_mgr = SimpleNamespace(
        get_session=lambda sid: sessions.get(str(sid))
    )
    token = server._begin_client_connection()
    try:
        state = server._client_request_state()
        state.owned_session_ids.add("A")
        server.current_session = sessions["A"]
        server.session_runtimes = {}  # nothing locked

        # Owned session explicit id: allowed.
        owned = server._bg_submit(
            {"session_id": "A", "tool_call": {"tool": "idb", "args": {"action": "overview"}}}
        )
        assert owned.get("error") is not True
        server._batch_manager.wait(owned["task_id"], timeout=5)

        # No session_id -> resolves from current_session (owned): allowed.
        implicit = server._bg_submit(
            {"tool_call": {"tool": "idb", "args": {"action": "overview"}}}
        )
        assert implicit.get("error") is not True
        server._batch_manager.wait(implicit["task_id"], timeout=5)

        # Unleased foreign session -> adoptable, allowed, ownership recorded.
        adopted = server._bg_submit(
            {"session_id": "B", "tool_call": {"tool": "idb", "args": {"action": "overview"}}}
        )
        assert adopted.get("error") is not True
        server._batch_manager.wait(adopted["task_id"], timeout=5)
        assert "B" in state.owned_session_ids
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_bg_submit_unknown_session_is_rejected(tmp_path, monkeypatch):
    """An explicit session_id that does not exist must fail, not silently
    fall back to the caller's current session."""
    sessions = {
        "A": SimpleNamespace(
            session_id="A", idb_path=str(tmp_path / "SID_A.i64"),
            binary_path=str(tmp_path / "a.bin"), analysis_options={},
        ),
    }
    server = _make_server(tmp_path, monkeypatch)
    server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
    server.session_mgr = SimpleNamespace(
        get_session=lambda sid: sessions.get(str(sid))
    )
    token = server._begin_client_connection()
    try:
        server.current_session = sessions["A"]
        submitted = server._bg_submit(
            {"session_id": "NOPE", "tool_call": {"tool": "idb", "args": {"action": "overview"}}}
        )
        assert submitted.get("error") is True
        assert submitted.get("code") == MCPError.FILE_NOT_FOUND
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# correctness/medium — compose annotations must not leak into step args
# ---------------------------------------------------------------------------


def test_normalize_batch_call_strips_compose_annotations():
    """sources/source_count/index (and prioritize annotations) are metadata,
    never tool arguments: they must not be merged into call_args."""
    mixin = ServerWorkflowBatchMixin()
    for extra_key in ("sources", "source_count", "index", "priority_index", "priority_mode"):
        name, call_args, err = mixin._normalize_batch_call(
            {
                "name": "search",
                "arguments": {"action": "find", "query": "http"},
                extra_key: "x",
            },
            0,
        )
        assert err is None
        assert name == "search"
        assert extra_key not in call_args, extra_key
        assert call_args == {"action": "find", "query": "http"}
    assert "sources" in _NON_ARG_ANNOTATION_KEYS


def test_compose_to_execute_plan_steps_do_not_carry_annotations(tmp_path, monkeypatch):
    """The documented compose -> execute_plan flow must run every step with
    clean args (no sources/source_count/index), so RPC admission passes."""
    server = _make_server(tmp_path, monkeypatch)
    seen: list[tuple[str, dict]] = []

    def fake_execute(tool, args):
        seen.append((tool, dict(args)))
        return _workflow_execute(tool, args, seen)

    server._execute_tool = fake_execute
    try:
        result = server._handle_workflow(
            {"action": "execute_plan", "workflow_actions": ["triage_fast"]}
        )
        assert result.get("ok") is True, result
        assert result["source"] == "compose"
        for step in result["step_results"]:
            assert step["outcome"] == "ok", step
        assert seen, "execute_plan should have executed steps"
        for tool, args in seen:
            assert "sources" not in args, (tool, args)
            assert "source_count" not in args, (tool, args)
            assert "index" not in args, (tool, args)
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# correctness/medium — compose dedup must not drop distinct steps
# ---------------------------------------------------------------------------


def test_compose_preserves_distinct_steps_sharing_tool_action(tmp_path, monkeypatch):
    """Dedup keys on tool+action+arguments, so two search.find steps with
    different queries survive composition instead of collapsing to the first."""
    server = _make_server(tmp_path, monkeypatch)
    seen: list[tuple[str, dict]] = []
    server._execute_tool = lambda tool, args: _workflow_execute(tool, args, seen)
    try:
        result = server._handle_workflow(
            {"action": "compose", "workflow_actions": ["triage_fast", "malware_deep"]}
        )
        assert result.get("ok") is True, result
        assert result["dedup_enabled"] is True
        planned = result["planned_calls"]
        find_steps = [
            c for c in planned
            if c.get("name") == "search"
            and (c.get("arguments") or {}).get("action") == "find"
        ]
        queries = {(c.get("arguments") or {}).get("query") for c in find_steps}
        assert len(find_steps) == 3, [c.get("arguments") for c in find_steps]
        assert queries == {
            "entrypoint parser auth decode crypto",
            "http url ip address",
            "GetProcAddress CreateThread VirtualAlloc",
        }
        # Sources attribution stays correct per distinct step.
        by_query = {
            (c.get("arguments") or {}).get("query"): c.get("sources") for c in find_steps
        }
        assert by_query["GetProcAddress CreateThread VirtualAlloc"] == ["malware_deep"]
        assert by_query["http url ip address"] == ["triage_fast"]
        # Exact duplicate calls (same tool+action+args) still dedup: no two
        # planned calls may share the same name/action/argument content.
        all_steps = {
            (
                c.get("name"),
                (c.get("arguments") or {}).get("action"),
                tuple(sorted((c.get("arguments") or {}).items())),
            )
            for c in planned
        }
        assert len(planned) == len(all_steps), "no exact-duplicate steps kept"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# race/medium — lazy lock initialisation
# ---------------------------------------------------------------------------


class _IndexHarness(BackgroundMixin):
    """Minimal BackgroundMixin with a real BatchManager, like the server."""

    def __init__(self, session, tmp_path, monkeypatch):
        super().__init__()
        self.session_mgr = SimpleNamespace(
            sessions=[session],
            discover_sessions=lambda: [session],
            get_session=lambda sid: session if str(sid) == str(session.session_id) else None,
        )
        self._batch_mgr = BatchManager(max_workers=1)
        self._client_request_state().owned_session_ids.add(str(session.session_id))
        # The server mixin implementing this is not part of the harness.
        self._update_session_indexing_metadata = lambda *a, **k: None

    def _resolve_session_from_idb_ref(self, ref):
        session = self.session_mgr.sessions[0]
        return session if ref in {session.session_id, session.idb_path, session.binary_path} else None

    def call_tool(self, tool, idb_path, **args):
        return {
            "ok": True, "indexed": 0, "attempted": 0, "failed": 0,
            "eligible": 0, "complete": True, "next_cursor": None,
            "index": {}, "input": {},
        }

    def shutdown(self):
        self._batch_mgr.shutdown()


def test_semantic_index_lazy_state_uses_single_lock(tmp_path, monkeypatch):
    """_semantic_index_job_state must converge on one lock and one dict even
    when several threads initialise it concurrently (no two-RLock race)."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path / "batch"))
    session = SimpleNamespace(
        session_id="AAAAAAAA", binary_path=str(tmp_path / "a.bin"),
        idb_path=str(tmp_path / "SID_AAAAAAAA.a.i64"), analysis_options={},
    )
    harness = _IndexHarness(session, tmp_path, monkeypatch)
    try:
        lock_a, active_a = harness._semantic_index_job_state()
        lock_b, active_b = harness._semantic_index_job_state()
        assert lock_a is lock_b
        assert active_a is active_b

        # Force re-initialisation under concurrent access: all threads must
        # converge on the same lock and the same shared dict.
        harness._semantic_index_jobs_lock = None
        harness._semantic_index_tasks = None
        barrier = threading.Barrier(16)
        results: list[tuple] = []

        def worker():
            barrier.wait()
            results.append(harness._semantic_index_job_state())

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len({id(lock) for lock, _ in results}) == 1
        assert len({id(active) for _, active in results}) == 1
    finally:
        harness.shutdown()


# ---------------------------------------------------------------------------
# resource_leak/low — background.wait timeout cap
# ---------------------------------------------------------------------------


def test_bg_wait_caps_unbounded_and_huge_timeouts(tmp_path, monkeypatch):
    """None (wait forever) and huge timeouts must be capped so a stuck worker
    cannot park the request thread indefinitely."""
    monkeypatch.setattr(sb_module, "_BG_WAIT_MAX_SECONDS", 0.1)
    server = _make_server(tmp_path, monkeypatch)
    block = threading.Event()
    server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
    token = server._begin_client_connection()
    try:
        state = server._client_request_state()
        state.owned_session_ids.add("SID_T1")
        task_id = server._batch_manager.submit(
            "tool_call", {"x": 1}, session_id="SID_T1", run_fn=lambda task: block.wait(3) or {"ok": True}
        )
        start = time.time()
        huge = server._bg_wait({"task_id": task_id, "timeout": 99999})
        assert huge.get("error") is not True
        assert (time.time() - start) < 2, "huge timeout must be capped"
        assert huge["state"] == "running"

        start = time.time()
        implicit = server._bg_wait({"task_id": task_id})
        assert implicit.get("error") is not True
        assert (time.time() - start) < 2, "None timeout must be capped"
        assert implicit["state"] == "running"
    finally:
        block.set()
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# correctness/low — _handle_batch continue_on_error coercion
# ---------------------------------------------------------------------------


def test_handle_batch_coerces_continue_on_error_string(tmp_path, monkeypatch):
    """continue_on_error='false' (JSON string) must mean stop-on-error."""
    server = _make_server(tmp_path, monkeypatch)
    calls: list[str] = []

    def fake_execute(tool, args):
        calls.append(tool)
        if tool == "data":
            return {"error": True, "code": MCPError.INVALID_ARGS, "category": "user",
                    "message": "nope", "recoverable": False}
        return {"ok": True}

    server._execute_tool = fake_execute
    try:
        result = server._handle_batch(
            {
                "calls": [
                    {"name": "data", "arguments": {"action": "functions"}},
                    {"name": "idb", "arguments": {"action": "overview"}},
                ],
                "continue_on_error": "false",
            }
        )
        assert calls == ["data"], "string 'false' must stop on the first error"
        assert result["summary"]["errors"] == 1
        assert result["summary"]["stopped_on_error"] is True
        calls.clear()

        result = server._handle_batch(
            {
                "calls": [
                    {"name": "data", "arguments": {"action": "functions"}},
                    {"name": "idb", "arguments": {"action": "overview"}},
                ],
                "continue_on_error": "true",
            }
        )
        assert calls == ["data", "idb"], "string 'true' must continue after an error"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# error_handling/low — background preflight uses resolved policy mode
# ---------------------------------------------------------------------------


def test_bg_submit_preflight_uses_resolved_permissive_mode(tmp_path, monkeypatch):
    """In a permissive deployment a background WRITE submission without ack
    must be accepted at preflight, matching the synchronous WARN path."""
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "permissive")
    try:
        sessions = {
            "A": SimpleNamespace(
                session_id="A", idb_path=str(tmp_path / "SID_A.i64"),
                binary_path=str(tmp_path / "a.bin"), analysis_options={},
            ),
        }
        server = _make_server(tmp_path, monkeypatch)
        server._execute_tool = lambda tool, args: {"ok": True, "tool": tool}
        server.session_mgr = SimpleNamespace(
            get_session=lambda sid: sessions.get(str(sid))
        )
        token = server._begin_client_connection()
        try:
            server.current_session = sessions["A"]
            submitted = server._bg_submit(
                {
                    "tool_call": {
                        "tool": "modify",
                        "args": {"action": "rename", "addr": "0x1000", "name": "foo"},
                    }
                }
            )
            assert submitted.get("error") is not True, submitted
            server._batch_manager.wait(submitted["task_id"], timeout=5)
        finally:
            server._end_client_connection(token)
            server.shutdown()
    finally:
        monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)


# ---------------------------------------------------------------------------
# clarity/low — _handle_background lowercases action
# ---------------------------------------------------------------------------


def test_handle_background_lowercases_action(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    token = server._begin_client_connection()
    try:
        result = server._handle_background({"action": "Status"})
        assert result.get("error") is not True, result
        assert "tasks" in result

        bogus = server._handle_background({"action": "Bogus"})
        assert bogus.get("error") is True
        assert bogus.get("code") == MCPError.INVALID_ARGS
    finally:
        server._end_client_connection(token)
        server.shutdown()


# ---------------------------------------------------------------------------
# resource_leak/low — completed semantic-index jobs leave the active map
# ---------------------------------------------------------------------------


def test_semantic_index_active_entry_popped_on_completion(tmp_path, monkeypatch):
    """A finished/cancelled/failed semantic-index job must be removed from
    _semantic_index_tasks so the server does not retain its BatchTask/Future."""
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path / "batch"))
    session = SimpleNamespace(
        session_id="AAAAAAAA", binary_path=str(tmp_path / "a.bin"),
        idb_path=str(tmp_path / "SID_AAAAAAAA.a.i64"), analysis_options={},
    )
    harness = _IndexHarness(session, tmp_path, monkeypatch)
    try:
        result = harness._submit_semantic_index(
            {"action": "index_fast", "mode": "fast", "_background": True, "limit": 2},
            session.session_id,
        )
        assert result.get("ok") is True, result
        task_id = result["task_id"]
        status = harness._batch_manager.wait(task_id, timeout=10)
        assert status["state"] == "done"
        assert harness._semantic_index_tasks.get(session.session_id) is None

        # The dedup no longer blocks a fresh submit once the job completed.
        again = harness._submit_semantic_index(
            {"action": "index_fast", "mode": "fast", "_background": True, "limit": 2},
            session.session_id,
        )
        assert again.get("ok") is True
        assert again["task_id"] != task_id
        assert again.get("reused") is not True
        harness._batch_manager.wait(again["task_id"], timeout=10)
        assert harness._semantic_index_tasks.get(session.session_id) is None
    finally:
        harness.shutdown()
