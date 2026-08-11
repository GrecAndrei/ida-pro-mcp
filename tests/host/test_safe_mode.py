"""Safe mode: gate + auto-background + analysis-completion lifecycle.

Safe mode activates whenever a session's IDA auto-analysis is still
completing (every open/rebuild that leaves analysis incomplete). While
active, full-binary analysis, decompile-everything indexing, and arbitrary
script execution are blocked with SAFE_MODE; manual small-area operations
stay available. It lifts only when a live runtime confirms
analysis_complete, and the next response for the session carries a one-shot
'analysis complete / safe mode lifted' warning.

Escape-vector regression tests: re-opening the same binary (reuse or
force_new), killing the runtime mid-build, and rebuilding the IDB must all
keep the gate on — none of them may silently lift safe mode.
"""

from __future__ import annotations

import threading

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive but cannot be killed."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    # Safe-mode lifecycle is exercised through the background open path here,
    # which is experimental and needs the opt-in flag.
    monkeypatch.setenv("IDA_MCP_BACKGROUND_OPEN", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    srv = IDAMCPServer()
    monkeypatch.setattr(srv, "_ensure_runtime_and_idb", lambda session: None)
    # Fast watcher so completion/interruption tests do not wait 5s.
    srv.safe_mode_poll_seconds = 0.05
    yield srv
    srv.shutdown()


def _open(server, name, arguments, request_id=1):
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]["structuredContent"]


def _open_background_pending(server, binary_path):
    """Open in background and return (session object, response)."""
    result = _open(server, "ida_open_background", {"binary_path": binary_path})
    assert result.get("ok") is True
    sid = result["session_id"]
    assert result.get("safe_mode") is True
    session = server.session_mgr.get_session(sid)
    assert session is not None
    return session, result


def test_safe_mode_gate_blocks_full_binary_operations(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    blocked = [
        ("misc", "python"),           # arbitrary interpreter (ida_python)
        ("misc", "idc"),
        ("misc", "plugin_run"),
        ("analysis", "set_architecture"),
        ("analysis", "set_processor"),
        ("analysis", "reanalyze"),
        ("analysis", "run"),
        ("analysis", "analyze"),
        ("intelligence", "index_fast"),
        ("intelligence", "index_batch"),
        ("intelligence", "semantic_search"),
        ("intelligence", "similar_functions"),
        ("workflow", "execute_plan"),
        ("workflow", "triage_fast"),
        ("symbols", "load_pdb"),
        ("segments", "analyze"),
    ]
    for tool, action in blocked:
        denied = server._safe_mode_gate(sid, tool, action)
        assert denied is not None, f"{tool}/{action} should be blocked"
        assert denied.get("code") == MCPError.SAFE_MODE
        assert denied.get("recoverable") is True


def test_safe_mode_allows_manual_small_area_operations(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    allowed = [
        ("code", "decompile"),          # small-area per-function decompilation
        ("code", "disasm"),
        ("code", "blocks"),
        ("funcs", "list"),
        ("funcs", "info"),
        ("modify", "rename"),           # manual write-back is manual work
        ("modify", "comment"),
        ("search", "find"),
        ("search", "string"),
        ("analysis", "state"),          # needed to poll completion
        ("analysis", "get_options"),
        ("intelligence", "intelligence_status"),
        ("session", "status"),
        ("blackboard", "write"),
        # r2 raw-binary sidecar: subprocess-only, never touches the IDB, so it
        # must stay available while IDA auto-analysis is still running.
        ("r2", "status"),
        ("r2", "bininfo"),
        ("r2", "load_hints"),
        ("r2", "disassemble_hypothesis"),
        ("r2", "vxrefs"),
    ]
    for tool, action in allowed:
        assert server._safe_mode_gate(sid, tool, action) is None, (
            f"{tool}/{action} must stay available in safe mode"
        )


def test_safe_mode_gate_noop_for_completed_sessions(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id
    server._mark_analysis_complete(session)
    assert server._safe_mode_gate(sid, "misc", "python") is None
    assert server._safe_mode_gate(sid, "intelligence", "semantic_search") is None


def test_call_tool_blocks_ida_python_in_safe_mode(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id
    token = server._begin_client_connection()
    try:
        denied = server.call_tool("misc", sid, action="python", code="1")
        assert denied.get("code") == MCPError.SAFE_MODE
    finally:
        server._end_client_connection(token)


def test_reopen_same_binary_keeps_safe_mode(tmp_path, server):
    """Escape vector: re-opening the same binary must not lift the gate."""
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    token = server._begin_client_connection()
    try:
        reopened = _open(
            server, "ida_open_binary", {"binary_path": str(binary)}, request_id=2
        )
    finally:
        server._end_client_connection(token)
    assert reopened.get("ok") is True
    assert reopened["session_id"] == sid  # reused, not a new session
    assert reopened.get("safe_mode") is True
    assert server._safe_mode_active(sid)


def test_force_new_cannot_escape_safe_mode(tmp_path, server):
    """Escape vector: force_new=true yields a fresh session that is ALSO pending."""
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid1 = session.session_id

    token = server._begin_client_connection()
    try:
        forced = _open(
            server,
            "ida_open_binary",
            {"binary_path": str(binary), "force_new": True},
            request_id=2,
        )
    finally:
        server._end_client_connection(token)
    sid2 = forced["session_id"]
    assert sid2 != sid1
    assert forced.get("safe_mode") is True
    assert server._safe_mode_active(sid2)


def test_kill_mid_build_keeps_safe_mode_and_surfaces_error(tmp_path, server):
    """Escape vector: killing the runtime mid-build must not lift the gate."""
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    # The background spawn is stubbed, so simulate the live runtime the
    # watcher would see before the kill. The revamped watcher only flags a
    # "registered-then-dead" runtime once it has OBSERVED the runtime alive, so
    # hold the fake runtime registered long enough for one poll to land.
    server.session_runtimes[sid] = {"process": _FakeIdaProcess()}
    import time

    time.sleep(0.2)
    # session/kill is now classified DESTRUCTIVE (it tears down the runtime),
    # so it requires explicit ack even in the test's policy mode.
    killed = _open(
        server,
        "session",
        {"action": "kill", "session_id": sid, "_risk_ack": True},
        request_id=2,
    )
    assert killed.get("error") is not True

    # The watcher notices the dead runtime and records the interruption
    # while keeping the half-analyzed IDB gated.
    deadline = 3.0
    import time

    t0 = time.monotonic()
    errors = server._background_load_errors
    while time.monotonic() - t0 < deadline and sid not in errors:
        time.sleep(0.02)
    assert sid in errors
    assert "before auto-analysis" in str(errors[sid].get("message") or "")
    assert server._safe_mode_active(sid)

    status = _open(server, "ida_session_status", {}, request_id=2)
    assert status["session"].get("safe_mode") is True
    bg_error = status["session"].get("background_error")
    assert bg_error is not None and bg_error.get("error") is True


def test_rebuild_reenters_safe_mode(tmp_path, server, monkeypatch):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id
    server._mark_analysis_complete(session)
    assert not server._safe_mode_active(sid)

    monkeypatch.setattr(
        server, "_start_server", lambda s: {"ok": True, "current_options": {}}
    )
    token = server._begin_client_connection()
    try:
        rebuilt = server._session_action_rebuild({"session_id": sid})
    finally:
        server._end_client_connection(token)
    assert rebuilt.get("error") is not True
    assert rebuilt.get("safe_mode") is True
    assert server._safe_mode_active(sid)


def test_analysis_completion_lifts_safe_mode_and_fires_notice(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    # Simulate the watcher observing analysis_complete.
    server._on_analysis_complete(session, reload=False)
    assert not server._safe_mode_active(sid)
    assert server._analysis_is_complete(sid)

    # The next response carries the one-shot warning exactly once. It uses the
    # generic completion message: analysis_complete means "confirmed complete
    # at least once", not "currently idle" (idleness is analysis_ready).
    status = _open(server, "ida_session_status", {}, request_id=2)
    warning = status.get("warning")
    assert warning is not None and warning.get("code") == "analysis_complete"
    assert warning.get("message") == "IDA auto-analysis completed."
    assert status["session"].get("safe_mode") is False
    assert status["session"].get("analysis_complete") is True

    second = _open(server, "ida_session_status", {}, request_id=3)
    assert "warning" not in second


def test_status_reports_safe_mode_fields(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    session, _ = _open_background_pending(server, str(binary))
    sid = session.session_id

    status = _open(server, "ida_session_status", {})
    assert status["session"]["session_id"] == sid
    assert status["session"].get("safe_mode") is True
    assert status["session"].get("analysis_complete") is False

    server._on_analysis_complete(session, reload=False)
    status = _open(server, "ida_session_status", {}, request_id=2)
    assert status["session"].get("safe_mode") is False
    assert status["session"].get("analysis_complete") is True


def test_open_response_flags_safe_mode(tmp_path, server):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x00" * 1024)
    result = _open(server, "ida_open_background", {"binary_path": str(binary)})
    assert result.get("safe_mode") is True
    assert result.get("analysis_complete") is False
    assert result.get("background") is True
