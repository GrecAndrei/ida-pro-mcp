"""Public MCP contract tests for concurrent daemon clients."""

from __future__ import annotations

import json
import os
import threading
import time

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer


def _tool_call(server: IDAMCPServer, request_id: int, name: str, arguments: dict) -> dict:
    """Issue one MCP tools/call request and return its structured result."""
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


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive but cannot be killed.

    ``pid`` is above Linux's pid_max, so ``os.killpg`` on it raises
    ProcessLookupError/EINVAL and every kill path is a safe no-op.
    """

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def test_simultaneous_clients_keep_independent_active_sessions(tmp_path, monkeypatch):
    """Each daemon client must keep routing default calls to its own binary."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    # This contract test exercises connection routing only; no IDA process or
    # IDB is needed to prove that each client retains its selected session.
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    barrier = threading.Barrier(2)
    results: dict[str, dict] = {}

    def client(label: str, binary_path: str) -> None:
        init = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": f"concurrent-{label}", "version": "test"},
                },
            }
        )
        assert init is not None and "result" in init
        opened = _tool_call(
            server, 2, "ida_open_binary", {"binary_path": binary_path}
        )
        barrier.wait(timeout=5)
        status = _tool_call(server, 3, "ida_session_status", {})
        results[label] = {"opened": opened, "status": status}

    threads = [
        threading.Thread(target=client, args=("a", str(binary_a))),
        threading.Thread(target=client, args=("b", str(binary_b))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    try:
        opened_a = results["a"]["opened"]
        opened_b = results["b"]["opened"]
        status_a = results["a"]["status"]["session"]
        status_b = results["b"]["status"]["session"]

        assert opened_a["binary_path"] == str(binary_a)
        assert opened_b["binary_path"] == str(binary_b)
        assert opened_a["session_id"] != opened_b["session_id"]
        assert status_a["session_id"] == opened_a["session_id"]
        assert status_b["session_id"] == opened_b["session_id"]
        assert status_a["binary_path"] == str(binary_a)
        assert status_b["binary_path"] == str(binary_b)
    finally:
        server.shutdown()


def test_simultaneous_clients_opening_same_binary_get_separate_sessions(
    tmp_path, monkeypatch
):
    """A session that another client is actively running is never shared."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_path = tmp_path / "shared-input.bin"
    binary_path.write_bytes(b"same immutable input")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    barrier = threading.Barrier(2)
    results: dict[str, dict] = {}

    def client_a() -> None:
        results["a"] = _tool_call(
            server, 1, "ida_open_binary", {"binary_path": str(binary_path)}
        )
        sid_a = results["a"]["session_id"]
        # Client A is actively analyzing: its idat runtime is alive, so a
        # concurrent client must not adopt the session.
        server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}
        barrier.wait(timeout=5)

    def client_b() -> None:
        barrier.wait(timeout=5)
        results["b"] = _tool_call(
            server, 2, "ida_open_binary", {"binary_path": str(binary_path)}
        )

    threads = [
        threading.Thread(target=client_a),
        threading.Thread(target=client_b),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    try:
        session_a = results["a"]
        session_b = results["b"]
        assert session_a["binary_path"] == str(binary_path)
        assert session_b["binary_path"] == str(binary_path)
        assert session_a["session_id"] != session_b["session_id"]
        assert session_a["idb_path"] != session_b["idb_path"]
    finally:
        server.shutdown()


def test_idle_daemon_connection_is_not_closed_on_receive_timeout(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    class IdleThenClosedConnection:
        def __init__(self):
            self.recv_count = 0
            self.closed = False

        def settimeout(self, timeout):
            self.timeout = timeout

        def recv(self, size):
            self.recv_count += 1
            if self.recv_count == 1:
                raise TimeoutError("idle")
            return b""

        def close(self):
            self.closed = True

    server = IDAMCPServer()
    conn = IdleThenClosedConnection()
    try:
        server._handle_daemon_conn(conn)
        assert conn.recv_count == 2
        assert conn.closed is True
    finally:
        server.shutdown()


def _open_owned_session(server: IDAMCPServer, binary_path: str, request_id: int = 1) -> dict:
    return _tool_call(
        server, request_id, "ida_open_binary", {"binary_path": binary_path}
    )


def test_foreign_idb_argument_cannot_drive_another_clients_session(
    tmp_path, monkeypatch
):
    """Passing another client's idb/session id must not reach call_tool RPC."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    starts: list[str] = []

    def _record_start(session):
        starts.append(session.session_id)
        return {
            "error": True,
            "code": "IDA_CRASHED",
            "message": "start should not run for foreign sessions",
        }

    monkeypatch.setattr(server, "_start_server", _record_start)

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a))
        idb_a = opened_a["idb_path"]
        sid_a = opened_a["session_id"]
    finally:
        server._client_request_state_var.reset(token_a)
    # Client A's idat is still alive and analyzing; the session is busy even
    # though A's connection state is gone, so B must not be able to drive it.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        _open_owned_session(server, str(binary_b))
        denied = server.call_tool("funcs", idb_a, action="list")
        assert denied.get("error") is True
        assert denied.get("code") == "FILE_LOCKED"
        denied_sid = server.call_tool("funcs", sid_a, action="list")
        assert denied_sid.get("error") is True
        assert denied_sid.get("code") == "FILE_LOCKED"
        denied_exec = server._execute_tool("funcs", {"action": "list", "idb": idb_a})
        assert denied_exec.get("error") is True
        assert denied_exec.get("code") == "FILE_LOCKED"
        assert starts == []
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_restarted_client_adopts_disconnected_sessions_and_reuses_idb(
    tmp_path, monkeypatch
):
    """A restarted client reloads its old session instead of creating a new one.

    When a client disconnects, its runtimes are cleaned up. A later client
    (the restarted one) may adopt the recorded session and must keep reusing
    the same IDB — this is what makes analysis survive client restarts.
    """
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_a.write_bytes(b"alpha")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a))
        sid_a = opened_a["session_id"]
        idb_a = opened_a["idb_path"]
    finally:
        server._end_client_connection(token_a)

    token_b = server._begin_client_connection()
    try:
        reopened = _open_owned_session(server, str(binary_a))
        assert reopened.get("ok") is True
        assert reopened["session_id"] == sid_a
        assert reopened["idb_path"] == idb_a
        assert "Reusing" in str(reopened.get("note") or "")
        assert server._client_owns_session(sid_a)
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_foreign_client_cannot_close_or_kill_peer_session(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a))
        sid_a = opened_a["session_id"]
    finally:
        # Keep runtime metadata around; disconnect cleanup would remove it.
        # For this test we only need the session row to remain.
        server._client_request_state_var.reset(token_a)
    # A is still actively analyzing the session: it must stay protected.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        _open_owned_session(server, str(binary_b))
        denied_close = server._session_action_close({"session_id": sid_a})
        assert denied_close.get("error") is True
        assert denied_close.get("code") == "FILE_LOCKED"
        denied_kill = server._session_action_kill({"session_id": sid_a})
        assert denied_kill.get("error") is True
        assert denied_kill.get("code") == "FILE_LOCKED"
        assert server.session_mgr.get_session(sid_a) is not None
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_background_index_worker_retains_session_ownership(
    tmp_path, monkeypatch
):
    """ThreadPool workers must still pass call_tool ownership after submit."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    calls: list[str] = []

    def _fake_call_tool(tool_name, idb_path, **kwargs):
        # Exercise the real ownership gate before recording success.
        session = server._resolve_session_from_idb_ref(idb_path)
        assert session is not None
        denied = server._ensure_client_owns_session(session)
        assert denied is None, denied
        calls.append(tool_name)
        return {
            "ok": True,
            "indexed": 1,
            "attempted": 1,
            "failed": 0,
            "eligible": 1,
            "complete": True,
            "next_cursor": None,
            "index": {"size": 1},
        }

    monkeypatch.setattr(server, "call_tool", _fake_call_tool)

    token = server._begin_client_connection()
    try:
        opened = _open_owned_session(server, str(binary))
        submitted = server._submit_semantic_index(
            {
                "action": "index_fast",
                "mode": "fast",
                "_background": True,
                "_index_slice_size": 1,
            },
            opened["idb_path"],
        )
        assert submitted.get("error") is not True
        result = server._batch_manager.wait(submitted["task_id"], timeout=5)
        assert result["state"] == "done", result
        assert calls == ["intelligence"]
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_session_switch_cannot_claim_another_clients_session(
    tmp_path, monkeypatch
):
    """switch must not grant ownership of a peer client's session."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a))
        sid_a = opened_a["session_id"]
        path_a = opened_a["binary_path"]
    finally:
        server._client_request_state_var.reset(token_a)
    # A's session is actively running, so B cannot claim it.
    server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}

    token_b = server._begin_client_connection()
    try:
        opened_b = _open_owned_session(server, str(binary_b))
        sid_b = opened_b["session_id"]
        denied = server._session_action_switch({"session_id": sid_a})
        assert denied.get("error") is True
        assert denied.get("code") == "FILE_LOCKED"
        denied_path = server._session_action_switch({"binary_path": path_a})
        assert denied_path.get("error") is True
        assert denied_path.get("code") in {"FILE_LOCKED", "INVALID_ARGS", "SESSION_NOT_FOUND"}
        # Stay on B's session.
        assert server.current_session.session_id == sid_b
        assert not server._client_owns_session(sid_a)
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_index_status_and_cancel_are_scoped_to_owning_client(
    tmp_path, monkeypatch
):
    """Unscoped status must not list peer jobs; cancel must not stop them."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token_a = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a))
        sid_a = opened_a["session_id"]
        task_a = server._batch_manager.submit(
            action="semantic_index",
            args={"mode": "fast"},
            session_id=sid_a,
            run_fn=lambda task: {"ok": True},
        )
    finally:
        server._client_request_state_var.reset(token_a)

    token_b = server._begin_client_connection()
    try:
        opened_b = _open_owned_session(server, str(binary_b))
        sid_b = opened_b["session_id"]
        task_b = server._batch_manager.submit(
            action="semantic_index",
            args={"mode": "fast"},
            session_id=sid_b,
            run_fn=lambda task: {"ok": True},
        )

        listed = server._bg_status({})
        listed_ids = {t["task_id"] for t in listed["tasks"]}
        assert task_b in listed_ids
        assert task_a not in listed_ids

        foreign = server._bg_status({"task_id": task_a})
        assert foreign.get("error") is True
        assert foreign.get("code") == "NOT_FOUND"

        cancel = server._bg_cancel({"task_id": task_a})
        assert cancel.get("error") is True
        assert cancel.get("code") == "NOT_FOUND"
        leftover = server._batch_manager.status(task_a)
        assert leftover and leftover[0]["state"] in {"pending", "running", "done"}
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_status_and_state_can_target_a_specific_session_explicitly(
    tmp_path, monkeypatch
):
    """Several agents share one MCP connection; status must be steerable at
    a named session instead of always reporting whoever opened last.

    MCP carries no per-agent identity (subagents multiplex over one
    connection), so the connection-wide active session is a shared default.
    Passing idb/session_id lets each agent poll — and steer toward — its own
    session.
    """
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a), request_id=1)
        opened_b = _open_owned_session(server, str(binary_b), request_id=2)
        sid_a = opened_a["session_id"]
        sid_b = opened_b["session_id"]

        # Unscoped status reports whoever opened last (the shared active).
        active = _tool_call(server, 3, "ida_session_status", {})
        assert active["session"]["session_id"] == sid_b

        # Explicit idb steers status at session A — and makes it active.
        targeted = _tool_call(server, 4, "ida_session_status", {"idb": sid_a})
        assert targeted["session"]["session_id"] == sid_a
        assert server.current_session.session_id == sid_a

        # Explicit session_id-style targeting works via the idb argument.
        again = _tool_call(server, 5, "ida_session_status", {"idb": sid_b})
        assert again["session"]["session_id"] == sid_b
        assert server.current_session.session_id == sid_b

        # State routing follows the same explicit target (side effect:
        # connection active session becomes the named one).
        state = _tool_call(server, 6, "ida_session_state", {"idb": sid_a})
        assert isinstance(state, dict)
        assert server.current_session.session_id == sid_a

        # A foreign session id is rejected by the ownership guard when the
        # owning session's runtime is live.
        token_peer = server._begin_client_connection()
        try:
            _open_owned_session(server, str(binary_b), request_id=7)
            server.session_runtimes[sid_a] = {"process": _FakeIdaProcess()}
            denied = server._handle_session({"action": "status", "idb": sid_a})
            assert denied.get("error") is True
            assert denied.get("code") in {"FILE_LOCKED", "INVALID_ARGS"}
        finally:
            server._end_client_connection(token_peer)
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_python_targets_a_specific_session_explicitly(tmp_path, monkeypatch):
    """ida_python must execute in the session named by idb, not the shared
    active one, when several agents multiplex one MCP connection."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    routed: list[str] = []

    def _record_call_tool(tool_name, idb_path, **kwargs):
        # No live runtime in this contract test; capture the session that
        # python would have run inside, then stop short of an RPC attempt.
        routed.append(idb_path)
        return {
            "error": True,
            "code": "IDA_CRASHED",
            "message": "no live runtime in contract test",
        }

    monkeypatch.setattr(server, "call_tool", _record_call_tool)

    token = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a), request_id=1)
        opened_b = _open_owned_session(server, str(binary_b), request_id=2)
        sid_a = opened_a["session_id"]
        sid_b = opened_b["session_id"]
        # Background-opened sessions are in safe mode; lift it for both so
        # python is allowed once targeting works.
        server._mark_analysis_complete(server._resolve_session_from_idb_ref(sid_a))
        server._mark_analysis_complete(server._resolve_session_from_idb_ref(sid_b))

        # Unscoped python routes to whoever opened last (the shared active).
        _tool_call(server, 3, "ida_python", {"code": "1", "risk_ack": True})
        assert server.current_session.session_id == sid_b
        assert routed[-1] == server.current_session.idb_path

        # Explicit idb steers python at session A even though B is active.
        _tool_call(
            server,
            4,
            "ida_python",
            {"code": "1", "risk_ack": True, "idb": sid_a},
        )
        assert routed[-1] == sid_a

        # session_id-style targeting works through the same idb argument.
        _tool_call(
            server,
            5,
            "ida_python",
            {"code": "1", "risk_ack": True, "idb": sid_b},
        )
        assert routed[-1] == sid_b

        # Safe mode gates on the *target*, not the shared active default: with
        # the active session B back in safe mode, python still runs against the
        # completed session A, and is blocked when aimed back at pending B.
        server._pending_analysis.add(sid_b)
        blocked = _tool_call(
            server, 6, "ida_python", {"code": "1", "risk_ack": True}
        )
        assert blocked.get("code") == MCPError.SAFE_MODE
        assert routed[-1] == sid_b  # blocked before routing; list unchanged

        _tool_call(
            server,
            7,
            "ida_python",
            {"code": "1", "risk_ack": True, "idb": sid_a},
        )
        assert routed[-1] == sid_a

        denied = _tool_call(
            server,
            8,
            "ida_python",
            {"code": "1", "risk_ack": True, "idb": sid_b},
        )
        assert denied.get("code") == MCPError.SAFE_MODE
        assert routed[-1] == sid_a  # target blocked; no routing happened
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_python_response_stamps_the_session_it_executed_in(tmp_path, monkeypatch):
    """ida_python responses must self-identify the session (and image base)
    they actually ran in, so a call aimed at the wrong session on a shared
    connection is visible instead of silently returning foreign addresses."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_b = tmp_path / "bravo.bin"
    binary_a.write_bytes(b"alpha")
    binary_b.write_bytes(b"bravo")

    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened_a = _open_owned_session(server, str(binary_a), request_id=1)
        opened_b = _open_owned_session(server, str(binary_b), request_id=2)
        sid_a = opened_a["session_id"]
        sid_b = opened_b["session_id"]
        server._mark_analysis_complete(server._resolve_session_from_idb_ref(sid_a))
        server._mark_analysis_complete(server._resolve_session_from_idb_ref(sid_b))

        # Give both sessions a live runtime with a distinct known image base so
        # call_tool runs its full path (and the stamp resolves a real base
        # from the runtime cache instead of a live RPC).
        for sid, base in ((sid_a, 0xC000), (sid_b, 0x8000)):
            server.session_runtimes[sid] = {
                "process": _FakeIdaProcess(),
                "port": 9999,
                "auth_token": "t",
                "imagebase": base,
            }

        def _fake_send(payload, port, **kwargs):
            return {"output": "ran\n", "result": None}

        monkeypatch.setattr(server, "_send_rpc_with_retry", _fake_send)

        # Unscoped python runs in the shared active (B, base 0x8000) — the
        # stamp must say so, making that default visible.
        res = _tool_call(server, 3, "ida_python", {"code": "1", "risk_ack": True})
        assert res["_executed_in"]["session_id"] == sid_b
        assert res["_executed_in"]["image_base"] == "0x8000"
        assert res["_executed_in"]["idb_path"] == server.current_session.idb_path

        # Targeted python runs in A (base 0xc000) — the stamp must say so.
        res = _tool_call(
            server,
            4,
            "ida_python",
            {"code": "1", "risk_ack": True, "idb": sid_a},
        )
        assert res["_executed_in"]["session_id"] == sid_a
        assert res["_executed_in"]["image_base"] == "0xc000"
        assert res["_executed_in"]["idb_path"] != server.current_session.idb_path
    finally:
        server._end_client_connection(token)
        server.shutdown()


def test_file_locked_reports_foreign_lease_owner(tmp_path, monkeypatch):
    """FILE_LOCKED must say who holds a foreign-lease session, not just that
    it is busy — the opaque error was the whole point of the complaint."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_a.write_bytes(b"alpha")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened = _open_owned_session(server, str(binary_a))
        sid = opened["session_id"]
    finally:
        server._client_request_state_var.reset(token)

    # A live foreign owner holds a lease for this session (no local runtime).
    lease = {
        "session_id": sid,
        "pid": 424242,
        "owner_pid": 424243,
        "owner_id": "SID_FOREIGN",
        "updated_at": time.time(),
    }
    os.makedirs(server._runtime_lease_dir, exist_ok=True)
    lease_path = server._runtime_lease_path(sid)
    with open(lease_path, "w", encoding="utf-8") as f:
        json.dump(lease, f)
    monkeypatch.setattr(
        IDAMCPServer, "_lease_has_live_foreign_owner", staticmethod(lambda lease: True)
    )

    report = server._session_ownership_report(sid)
    assert report["locked"] is True
    assert report["holder"] == "foreign-lease"
    assert report["owner_id"] == "SID_FOREIGN"
    assert report["owner_pid"] == 424243
    assert report["idat_pid"] == 424242

    # The error surfaced to a caller must carry the same forensics.
    session = server.session_mgr.get_session(sid)
    error = server._ensure_client_owns_session(session)
    assert error is not None
    assert error.get("code") == "FILE_LOCKED"
    assert error["details"]["holder"] == "foreign-lease"
    assert error["details"]["owner_id"] == "SID_FOREIGN"
    assert error["details"]["owner_pid"] == 424243
    assert "424243" in error["hint"]
    server.shutdown()


def test_stale_lease_with_dead_owner_is_reclaimable(tmp_path, monkeypatch):
    """A lease whose owner process is gone must NOT be reported locked."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_a.write_bytes(b"alpha")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened = _open_owned_session(server, str(binary_a))
        sid = opened["session_id"]
    finally:
        server._client_request_state_var.reset(token)

    lease = {
        "session_id": sid,
        "pid": 424242,
        "owner_pid": 999999999,  # certainly dead
        "owner_id": "SID_DEAD",
        "updated_at": time.time(),
    }
    os.makedirs(server._runtime_lease_dir, exist_ok=True)
    with open(server._runtime_lease_path(sid), "w", encoding="utf-8") as f:
        json.dump(lease, f)

    report = server._session_ownership_report(sid)
    assert report["locked"] is False
    assert report["holder"] is None
    assert report["owner_alive"] is False
    assert report["owner_pid"] == 999999999
    server.shutdown()


def test_file_locked_reports_local_runtime_holder(tmp_path, monkeypatch):
    """A session busy because a live local runtime owns it must say so."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_a.write_bytes(b"alpha")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened = _open_owned_session(server, str(binary_a))
        sid = opened["session_id"]
    finally:
        server._client_request_state_var.reset(token)

    # A live runtime in THIS host holds the session — the holder is the
    # daemon itself, not a foreign lease.
    server.session_runtimes[sid] = {"process": _FakeIdaProcess()}
    report = server._session_ownership_report(sid)
    assert report["locked"] is True
    assert report["holder"] == "this-host-runtime"
    assert report["owner_pid"] == os.getpid()
    assert report["owner_alive"] is True

    session = server.session_mgr.get_session(sid)
    error = server._ensure_client_owns_session(session)
    assert error is not None
    assert error.get("code") == "FILE_LOCKED"
    assert error["details"]["holder"] == "this-host-runtime"
    server.shutdown()


def test_session_list_and_state_expose_ownership(tmp_path, monkeypatch):
    """session list/state must mark locked sessions with who holds them."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    binary_a = tmp_path / "alpha.bin"
    binary_a.write_bytes(b"alpha")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)

    token = server._begin_client_connection()
    try:
        opened = _open_owned_session(server, str(binary_a))
        sid = opened["session_id"]
        server.session_runtimes[sid] = {"process": _FakeIdaProcess()}

        listing = server._session_action_list({})
        assert listing["ok"] is True
        row = next(s for s in listing["sessions"] if s["session_id"] == sid)
        assert row["locked"] is True
        assert row["holder"] == "this-host-runtime"
        assert row["owner_pid"] == os.getpid()

        state = server._session_action_state({"idb": sid})
        assert state["ok"] is True
        assert state["state"]["locked"] is True
        assert state["state"]["holder"] == "this-host-runtime"
    finally:
        server._end_client_connection(token)
        server.shutdown()
