"""Public MCP contract tests for concurrent daemon clients."""

from __future__ import annotations

import threading

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
        opened_a = results["a"]["opened"]["session"]
        opened_b = results["b"]["opened"]["session"]
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
    """A persisted IDB is never silently shared by independent clients."""
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

    def client(label: str) -> None:
        barrier.wait(timeout=5)
        results[label] = _tool_call(
            server, 1, "ida_open_binary", {"binary_path": str(binary_path)}
        )

    threads = [
        threading.Thread(target=client, args=("a",)),
        threading.Thread(target=client, args=("b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    try:
        session_a = results["a"]["session"]
        session_b = results["b"]["session"]
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
        idb_a = opened_a["session"]["idb_path"]
        sid_a = opened_a["session"]["session_id"]
    finally:
        server._end_client_connection(token_a)

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
            opened["session"]["idb_path"],
        )
        assert submitted.get("error") is not True
        result = server._batch_manager.wait(submitted["task_id"], timeout=5)
        assert result["state"] == "done", result
        assert calls == ["intelligence"]
    finally:
        server._end_client_connection(token)
        server.shutdown()
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
        sid_a = opened_a["session"]["session_id"]
        path_a = opened_a["session"]["binary_path"]
    finally:
        server._end_client_connection(token_a)

    token_b = server._begin_client_connection()
    try:
        opened_b = _open_owned_session(server, str(binary_b))
        sid_b = opened_b["session"]["session_id"]
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
        sid_a = opened_a["session"]["session_id"]
        task_a = server._batch_manager.submit(
            action="semantic_index",
            args={"mode": "fast"},
            session_id=sid_a,
            run_fn=lambda task: {"ok": True},
        )
    finally:
        server._end_client_connection(token_a)

    token_b = server._begin_client_connection()
    try:
        opened_b = _open_owned_session(server, str(binary_b))
        sid_b = opened_b["session"]["session_id"]
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
