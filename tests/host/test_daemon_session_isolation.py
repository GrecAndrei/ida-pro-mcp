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
