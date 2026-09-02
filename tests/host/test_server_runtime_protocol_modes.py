"""Exercise the host protocol loop and public/legacy surface modes."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server as server_mod
from ida_pro_mcp.host.server.server import IDAMCPServer


class _BinaryInput:
    def __init__(self, lines, error_once=False):
        self._lines = list(lines)
        self._error_once = error_once

    def readline(self):
        if self._error_once:
            self._error_once = False
            raise OSError("read failed")
        return self._lines.pop(0) if self._lines else b""


class _BinaryOutput:
    def __init__(self):
        self.data = bytearray()

    def write(self, data):
        self.data.extend(data)

    def flush(self):
        return None


def _bare_server(input_lines, *, error_once=False):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._usage_intel = None
    server.handle_request = lambda req: (
        None
        if req.get("method") == "notifications/progress"
        else {"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}
    )
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    stdin = _BinaryInput(input_lines, error_once=error_once)
    stdout = _BinaryOutput()
    return server, stdin, stdout


def test_stdio_run_parses_requests_notifications_and_internal_errors(monkeypatch):
    lines = [
        b"\n",
        b"not-json\n",
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
        b'{"jsonrpc":"2.0","method":"notifications/progress"}\n',
    ]
    server, stdin, stdout = _bare_server(lines)
    monkeypatch.setattr(server_mod, "_real_stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(server_mod.sys, "stdin", SimpleNamespace(buffer=stdin))
    server.run()
    outputs = [json.loads(line) for line in stdout.data.decode().splitlines()]
    assert outputs[0]["error"]["code"] == -32700
    assert outputs[1]["id"] == 1
    assert server.shutdown_called is True

    server, stdin, stdout = _bare_server([], error_once=True)
    monkeypatch.setattr(server_mod, "_real_stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(server_mod.sys, "stdin", SimpleNamespace(buffer=stdin))
    server.run()
    assert json.loads(stdout.data.decode().splitlines()[0])["error"]["code"] == -32000


def test_handle_request_protocol_modes_filters_tools_and_reports_bad_methods(monkeypatch):
    server = IDAMCPServer()
    server._build_tools_list_catalog = lambda mode: [
        {"name": "ida_find", "category": "search"},
        {"name": "ida_calc", "category": "analysis"},
        {"name": "legacy", "category": "compat"},
    ]
    listed = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "prefix": "ida_",
                "contains": "calc",
                "category": "analysis",
                "sort": "unexpected",
                "descending": True,
                "limit": 1,
                "offset": 0,
            },
        }
    )
    assert listed["result"]["tools"] == [{"name": "ida_calc", "category": "analysis"}]
    assert listed["result"]["next_offset"] is None
    assert server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "notifications/noop"})["error"]["code"] == -32601
    assert server.handle_request({"jsonrpc": "2.0", "method": "notifications/noop"}) is None

    initialized = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {"clientInfo": {"name": "Gemini Desktop"}},
        }
    )
    assert initialized["result"]["serverInfo"]["name"] == "ida-pro-mcp"
    assert server.vertex_compat is True

    server.tool_surface = "agent"
    unknown = server.handle_request(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "search", "arguments": {}}}
    )
    assert unknown["result"]["isError"] is True
    assert MCPError.TOOL_NOT_FOUND in unknown["result"]["content"][0]["text"]

    monkeypatch.setattr(server, "_execute_tool", lambda tool, args: {"ok": True, "tool": tool, **args})
    server.tool_surface = "legacy"
    legacy = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"action": "find", "query": "main"}},
        }
    )
    assert legacy["result"]["isError"] is False
    assert "tool: search" in legacy["result"]["content"][0]["text"]


def test_handle_request_call_modes_validate_help_batch_and_agent_cleanup(monkeypatch):
    server = IDAMCPServer()
    bad_args = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ida_find", "arguments": "not-an-object"},
        }
    )
    assert bad_args["result"]["isError"] is True
    help_result = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "ida_help", "arguments": {"topic": "ida_find"}},
        }
    )
    assert help_result["result"]["isError"] is False
    assert "operation:" in help_result["result"]["content"][0]["text"]

    monkeypatch.setattr(server, "_handle_batch", lambda _args: {"ok": True, "count": 0})
    batch = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "ida_batch", "arguments": {"calls": [{"name": "ida_overview", "arguments": {}}]}},
        }
    )
    assert batch["result"]["isError"] is False
    monkeypatch.setattr(server, "_execute_tool", lambda *_args: {"ok": True})
    monkeypatch.setattr(server, "_bind_agent_call", lambda _name: None)
    monkeypatch.setattr(server, "_unbind_agent_call", lambda: None)
    agent = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "ida_overview", "arguments": {"agent": "worker-a"}},
        }
    )
    assert agent["result"]["isError"] is False


def test_daemon_connection_handles_fragmented_lines_timeout_and_send_failure(monkeypatch):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._begin_client_connection = lambda: "token"
    server._end_client_connection = lambda token: setattr(server, "ended", token)
    server.handle_request = lambda req: {"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}

    class Conn:
        def __init__(self):
            self.chunks = [b'{"id":', b'1}\n', TimeoutError(), b"bad-json\n", b""]
            self.sent = []

        def settimeout(self, value):
            self.timeout = value

        def recv(self, _size):
            chunk = self.chunks.pop(0)
            if isinstance(chunk, Exception):
                raise chunk
            return chunk

        def sendall(self, data):
            self.sent.append(data)

        def close(self):
            self.closed = True

    conn = Conn()
    server._handle_daemon_conn(conn)
    assert json.loads(conn.sent[0])["id"] == 1
    assert server.ended == "token"
    assert conn.closed is True

    server._shutdown_requested = True
    conn = Conn()
    conn.sendall = lambda _data: (_ for _ in ()).throw(OSError("closed"))
    server._handle_daemon_conn(conn)
    assert conn.closed is True
