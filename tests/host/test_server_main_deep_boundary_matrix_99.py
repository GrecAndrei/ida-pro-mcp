"""Offline boundary coverage for the top-level host server loop."""

from __future__ import annotations

import builtins
import io
import json
import os
import sys
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server as server_module
from ida_pro_mcp.host.server.server import IDAMCPServer


def test_constructor_normalizes_invalid_environment_modes(monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    for name, value in (
        ("IDA_MCP_RESPONSE_MODE", "invalid"),
        ("IDA_MCP_QOL_MODE", "invalid"),
        ("IDA_MCP_TOOLS_LIST_MODE", "invalid"),
        ("IDA_MCP_TOOL_SURFACE", "invalid"),
        ("IDA_MCP_ERROR_DETAIL_LEVEL", "invalid"),
    ):
        monkeypatch.setenv(name, value)

    server = IDAMCPServer()

    assert server.default_response_mode == "compact"
    assert server.default_qol_mode == "balanced"
    assert server.default_tools_list_mode == "ultra"
    assert server.tool_surface == "agent"
    assert server.default_error_detail_level == "basic"


def test_constructor_contains_optional_startup_failures(monkeypatch):
    from ida_pro_mcp.host.server import session as session_module

    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")

    def fail(*_args, **_kwargs):
        raise RuntimeError("optional startup failed")

    monkeypatch.setattr(
        session_module.SessionManager, "auto_prune_if_over_budget", fail
    )
    original_import = builtins.__import__

    def fail_usage_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"intelligence.usage", "ida_pro_mcp.host.intelligence.usage"}:
            raise ImportError("optional startup failed")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_usage_import)

    server = IDAMCPServer()

    assert server._usage_intel is None


def test_initialize_clears_catalog_without_a_lock_and_tools_list_accepts_mode():
    server = IDAMCPServer()
    server._tools_list_cache_lock = None
    server._tools_list_cache["stale"] = []
    initialized = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "Gemini Desktop"}},
        }
    )
    assert initialized["result"]["serverInfo"]["name"] == "ida-pro-mcp"
    assert server._tools_list_cache == {}

    listed = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"mode": "lean", "sort": "category"},
        }
    )
    assert listed["result"]["tools"]


def test_stdio_run_stops_before_read_when_shutdown_is_requested(monkeypatch):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = True
    server._usage_intel = SimpleNamespace(_notify=None, start=lambda: None)
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    output = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(server_module, "_real_stdout", output)
    monkeypatch.setattr(server_module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO()))

    server.run()

    assert server.shutdown_called is True
    assert server._usage_intel._notify == server._send_notification


def test_stdio_run_handles_non_object_request_and_output_failures(monkeypatch):
    class Input:
        def __init__(self, lines):
            self.lines = iter(lines)

        def readline(self):
            return next(self.lines)

    class Output:
        def __init__(self, fail=False):
            self.fail = fail

        def write(self, _data):
            if self.fail:
                raise OSError("stdout closed")

        def flush(self):
            if self.fail:
                raise OSError("stdout closed")

    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._usage_intel = None
    server.handle_request = lambda _request: {"jsonrpc": "2.0", "id": None}
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    monkeypatch.setattr(
        server_module.sys,
        "stdin",
        SimpleNamespace(buffer=Input([b"[]\n", b""])),
    )
    monkeypatch.setattr(server_module, "_real_stdout", SimpleNamespace(buffer=Output()))
    server.run()
    assert server.shutdown_called is True

    class ShutdownInput:
        def readline(self):
            server._shutdown_requested = True
            raise OSError("shutdown while reading")

    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._usage_intel = None
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    monkeypatch.setattr(
        server_module.sys,
        "stdin",
        SimpleNamespace(buffer=ShutdownInput()),
    )
    monkeypatch.setattr(server_module, "_real_stdout", SimpleNamespace(buffer=Output()))
    server.run()
    assert server.shutdown_called is True

    class BrokenRequestServer(IDAMCPServer):
        def handle_request(self, request):
            return request.get("id")

    server = BrokenRequestServer.__new__(BrokenRequestServer)
    server._shutdown_requested = False
    server._usage_intel = None
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    monkeypatch.setattr(
        server_module.sys,
        "stdin",
        SimpleNamespace(buffer=Input([b"[]\n", b""])),
    )
    monkeypatch.setattr(server_module, "_real_stdout", SimpleNamespace(buffer=Output()))
    server.run()
    assert server.shutdown_called is True

    class FailingInput:
        def __init__(self):
            self.calls = 0

        def readline(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("read failed")
            return b""

    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._usage_intel = None
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    monkeypatch.setattr(
        server_module.sys,
        "stdin",
        SimpleNamespace(buffer=FailingInput()),
    )
    monkeypatch.setattr(server_module, "_real_stdout", SimpleNamespace(buffer=Output(fail=True)))
    server.run()
    assert server.shutdown_called is True


def test_daemon_loop_handles_timeout_then_shutdown(monkeypatch, tmp_path):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server.shutdown = lambda: setattr(server, "shutdown_called", True)

    class Socket:
        def bind(self, path):
            self.bound = path

        def listen(self, count):
            self.backlog = count

        def settimeout(self, seconds):
            self.timeout = seconds

        def accept(self):
            server._shutdown_requested = True
            raise TimeoutError

    monkeypatch.setattr(server_module._socket_mod, "socket", lambda *_args: Socket())
    monkeypatch.setattr(server_module, "DAEMON_SOCKET", str(tmp_path / "daemon.sock"))
    monkeypatch.setattr(server_module, "_write_pidfile", lambda: None)
    monkeypatch.setattr(server_module.atexit, "register", lambda *_args: None)

    server.run_daemon()

    assert server.shutdown_called is True


def test_daemon_loop_starts_connection_thread(monkeypatch, tmp_path):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._handle_daemon_conn = lambda _conn: None
    server.shutdown = lambda: setattr(server, "shutdown_called", True)

    class Socket:
        def bind(self, _path):
            pass

        def listen(self, _count):
            pass

        def settimeout(self, _seconds):
            pass

        def accept(self):
            return object(), object()

    class Thread:
        def __init__(self, target, args, daemon):
            self.target = target
            self.args = args
            self.daemon = daemon

        def start(self):
            self.target(*self.args)
            server._shutdown_requested = True

    monkeypatch.setattr(server_module._socket_mod, "socket", lambda *_args: Socket())
    monkeypatch.setattr(server_module, "DAEMON_SOCKET", str(tmp_path / "daemon.sock"))
    monkeypatch.setattr(server_module, "_write_pidfile", lambda: None)
    monkeypatch.setattr(server_module.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(server_module.threading, "Thread", Thread)

    server.run_daemon()

    assert server.shutdown_called is True


def test_daemon_connection_shutdown_timeout_and_buffer_cap(monkeypatch):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = True
    server._begin_client_connection = lambda: "state"
    server._end_client_connection = lambda token: setattr(server, "ended", token)

    class Connection:
        def __init__(self, chunk):
            self.chunk = chunk

        def settimeout(self, _seconds):
            pass

        def recv(self, _size):
            if self.chunk is TimeoutError:
                raise TimeoutError
            return self.chunk

        def close(self):
            self.closed = True

    timed_out = Connection(TimeoutError)
    server._handle_daemon_conn(timed_out)
    assert timed_out.closed is True
    assert server.ended == "state"

    server._shutdown_requested = False
    oversized = Connection(b"x" * (server_module._MAX_DAEMON_LINE_BYTES + 1))
    server._handle_daemon_conn(oversized)
    assert oversized.closed is True


def test_daemon_connection_skips_blank_lines_and_handles_no_response():
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._begin_client_connection = lambda: "state"
    server._end_client_connection = lambda token: setattr(server, "ended", token)
    server.handle_request = lambda _request: None

    class Connection:
        chunks = [b"\n", b'{"id": 3}\n', b""]

        def settimeout(self, _seconds):
            pass

        def recv(self, _size):
            return self.chunks.pop(0)

        def close(self):
            self.closed = True

        def sendall(self, _data):
            raise AssertionError("no response should be sent")

    conn = Connection()
    server._handle_daemon_conn(conn)
    assert conn.closed is True
    assert server.ended == "state"


def test_daemon_connection_logs_outer_receive_failure(monkeypatch):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = False
    server._begin_client_connection = lambda: "state"
    server._end_client_connection = lambda token: setattr(server, "ended", token)

    class BrokenConnection:
        def settimeout(self, _seconds):
            pass

        def recv(self, _size):
            raise OSError("connection gone")

        def close(self):
            self.closed = True

    monkeypatch.setattr(server_module, "log_rpc", lambda message: setattr(server, "log", message))
    conn = BrokenConnection()
    server._handle_daemon_conn(conn)

    assert "connection gone" in server.log
    assert conn.closed is True


def test_notification_and_pidfile_helpers_are_fail_soft(monkeypatch, tmp_path):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._send_notification({"method": "progress", "params": {"n": 1}})
    server._rs = SimpleNamespace(
        write=lambda _data: (_ for _ in ()).throw(OSError("closed")),
        flush=lambda: None,
    )
    server._send_notification({"method": "progress"})
    written = bytearray()
    server._rs = SimpleNamespace(write=written.extend, flush=lambda: None)
    server._send_notification({"method": "progress", "value": 1})
    assert json.loads(written.decode())["value"] == 1

    pidfile = tmp_path / "daemon.pid"
    monkeypatch.setattr(server_module, "DAEMON_PIDFILE", str(pidfile))
    server_module._write_pidfile()
    assert pidfile.read_text(encoding="utf-8") == str(os.getpid())
    assert server_module._read_daemon_pidfile() == os.getpid()
    pidfile.write_text("not-a-pid", encoding="utf-8")
    assert server_module._read_daemon_pidfile() is None
    pidfile.write_text("", encoding="utf-8")
    assert server_module._read_daemon_pidfile() is None


def test_shutdown_is_idempotent_on_already_closed_instance():
    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown = True

    assert server.shutdown() is None


def test_cleanup_daemon_removes_own_pid_and_socket(monkeypatch, tmp_path):
    pidfile = tmp_path / "daemon.pid"
    socket_path = tmp_path / "daemon.sock"
    pidfile.write_text(str(os.getpid()), encoding="utf-8")
    socket_path.write_text("socket", encoding="utf-8")
    monkeypatch.setattr(server_module, "DAEMON_PIDFILE", str(pidfile))
    monkeypatch.setattr(server_module, "DAEMON_SOCKET", str(socket_path))

    server_module.IDAMCPServer._cleanup_daemon()

    assert not pidfile.exists()
    assert not socket_path.exists()


def test_main_refuses_second_live_daemon(monkeypatch, capsys):
    monkeypatch.setattr(server_module, "_real_stdout", sys.stdout)
    monkeypatch.setattr(server_module.sys, "argv", ["ida-pro-mcp", "--daemon"])
    monkeypatch.setattr(server_module, "_read_daemon_pidfile", os.getpid)
    monkeypatch.setattr(server_module, "_pid_is_live", lambda _pid: True)

    with pytest.raises(SystemExit, match="1"):
        server_module.main()

    assert "already running" in capsys.readouterr().err


def test_handle_request_batch_legacy_paths_accept_and_reject_argument_shapes():
    server = IDAMCPServer()
    server.tool_surface = "legacy"
    server._handle_batch = lambda args: {"ok": True, "args": args}

    rejected = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "batch", "arguments": []},
        }
    )
    assert rejected["result"]["isError"] is True

    accepted = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "batch", "arguments": {"calls": []}},
        }
    )
    assert accepted["result"]["isError"] is False


def test_handle_request_keeps_inflight_session_count_when_another_call_remains():
    server = IDAMCPServer()
    server.tool_surface = "legacy"
    server._session_inflight_calls["A1B2C3D4"] = 2
    server._execute_tool = lambda _tool, _args: {"ok": True}

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"action": "find", "session_id": "A1B2C3D4"},
            },
        }
    )

    assert response["result"]["isError"] is False
    assert server._session_inflight_calls["A1B2C3D4"] == 2


def test_main_runs_non_daemon_and_reports_native_bootstrap_failure(monkeypatch):
    from ida_pro_mcp.host.intelligence import native

    class FakeServer:
        def run(self):
            self.ran = True

    monkeypatch.setattr(server_module, "_real_stdout", sys.stdout)
    monkeypatch.setattr(server_module.sys, "argv", ["ida-pro-mcp"])
    monkeypatch.setattr(
        native,
        "bootstrap_native_backend",
        lambda: {"enabled": True, "lib": "/tmp/libmcp_llama.so"},
    )
    monkeypatch.setattr(server_module, "IDAMCPServer", FakeServer)

    server_module.main()


def test_main_continues_when_native_bootstrap_raises(monkeypatch, capsys):
    monkeypatch.setattr(server_module, "_real_stdout", sys.stdout)
    monkeypatch.setattr(server_module.sys, "argv", ["ida-pro-mcp"])

    def fail_bootstrap():
        raise RuntimeError("native unavailable")

    fake_native = SimpleNamespace(bootstrap_native_backend=fail_bootstrap)
    original_import = builtins.__import__

    def import_without_native(name, globals=None, locals=None, fromlist=(), level=0):
        if name.endswith(".intelligence.native"):
            return fake_native
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_native)

    class FakeServer:
        def run(self):
            return None

    monkeypatch.setattr(server_module, "IDAMCPServer", FakeServer)
    server_module.main()

    assert "native backend bootstrap skipped" in capsys.readouterr().err


def test_main_converts_server_startup_exception_to_exit(monkeypatch, capsys):
    from ida_pro_mcp.host.intelligence import native

    monkeypatch.setattr(server_module, "_real_stdout", sys.stdout)
    monkeypatch.setattr(server_module.sys, "argv", ["ida-pro-mcp"])
    monkeypatch.setattr(native, "bootstrap_native_backend", lambda: {"enabled": False})

    class BrokenServer:
        def __init__(self):
            raise RuntimeError("server startup failed")

    monkeypatch.setattr(server_module, "IDAMCPServer", BrokenServer)
    with pytest.raises(SystemExit, match="1"):
        server_module.main()

    assert "server startup failed" in capsys.readouterr().err


def test_stdio_run_uses_windows_binary_mode(monkeypatch):
    calls = []
    msvcrt = SimpleNamespace(setmode=lambda fd, mode: calls.append((fd, mode)))
    monkeypatch.setitem(sys.modules, "msvcrt", msvcrt)
    monkeypatch.setattr(server_module.sys, "platform", "win32")
    monkeypatch.setattr(server_module.os, "O_BINARY", 0, raising=False)

    class Stream:
        buffer = io.BytesIO()

        def fileno(self):
            return 7

    server = IDAMCPServer.__new__(IDAMCPServer)
    server._shutdown_requested = True
    server._usage_intel = None
    server.shutdown = lambda: setattr(server, "shutdown_called", True)
    monkeypatch.setattr(server_module, "_real_stdout", Stream())
    monkeypatch.setattr(server_module.sys, "stdin", Stream())

    server.run()

    assert calls == [(7, 0), (7, 0)]
    assert server.shutdown_called is True
