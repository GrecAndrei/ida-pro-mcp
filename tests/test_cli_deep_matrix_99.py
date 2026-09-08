"""Exhaustive boundary and error handling tests for cli.py and __main__.py."""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
import types
import warnings
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp import cli


def test_cli_proc_stderr_none():
    mock_proc = types.SimpleNamespace(
        stderr=None,
        stdin=MagicMock(),
        stdout=MagicMock(),
        poll=lambda: 0,
        wait=lambda timeout=None: 0,
    )
    with patch("subprocess.Popen", return_value=mock_proc):
        client = cli.MCPStdioClient(["dummy"])
        assert client._stderr.lines == []
        client.close()


def test_cli_call_empty_or_non_string_method():
    mock_proc = types.SimpleNamespace(
        stderr=None,
        stdin=MagicMock(),
        stdout=MagicMock(),
        poll=lambda: 0,
        wait=lambda timeout=None: 0,
    )
    with patch("subprocess.Popen", return_value=mock_proc):
        client = cli.MCPStdioClient(["dummy"])
        with pytest.raises(SystemExit, match="method must be a non-empty string"):
            client.call("")
        with pytest.raises(SystemExit, match="method must be a non-empty string"):
            client.call(123)  # type: ignore[arg-type]
        client.close()


def test_cli_daemon_is_running_exception(monkeypatch):
    def broken_socket(*args, **kwargs):
        raise OSError("socket creation error")
    monkeypatch.setattr(cli._socket_mod, "socket", broken_socket)
    assert cli._daemon_is_running() is False


def test_cli_start_daemon_already_running(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    cli._start_daemon()


def test_cli_start_daemon_socket_not_owned(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: False)
    with pytest.raises(SystemExit, match="Refusing to manage daemon socket"):
        cli._start_daemon()


def test_cli_start_daemon_probe_connect_succeeds(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)

    mock_sock = MagicMock()
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)
    cli._start_daemon()
    assert mock_sock.connect.called
    assert mock_sock.close.called


def test_cli_start_daemon_recheck_running_before_unlink(monkeypatch):
    calls = []
    def running_sequence():
        calls.append(1)
        return len(calls) > 1

    monkeypatch.setattr(cli, "_daemon_is_running", running_sequence)
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)

    mock_sock = MagicMock()
    mock_sock.connect.side_effect = OSError("refused")
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    unlinked = []
    monkeypatch.setattr(os, "unlink", unlinked.append)

    cli._start_daemon()
    assert not unlinked


def test_cli_start_daemon_timeout_with_tail(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(os.path, "exists", lambda p: False)

    mock_proc = MagicMock()
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **kw: mock_proc)

    current_time = [100.0]
    def fake_time():
        current_time[0] += 5.0
        return current_time[0]
    monkeypatch.setattr(cli.time, "time", fake_time)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    log_file = tmp_path / "daemon.log"
    log_file.write_text("traceback line 1\ntraceback line 2\n")

    monkeypatch.setattr(cli.tempfile, "mkstemp", lambda **kw: (999, str(log_file)))
    monkeypatch.setattr(os, "close", lambda fd: None)
    monkeypatch.setattr(os, "unlink", lambda p: None)

    with pytest.raises(SystemExit, match="Daemon did not start within 10 seconds"):
        cli._start_daemon()


def test_cli_daemon_call_connect_oserror(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = OSError("connect refused")
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Cannot connect to daemon"):
        cli._daemon_call("test_tool", {"action": "ping"})


def test_cli_daemon_call_sendall_oserror(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = OSError("broken pipe")
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Failed to send request to daemon"):
        cli._daemon_call("test_tool", {"action": "ping"})


def test_cli_daemon_call_recv_timeout_error(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = TimeoutError("timed out")
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Daemon did not respond within"):
        cli._daemon_call("test_tool", {"action": "ping"}, timeout=5.0)


def test_cli_daemon_call_recv_oserror(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = OSError("connection reset")
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Daemon connection failed while reading"):
        cli._daemon_call("test_tool", {"action": "ping"})


def test_cli_daemon_call_empty_response(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b""
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Daemon returned empty response"):
        cli._daemon_call("test_tool", {"action": "ping"})


def test_cli_daemon_call_decode_error_and_missing_answer(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_socket_owned", lambda: True)
    mock_sock = MagicMock()
    chunks = [b"invalid-json\n{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n", b""]
    mock_sock.recv.side_effect = chunks
    monkeypatch.setattr(cli._socket_mod, "socket", lambda *a, **kw: mock_sock)

    with pytest.raises(SystemExit, match="Daemon did not return a response for the tool call"):
        cli._daemon_call("test_tool", {"action": "ping"})


def test_cli_handle_background_mode_file_read_error():
    args = types.SimpleNamespace(
        name="submit",
        file="/nonexistent/path/for/script.py",
        stdin_json=False,
        payload=None,
        session_id=None,
        pretty=False,
    )
    with pytest.raises(SystemExit, match="Cannot read file"):
        cli._handle_background_mode(args)


def test_cli_handle_background_mode_stdin_json(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    monkeypatch.setattr(cli, "_read_stdin_json", lambda label: {"task_id": "t1"})
    monkeypatch.setattr(
        cli,
        "_daemon_call",
        lambda *args, **kw: calls.append((args, kw)) or {"result": {"content": [{"type": "text", "text": "{\"ok\": true}"}]}},
    )

    args = types.SimpleNamespace(
        name="status",
        file=None,
        stdin_json=True,
        payload=None,
        session_id="sess_123",
        pretty=False,
    )
    assert cli._handle_background_mode(args) == 0
    assert calls[0][0][1]["session_id"] == "sess_123"
    assert calls[0][0][1]["task_id"] == "t1"


def test_cli_main_background_dispatch(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "_handle_background_mode", lambda args: called.append(args) or 0)
    assert cli.main(["background", "list"]) == 0
    assert len(called) == 1


def test_cli_main_unsupported_mode(monkeypatch):
    fake_args = types.SimpleNamespace(
        mode="unsupported_mode",
        stdin_json=False,
        payload=None,
        name="some_tool",
        request_id=None,
        pretty=False,
    )
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda self, argv: fake_args)

    mock_client = MagicMock()
    with patch.object(cli, "MCPStdioClient", return_value=mock_client), pytest.raises(
        SystemExit, match="unsupported mode: unsupported_mode"
    ):
        cli.main(["tools-list"])


def test_cli_module_main_entrypoint(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ida-pro-mcp-cli", "background", "list"])
    monkeypatch.setattr(cli, "_handle_background_mode", lambda args: 0)
    with pytest.raises(SystemExit) as exc, warnings.catch_warnings():
        # runpy warns when the module is already in sys.modules (it always
        # is here: this file imports cli above). Ignore only that warning.
        warnings.filterwarnings(
            "ignore",
            message=".*found in sys.modules.*",
            category=RuntimeWarning,
        )
        runpy.run_module("ida_pro_mcp.cli", run_name="__main__")
    assert exc.value.code == 0


def test_package_main_entrypoint(monkeypatch):
    called = []

    def fake_main():
        called.append(True)

    monkeypatch.setattr("ida_pro_mcp.host.server.server.main", fake_main)
    monkeypatch.setattr(sys, "argv", ["python", "-m", "ida_pro_mcp"])
    runpy.run_module("ida_pro_mcp", run_name="__main__")
    assert called == [True]
    assert sys.argv[0] == "ida_pro_mcp"


def test_cli_handle_background_mode_wait_invalid_timeout(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    monkeypatch.setattr(
        cli,
        "_daemon_call",
        lambda *args, **kw: calls.append((args, kw)) or {"result": {"content": [{"type": "text", "text": "{\"ok\": true}"}]}},
    )
    args = types.SimpleNamespace(
        name="wait",
        file=None,
        stdin_json=False,
        payload=json.dumps({"task_id": "t1", "timeout": "not-a-number"}),
        session_id=None,
        pretty=False,
    )
    assert cli._handle_background_mode(args) == 0
    assert calls[0][1]["timeout"] is None


def test_cli_start_daemon_timeout_with_tail_oserror(monkeypatch):
    monkeypatch.setattr(cli, "_daemon_is_running", lambda: False)
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    mock_proc = MagicMock()
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **kw: mock_proc)
    current_time = [100.0]
    def fake_time():
        current_time[0] += 5.0
        return current_time[0]
    monkeypatch.setattr(cli.time, "time", fake_time)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli.tempfile, "mkstemp", lambda **kw: (999, "/nonexistent/path/daemon.log"))
    monkeypatch.setattr(os, "close", lambda fd: None)
    monkeypatch.setattr(os, "unlink", lambda p: None)
    with pytest.raises(SystemExit, match="Daemon did not start within 10 seconds"):
        cli._start_daemon()

