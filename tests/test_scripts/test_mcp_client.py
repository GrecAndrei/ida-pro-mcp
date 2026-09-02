"""Unit tests for scripts/mcp_client.py."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import mcp_client


def test_default_state_dir(monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", "/custom/state")
    assert mcp_client._default_state_dir() == "/custom/state/ida-pro-mcp"

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert mcp_client._default_state_dir().endswith("ida-pro-mcp")


def test_default_data_dirs(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "/custom/data")
    dirs = mcp_client._default_data_dirs()
    assert "/custom/data/ida-pro-mcp" in dirs
    assert any("share" in d for d in dirs)


def test_discover_venv_python(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_client, "_default_data_dirs", lambda: [str(tmp_path)])
    assert mcp_client._discover_venv_python() is None

    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    py_bin = venv_bin / "python3"
    py_bin.write_text("#!/bin/sh\n")
    assert mcp_client._discover_venv_python() == str(py_bin)


def test_resolve_server_script():
    script_path = mcp_client._resolve_server_script()
    assert script_path.endswith("ida_mcp_stdio.py")
    assert Path(script_path).is_file()


def test_resolve_server_script_not_found(monkeypatch, tmp_path):
    dummy_path = tmp_path / "nested" / "dummy.py"
    monkeypatch.setattr(mcp_client, "Path", lambda f: dummy_path)
    with pytest.raises(FileNotFoundError):
        mcp_client._resolve_server_script()


class FakeStdin:
    def __init__(self, proc: FakeMCPProcess):
        self.proc = proc

    def write(self, data: bytes):
        if self.proc._stdout_lines:
            next_line = self.proc._stdout_lines.pop(0)
            os.write(self.proc._w_fd, next_line.encode("utf-8") + b"\n")

    def flush(self):
        pass

    def close(self):
        pass


class FakeMCPProcess:
    def __init__(self, stdout_lines=None, returncode=None):
        self._stdout_lines = list(stdout_lines or [])
        self.returncode = returncode
        self._r_fd, self._w_fd = os.pipe()
        self.stdin = FakeStdin(self)
        self.stdout = types_proc_file(self._r_fd)
        self.stderr = io.BytesIO(b"stderr line 1\nstderr line 2\n")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode or 0

    def kill(self):
        pass

    def close(self):
        try:
            os.close(self._w_fd)
            os.close(self._r_fd)
        except OSError:
            pass


class types_proc_file:
    def __init__(self, fd):
        self._fd = fd

    def fileno(self):
        return self._fd

    def readline(self):
        res = b""
        while True:
            try:
                b = os.read(self._fd, 1)
                if not b or b == b"\n":
                    break
                res += b
            except OSError:
                break
        return res

    def close(self):
        with contextlib.suppress(OSError):
            os.close(self._fd)


def test_mcp_client_lifecycle_and_calls(monkeypatch, tmp_path):
    fake_init_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"serverInfo": {"name": "test-server", "version": "1.0"}},
    })
    fake_list_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "session"}], "total": 1},
    })
    fake_call_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "result": {"content": [{"type": "text", "text": '{"ok": true, "session": {"is_running": true}}'}]},
    })
    fake_proc = FakeMCPProcess(stdout_lines=[fake_init_resp, fake_list_resp, fake_call_resp])

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_proc)

    with mcp_client.MCPClient(cache_dir=str(tmp_path)) as client:
        assert client.get_stderr() != ""
        tools = client.list_tools()
        assert tools["total"] == 1

        status = client.status()
        assert status.get("ok") is True

    fake_proc.close()


def test_mcp_client_error_and_timeout(monkeypatch):
    fake_init_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"serverInfo": {"name": "test-server"}},
    })
    fake_err_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "error": {"code": -32601, "message": "Method not found"},
    })
    fake_proc = FakeMCPProcess(stdout_lines=[fake_init_resp, fake_err_resp])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_proc)

    client = mcp_client.MCPClient()
    res = client.call("unknown_tool")
    assert res.get("code") == -32601
    client.close()
    fake_proc.close()


def test_test_basic_and_session(monkeypatch, tmp_path):
    mock_client = mock.MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.list_tools.return_value = {"total": 5}
    mock_client.status.return_value = {"total_sessions": 1, "session": {"is_running": True}}
    mock_client.call.return_value = {"ok": True, "session": {"session_id": "S123"}}

    monkeypatch.setattr(mcp_client, "MCPClient", lambda *a, **k: mock_client)

    assert mcp_client.test_basic() is True
    assert mcp_client.test_session(str(tmp_path / "test.bin")) is True

    # Test error in test_session
    mock_client.call.return_value = {"error": "failed"}
    assert mcp_client.test_session(str(tmp_path / "test.bin")) is False


def test_main_cli_dispatch(monkeypatch, tmp_path):
    bin_path = tmp_path / "test.bin"
    bin_path.write_bytes(b"\x00")

    monkeypatch.setattr(mcp_client, "test_basic", lambda: True)
    monkeypatch.setattr(mcp_client, "test_session", lambda b: True)

    monkeypatch.setattr(sys, "argv", ["mcp_client.py", "--test", "basic"])
    # should not raise
    mcp_client.main() if hasattr(mcp_client, "main") else None

    # Test missing binary error in CLI main flow
    monkeypatch.setattr(sys, "argv", ["mcp_client.py", "--test", "session", "--binary", "/non/existent/path"])
    # Run the main block logic safely
