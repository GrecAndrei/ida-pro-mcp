"""Unit tests for scripts/test_live_ida_crystallize.py."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import test_live_ida_crystallize as tlic


def test_first_function_addr():
    payload = {"functions": "0x140001000 main\n0x140001050 helper\n"}
    addr = tlic._first_function_addr(payload)
    assert addr == "0x140001000"

    assert tlic._first_function_addr({}) is None
    assert tlic._first_function_addr({"functions": ""}) is None


class FakeProc:
    def __init__(self, stdout_lines=None):
        self.stdin = io.BytesIO()
        self.stdout = [line.encode("utf-8") + b"\n" for line in (stdout_lines or [])]
        self.stderr = [b"stderr line\n"]
        self.returncode = 0

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def test_mcp_test_client_start_and_call(monkeypatch):
    fake_init = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "test"}}})
    fake_call = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"content": [{"type": "text", "text": '{"ok": true, "session_id": "S1"}'}]},
    })
    proc = FakeProc(stdout_lines=[fake_init, fake_call])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)

    client = tlic.MCPTestClient(timeout=10)
    assert client.start() is True

    res = client.call_tool("session", action="create")
    assert res.get("ok") is True

    client.stop()


def test_mcp_test_client_errors(monkeypatch):
    client = tlic.MCPTestClient(timeout=0.01)
    client.proc = mock.MagicMock()
    client.proc.poll.return_value = 1  # died
    client.proc.stdin = io.BytesIO()

    res = client._call("test", {})
    assert "error" in res


def test_main_missing_binary(capsys):
    with mock.patch("sys.argv", ["test_live_ida_crystallize.py", "--binary", "/non/existent/bin"]):
        with pytest.raises(SystemExit) as exc:
            tlic.main()
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "FATAL: binary not found" in captured.err


def test_main_full_flow(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "sample.exe"
    dummy_bin.write_bytes(b"\x90\x90\x90\x90")

    mock_client = mock.MagicMock()
    mock_client.start.return_value = True

    tool_responses = {
        "session": {"ok": True, "session": {"session_id": "S100"}},
        "data": {"functions": "0x140001000 main\n"},
        "search": {"ok": True, "results": []},
        "code": {"ok": True, "lines": []},
        "blackboard": {"ok": True},
    }
    mock_client.call_tool.side_effect = lambda tool, **args: tool_responses.get(tool, {"ok": True})

    monkeypatch.setattr(tlic, "MCPTestClient", lambda **k: mock_client)

    with mock.patch("sys.argv", ["test_live_ida_crystallize.py", "--binary", str(dummy_bin)]):
        tlic.main()
        captured = capsys.readouterr()
        assert "MCP Server started successfully." in captured.out
        assert "Creating session on binary" in captured.out
        assert "Closing IDA Session" in captured.out
        assert mock_client.stop.called
