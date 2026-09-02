"""Unit tests for scripts/ida_mcp_client.py."""

from __future__ import annotations

import io
import json
import queue
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import ida_mcp_client


class FakeSubprocess:
    def __init__(self, stdout_lines=None):
        self.stdin = io.BytesIO()
        self.stdout = [line.encode("utf-8") + b"\n" for line in (stdout_lines or [])]
        self.stderr = [b"ida stderr info\n"]
        self.returncode = 0

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def test_ida_mcp_client_start_and_call(monkeypatch):
    fake_init_resp = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "ida"}}})
    fake_tool_resp = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"content": [{"type": "text", "text": '{"ok": true, "session": {"id": "S1"}}'}]},
    })
    proc = FakeSubprocess(stdout_lines=[fake_init_resp, fake_tool_resp])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)

    client = ida_mcp_client.IDAMCPClient()
    ok = client.start()
    assert ok is True
    assert client.proc is not None

    res = client.call_tool("session", action="create", binary_path="/tmp/test.exe")
    assert res.get("ok") is True

    # Test open_binary
    client.session = None
    client.call_tool = mock.MagicMock(return_value={"ok": True, "session": "S1"})
    assert client.open_binary("/tmp/test.exe") is True
    assert client.session == "S1"

    client.call_tool = mock.MagicMock(return_value={"error": "fail"})
    assert client.open_binary("/tmp/test.exe") is False

    client.stop()


def test_ida_mcp_client_call_timeout_and_error(monkeypatch):
    client = ida_mcp_client.IDAMCPClient()
    client.proc = mock.MagicMock()
    client.proc.poll.return_value = 1  # died
    client.proc.stdin = io.BytesIO()

    # When queue is empty and server died
    res = client._call("test", {}, timeout=0.01)
    assert "error" in res


def test_interactive_session(monkeypatch, capsys):
    client = mock.MagicMock()
    client.call_tool.side_effect = lambda tool, **args: (
        {"functions": [{"address": "0x140001000", "name": "main"}]} if tool == "data" and args.get("action") == "functions" else
        {"strings": [{"address": "0x140002000", "value": "Hello"}]} if tool == "data" and args.get("action") == "strings" else
        {"pseudocode": "int main() { return 0; }"} if tool == "code" and args.get("action") == "decompile" else
        {"lines": [{"address": "0x140001000", "text": "push rbp"}]} if tool == "code" and args.get("action") == "disasm" else
        {"xrefs": ["0x140001008"]} if tool == "code" and args.get("action") == "xrefs_to" else
        {"meta": {"compiler": "msvc"}} if tool == "idb" and args.get("action") == "meta" else
        {"ok": True}
    )
    client._call.return_value = {
        "result": {"tools": [{"name": "session", "description": "Session manager"}]},
    }

    inputs = iter([
        "open /tmp/test.exe",
        "funcs",
        "strings",
        "decomp 0x140001000",
        "disasm 0x140001000",
        "xrefs 0x140001000",
        "meta",
        "help",
        'call session {"action": "list"}',
        "custom_tool action_arg",
        "exit",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    ida_mcp_client.interactive_session(client)

    captured = capsys.readouterr()
    assert "IDA MCP Interactive Client" in captured.out
    assert "main" in captured.out
    assert "Hello" in captured.out
    assert "int main()" in captured.out
    assert "push rbp" in captured.out


def test_interactive_session_eof_and_interrupt(monkeypatch):
    client = mock.MagicMock()

    # EOFError exit
    monkeypatch.setattr("builtins.input", mock.MagicMock(side_effect=EOFError))
    ida_mcp_client.interactive_session(client)

    # KeyboardInterrupt continue then exit
    inputs = iter([KeyboardInterrupt, "exit"])
    def mock_input(prompt=""):
        val = next(inputs)
        if isinstance(val, type) and issubclass(val, Exception):
            raise val()
        return val

    monkeypatch.setattr("builtins.input", mock_input)
    ida_mcp_client.interactive_session(client)


def test_main_cli_modes(monkeypatch, capsys):
    mock_client = mock.MagicMock()
    mock_client.start.return_value = True
    mock_client.open_binary.return_value = True
    mock_client.call_tool.return_value = {"ok": True, "result": "sample"}
    monkeypatch.setattr(ida_mcp_client, "IDAMCPClient", lambda: mock_client)

    # Single command mode
    monkeypatch.setattr(sys, "argv", ["ida_mcp_client.py", "/tmp/test.exe", "-c", 'session {"action":"list"}'])
    ida_mcp_client.main()
    captured = capsys.readouterr()
    assert '"ok": true' in captured.out
    assert mock_client.open_binary.called
    assert mock_client.stop.called
