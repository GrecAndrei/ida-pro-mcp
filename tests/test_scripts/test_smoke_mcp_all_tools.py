"""Unit tests for scripts/smoke_mcp_all_tools.py."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import smoke_mcp_all_tools as smat


def test_base_env_and_curated():
    assert "IDA_MCP_DISABLE_STUCK_DETECTION" in smat.BASE_ENV
    assert "IDA_MCP_RESPONSE_MODE" in smat.BASE_ENV
    assert len(smat.CURATED) > 20
    assert "session" in smat.CURATED
    assert "analysis" in smat.CURATED
    assert "code" in smat.CURATED


def test_first_addr_from_functions():
    payload = {"functions": "0x140001000 main\n0x140001050 helper\n"}
    addrs = smat.first_addr_from_functions(payload, n=2)
    assert addrs == ["0x140001000", "0x140001050"]

    assert smat.first_addr_from_functions({}, n=2) == []
    assert smat.first_addr_from_functions({"functions": "no_addr\n"}, n=2) == []


def test_classify():
    # Timeout
    assert smat.classify(None, "timeout") == ("TIMEOUT", "(no response in budget)")
    assert smat.classify(None, "no response") == ("TIMEOUT", "(no response)")

    # Crash
    assert smat.classify(None, "eof") == ("CRASH", "(host stdout EOF / process died)")
    assert smat.classify({"_rpc_error": "boom"}, "rpc_error")[0] == "CRASH"
    assert smat.classify({"error": True, "code": "UNKNOWN_ERROR", "details": {"traceback": "line 1\nline 2"}}, "")[0] == "CRASH"

    # Other
    assert smat.classify(None, "") == ("OTHER", "None payload")
    assert smat.classify({"_raw": "bad json"}, "")[0] == "OTHER"

    # OK
    assert smat.classify({"ok": True, "data": 123}, "") == ("OK", "")
    assert smat.classify({"ok": False, "reason": "stale"}, "")[0] == "OK"

    # Clean error
    st, note = smat.classify({"error": True, "code": "INVALID_ARGS", "message": "bad arg"}, "")
    assert st == "CLEAN"
    assert "INVALID_ARGS" in note


def test_substitute():
    raw_args = {"addr": "__ADDR__", "target": "__ADDR2__", "idb": "__IDB__", "limit": 10}
    sub = smat.substitute(raw_args, "0x1000", "0x2000", "/tmp/test.i64")
    assert sub["addr"] == "0x1000"
    assert sub["target"] == "0x2000"
    assert sub["idb"] == "/tmp/test.i64"
    assert sub["limit"] == 10
    assert sub["_risk_ack"] is True


def test_fallback_args():
    schema = {
        "properties": {
            "action": {"enum": ["list", "create"]},
            "addr": {"type": "string"},
            "query": {"type": "string"},
            "count": {"type": "integer"},
            "is_fast": {"type": "boolean"},
            "items": {"type": "array"},
            "meta": {"type": "object"},
        }
    }
    args = smat.fallback_args(schema, "0x140001000")
    assert args["action"] == "list"
    assert args["addr"] == "0x140001000"
    assert args["query"] == "main"
    assert args["count"] == 3
    assert args["is_fast"] is False
    assert args["items"] == []
    assert args["meta"] == {}
    assert args["_risk_ack"] is True


def test_mcp_client_mock():
    client = smat.MCPClient(timeout=1.0)
    client.proc = mock.MagicMock()
    client.proc.stdin = io.BytesIO()
    client.proc.stdout = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"session"}]}}\n')

    # Readline timeout test
    client._readline_timeout = mock.MagicMock(return_value=b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n')
    tools = client.tools_list()
    assert isinstance(tools, list)

    client.call = mock.MagicMock(return_value={"result": {"content": [{"text": '{"ok": true}'}]}})
    payload, err = client.tool_call("session", {})
    assert payload.get("ok") is True
    assert err == ""

    client.stop()


def test_main_cli_missing_binary(capsys):
    with mock.patch("sys.argv", ["smoke_mcp_all_tools.py"]):
        rc = smat.main()
        assert rc == 2
        captured = capsys.readouterr()
        assert "FATAL" in captured.err


def test_main_workflow_full(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "target.bin"
    dummy_bin.write_bytes(b"\x90\x90")

    monkeypatch.setattr(smat, "VENV_PY", sys.executable)
    monkeypatch.setattr(smat, "BASE_ENV", {"IDADIR": str(tmp_path), "IDA_MCP_IDAT": str(tmp_path / "idat")})
    (tmp_path / "idat").write_text("#!/bin/sh\n")

    mock_cli = mock.MagicMock()
    mock_cli.initialize.return_value = True
    mock_cli.tools_list.return_value = [
        {"name": "session", "inputSchema": {}},
        {"name": "code", "inputSchema": {}},
    ]
    mock_cli.tool_call.side_effect = lambda tool, args: (
        ({"ok": True, "session_id": "S100"}, "") if tool == "session" and args.get("action") == "create" else
        ({"functions": "0x140001000 main\n0x140001050 helper\n"}, "") if tool == "data" else
        ({"ok": True}, "")
    )
    mock_cli.call.side_effect = lambda method, params: (
        {"result": {"content": [{"text": '{"session_id": "S100"}'}]}} if params.get("arguments", {}).get("action") == "status" else
        {"result": {"content": [{"text": '{"idb_path": "/tmp/test.i64"}'}]}} if params.get("arguments", {}).get("action") == "meta" else
        {"result": {}}
    )

    monkeypatch.setattr(smat, "MCPClient", lambda timeout: mock_cli)

    with mock.patch("sys.argv", ["smoke_mcp_all_tools.py", "--binary", str(dummy_bin), "--only", "session,code"]):
        rc = smat.main()
        assert rc == 0
        captured = capsys.readouterr()
        assert "SUMMARY" in captured.out
        assert "TOTAL" in captured.out


def test_main_handshake_and_session_failures(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "target.bin"
    dummy_bin.write_bytes(b"\x90\x90")

    monkeypatch.setattr(smat, "VENV_PY", sys.executable)
    monkeypatch.setattr(smat, "BASE_ENV", {"IDADIR": str(tmp_path), "IDA_MCP_IDAT": str(tmp_path / "idat")})
    (tmp_path / "idat").write_text("#!/bin/sh\n")

    mock_cli = mock.MagicMock()
    mock_cli.initialize.return_value = False
    monkeypatch.setattr(smat, "MCPClient", lambda timeout: mock_cli)

    with mock.patch("sys.argv", ["smoke_mcp_all_tools.py", "--binary", str(dummy_bin)]):
        rc = smat.main()
        assert rc == 3
        captured = capsys.readouterr()
        assert "handshake failed" in captured.err

    # Session create failure
    mock_cli.initialize.return_value = True
    mock_cli.tool_call.return_value = ({"error": True}, "")
    with mock.patch("sys.argv", ["smoke_mcp_all_tools.py", "--binary", str(dummy_bin)]):
        rc = smat.main()
        assert rc == 4
        captured = capsys.readouterr()
        assert "could not create session" in captured.err
