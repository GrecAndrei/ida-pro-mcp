"""Unit tests for scripts/smoke_mcp_all_actions.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import smoke_mcp_all_actions as smaa


def test_action_args_and_skip_actions():
    assert len(smaa.ACTION_ARGS) > 50
    assert ("session", "list") not in smaa.SKIP_ACTIONS
    assert ("session", "create") in smaa.SKIP_ACTIONS
    assert ("session", "close") in smaa.SKIP_ACTIONS
    assert ("modify", "patch_asm") in smaa.SKIP_ACTIONS
    assert ("data_ops", "undefine") in smaa.SKIP_ACTIONS


def test_actions_for_tool():
    schema = {
        "properties": {
            "action": {
                "enum": ["get", "set", "list"],
            },
        },
    }
    actions = smaa.actions_for_tool(schema)
    assert actions == ["get", "set", "list"]

    assert smaa.actions_for_tool({}) == []
    assert smaa.actions_for_tool({"properties": {}}) == []


def test_fallback_args_for_action():
    schema = {
        "properties": {
            "action": {"enum": ["custom_action"]},
            "addr": {"type": "string"},
            "addr2": {"type": "string"},
            "idb": {"type": "string"},
            "query": {"type": "string"},
            "count": {"type": "integer"},
            "size": {"type": "integer"},
            "offset": {"type": "integer"},
            "is_enabled": {"type": "boolean"},
            "tags": {"type": "array"},
            "metadata": {"type": "object"},
            "custom_str": {"type": "string"},
        },
    }
    args = smaa.fallback_args_for_action(
        schema=schema,
        action="custom_action",
        addr="0x1000",
        addr2="0x2000",
        idb="/tmp/test.i64",
    )
    assert args["action"] == "custom_action"
    assert args["addr"] == "0x1000"
    assert args["addr2"] == "0x2000"
    assert args["idb"] == "/tmp/test.i64"
    assert args["query"] == "main"
    assert args["count"] == 3
    assert args["size"] == 16
    assert args["offset"] == 0
    assert args["is_enabled"] is False
    assert args["tags"] == []
    assert args["metadata"] == {}
    assert args["custom_str"] == "main"
    assert args["_risk_ack"] is True


def test_main_cli_missing_binary(capsys):
    with mock.patch("sys.argv", ["smoke_mcp_all_actions.py"]):
        rc = smaa.main()
        assert rc == 2
        captured = capsys.readouterr()
        assert "FATAL" in captured.err


def test_main_workflow_full(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "target.bin"
    dummy_bin.write_bytes(b"\x90\x90")

    monkeypatch.setattr(smaa.S, "VENV_PY", sys.executable)
    monkeypatch.setattr(smaa.S, "BASE_ENV", {"IDADIR": str(tmp_path)})
    (tmp_path / "idat").write_text("#!/bin/sh\n")

    mock_cli = mock.MagicMock()
    mock_cli.initialize.return_value = True
    mock_cli.tools_list.return_value = [
        {"name": "session", "inputSchema": {"properties": {"action": {"enum": ["list", "status"]}}}},
        {"name": "code", "inputSchema": {"properties": {"action": {"enum": ["decompile"]}}}},
    ]
    mock_cli.tool_call.side_effect = lambda tool, args: (
        ({"ok": True, "session_id": "S100"}, "") if tool == "session" and args.get("action") == "create" else
        ({"functions": "0x140001000 main\n0x140001050 helper\n"}, "") if tool == "data" else
        ({"entrypoints": [{"ea": "0x140001000"}]}, "") if tool == "idb" and args.get("action") == "entrypoints" else
        ({"ok": True}, "")
    )
    mock_cli.call.side_effect = lambda method, params: (
        {"result": {"content": [{"text": '{"idb_path": "/tmp/test.i64"}'}]}} if params.get("arguments", {}).get("action") == "meta" else
        {"result": {}}
    )

    monkeypatch.setattr(smaa.S, "MCPClient", lambda timeout: mock_cli)

    with mock.patch("sys.argv", ["smoke_mcp_all_actions.py", "--binary", str(dummy_bin), "--only", "session,code"]):
        rc = smaa.main()
        assert rc == 0
        captured = capsys.readouterr()
        assert "SUMMARY" in captured.out
        assert "TOTAL" in captured.out


def test_main_handshake_and_session_failures(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "target.bin"
    dummy_bin.write_bytes(b"\x90\x90")

    monkeypatch.setattr(smaa.S, "VENV_PY", sys.executable)
    monkeypatch.setattr(smaa.S, "BASE_ENV", {"IDADIR": str(tmp_path)})
    (tmp_path / "idat").write_text("#!/bin/sh\n")

    mock_cli = mock.MagicMock()
    mock_cli.initialize.return_value = False
    monkeypatch.setattr(smaa.S, "MCPClient", lambda timeout: mock_cli)

    with mock.patch("sys.argv", ["smoke_mcp_all_actions.py", "--binary", str(dummy_bin)]):
        rc = smaa.main()
        assert rc == 3
        captured = capsys.readouterr()
        assert "handshake failed" in captured.err

    # Session create failure
    mock_cli.initialize.return_value = True
    mock_cli.tool_call.return_value = ({"error": True}, "")
    with mock.patch("sys.argv", ["smoke_mcp_all_actions.py", "--binary", str(dummy_bin)]):
        rc = smaa.main()
        assert rc == 4
        captured = capsys.readouterr()
        assert "could not create session" in captured.err
