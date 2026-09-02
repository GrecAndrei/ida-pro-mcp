"""Unit tests for scripts/smoke_core_path.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import smoke_core_path


def test_tool_client_adapter_raw():
    mock_raw = mock.MagicMock()
    mock_raw.call.return_value = {
        "result": {"content": [{"type": "text", "text": '{"status": "ok"}'}]}
    }
    client = smoke_core_path._ToolClient(mock_raw, payload=True)
    res = client.call_tool("ida_session_state", {})
    assert res.get("status") == "ok"


def test_tool_client_adapter_unwrapped():
    mock_client = mock.MagicMock()
    mock_client.call.return_value = {"ok": True}
    client = smoke_core_path._ToolClient(mock_client, payload=False)
    res = client.call_tool("ida_session_state", {})
    assert res.get("ok") is True


def test_call_helper_success_and_failure(capsys):
    mock_client = mock.MagicMock()
    mock_client.call_tool.return_value = {"ok": True, "value": 123}

    res = smoke_core_path._call(mock_client, "ida_session_state", {}, "test_call")
    assert res.get("ok") is True
    captured = capsys.readouterr()
    assert "OK" in captured.out
    assert "test_call" in captured.out

    # Failure path
    mock_client.call_tool.return_value = {"error": True, "message": "boom"}
    with pytest.raises(SystemExit) as exc:
        smoke_core_path._call(mock_client, "ida_session_state", {}, "failing_call")
    assert "core path failed" in str(exc.value)


def test_main_missing_binary(capsys):
    with mock.patch("sys.argv", ["smoke_core_path.py", "--binary", "/non/existent/path/foo.bin"]):
        rc = smoke_core_path.main()
        assert rc == 2
        captured = capsys.readouterr()
        assert "binary not found" in captured.err


def test_main_workflow_execution(tmp_path, monkeypatch, capsys):
    dummy_bin = tmp_path / "sample.bin"
    dummy_bin.write_bytes(b"\x90\x90\x90\x90")

    mock_client = mock.MagicMock()
    responses = {
        "ida_open_binary": {"session_id": "S123", "sid": "S123"},
        "ida_session_state": {"ok": True, "state": "analyzing"},
        "ida_find": {"items": [{"addr": "0x140001000"}]},
        "ida_list_functions": {"functions": [{"addr": "0x140001000"}]},
        "ida_decompile": {"ok": True, "pseudocode": "void main() {}"},
        "ida_write_finding": {"ok": True, "finding_id": "F1"},
        "ida_index_functions": {"ok": True, "task_id": "T1"},
        "ida_semantic_search": {"ok": True, "results": []},
        "ida_close_session": {"ok": True},
    }
    mock_client.call_tool.side_effect = lambda tool, args: responses.get(tool, {"ok": True})

    monkeypatch.setattr(smoke_core_path, "_ToolClient", lambda *a, **k: mock_client)

    with mock.patch("sys.argv", ["smoke_core_path.py", "--binary", str(dummy_bin), "--with-nl"]):
        rc = smoke_core_path.main()
        assert rc == 0
        captured = capsys.readouterr()
        assert "core-path smoke PASSED" in captured.out
