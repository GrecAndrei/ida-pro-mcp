"""Unit tests for scripts/mcp_probe.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import mcp_probe


def test_build_payload_no_call():
    payload = mcp_probe.build_payload(None, None)
    assert len(payload) == 3
    assert payload[0]["method"] == "initialize"
    assert payload[1]["method"] == "notifications/initialized"
    assert payload[2]["method"] == "tools/list"


def test_build_payload_with_call():
    payload = mcp_probe.build_payload("segments", {"action": "list"})
    assert len(payload) == 4
    assert payload[3]["method"] == "tools/call"
    assert payload[3]["params"]["name"] == "segments"
    assert payload[3]["params"]["arguments"] == {"action": "list"}


def test_run_subprocess_mock():
    mock_res = subprocess.CompletedProcess(
        args=["python"],
        returncode=0,
        stdout='{"jsonrpc": "2.0", "id": 1, "result": {}}\n\nnot_json\n{"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}\n',
    )
    with mock.patch("subprocess.run", return_value=mock_res) as mock_run:
        responses = mcp_probe.run([{"method": "test"}])
        assert len(responses) == 2
        assert responses[0]["id"] == 1
        assert responses[1]["id"] == 2
        assert mock_run.called


def test_main_cli_variations(monkeypatch, capsys):
    mock_responses = [
        {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "test"}}},
        {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
        {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "{}"}]}},
    ]
    monkeypatch.setattr(mcp_probe, "run", lambda payload: mock_responses)

    # Test all show-only options
    for show_choice, expected_ids in [
        ("all", [1, 2, 3]),
        ("init", [1]),
        ("list", [2]),
        ("call", [3]),
    ]:
        test_args = [
            "mcp_probe.py",
            "--call", "segments",
            "--args", '{"action": "list"}',
            "--show-only", show_choice,
            "--pretty",
        ]
        monkeypatch.setattr(sys, "argv", test_args)
        rc = mcp_probe.main()
        assert rc == 0
        captured = capsys.readouterr()
        for i in [1, 2, 3]:
            if i in expected_ids:
                assert f'"id": {i}' in captured.out
            else:
                assert f'"id": {i}' not in captured.out

    # Test non-pretty output
    test_args = [
        "mcp_probe.py",
        "--show-only", "init",
    ]
    monkeypatch.setattr(sys, "argv", test_args)
    rc = mcp_probe.main()
    assert rc == 0
    captured = capsys.readouterr()
    assert '{"jsonrpc": "2.0", "id": 1,' in captured.out
