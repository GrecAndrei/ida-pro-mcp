"""Unit tests for scripts/generate_arg_action_variations.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import generate_arg_action_variations as gav


def test_wrappers():
    w = gav._wrappers("find")
    assert len(w) == 16
    assert "find" in w
    assert "FIND" in w
    assert "[find]" in w
    assert "(find)" in w
    assert "{find}" in w
    assert "<find>" in w
    assert '"find"' in w
    assert "'find'" in w
    assert "`find`" in w
    assert "find()" in w
    assert "tool:find" in w


def test_noisy_keys():
    k = gav._noisy_keys("binary_path")
    assert len(k) == 11
    assert "binary_path" in k
    assert "BINARY_PATH" in k
    assert "binary-path" in k
    assert "binarypath" in k
    assert "[binary_path]" in k
    assert "(binary_path)" in k


def test_field_test_value():
    assert gav._field_test_value("addr") == "0x401000"
    assert gav._field_test_value("start") == "0x401000"
    assert gav._field_test_value("target") == "0x401000"
    assert gav._field_test_value("session_id") == "ABCD1234"
    assert gav._field_test_value("binary_path") == "/tmp/test.bin"
    assert gav._field_test_value("count") == "16"
    assert gav._field_test_value("limit") == "16"
    assert gav._field_test_value("profile") == "balanced"
    assert gav._field_test_value("severity") == "high"
    assert gav._field_test_value("name") == "main"
    assert gav._field_test_value("tag") == "triage"
    assert gav._field_test_value("query") == "main"
    assert gav._field_test_value("pattern") == "main"
    assert gav._field_test_value("something_else") == "x"


def test_iter_target_tools():
    tools = gav._iter_target_tools(None)
    assert "search" in tools
    assert "session" in tools
    assert "code" in tools


def test_mk_server():
    server, host = gav._mk_server()
    assert server is not None
    assert host is not None
    if hasattr(server, "shutdown"):
        server.shutdown()


def test_generate_variants_and_compact(monkeypatch):
    monkeypatch.setattr(gav, "_iter_target_tools", lambda host: ["session"])
    mock_server, mock_host = gav._mk_server()
    monkeypatch.setattr(mock_host, "TOOL_ACTIONS", {"session": ["list"]})
    monkeypatch.setattr(mock_host, "TOOL_ARG_SCHEMAS", {"session": {"binary_path": {"type": "string"}}})
    monkeypatch.setattr(gav, "_mk_server", lambda: (mock_server, mock_host))

    payload = gav.generate_variants(seed=42, max_cases=10)
    assert payload["seed"] == 42
    assert "tools" in payload
    assert "totals" in payload
    assert payload["totals"]["cases"] > 0
    assert payload["totals"]["accepted"] >= 0
    assert payload["totals"]["rejected"] >= 0

    compacted = gav.compact_payload(payload, max_rows_per_tool=4)
    assert compacted["seed"] == 42
    assert "tools" in compacted
    for tool_data in compacted["tools"].values():
        assert "sample_rows" in tool_data
        assert len(tool_data["sample_rows"]) <= 4
    if hasattr(mock_server, "shutdown"):
        mock_server.shutdown()


def test_main_execution(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gav, "_iter_target_tools", lambda host: ["session"])
    mock_server, mock_host = gav._mk_server()
    monkeypatch.setattr(mock_host, "TOOL_ACTIONS", {"session": ["list"]})
    monkeypatch.setattr(mock_host, "TOOL_ARG_SCHEMAS", {"session": {"binary_path": {"type": "string"}}})
    monkeypatch.setattr(gav, "_mk_server", lambda: (mock_server, mock_host))

    out_file = tmp_path / "artifacts" / "test_variations.json"
    test_args = [
        "generate_arg_action_variations.py",
        "--seed", "123",
        "--max-cases-per-tool", "5",
        "--min-total-cases", "2",
        "--output", str(out_file),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    rc = gav.main()
    assert rc == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["seed"] == 123
    assert "totals" in data

    captured = capsys.readouterr()
    assert f"Wrote {data['totals']['cases']} cases to {out_file}" in captured.out
    if hasattr(mock_server, "shutdown"):
        mock_server.shutdown()


def test_main_min_cases_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(gav, "_iter_target_tools", lambda host: ["session"])
    mock_server, mock_host = gav._mk_server()
    monkeypatch.setattr(mock_host, "TOOL_ACTIONS", {"session": ["list"]})
    monkeypatch.setattr(mock_host, "TOOL_ARG_SCHEMAS", {"session": {"binary_path": {"type": "string"}}})
    monkeypatch.setattr(gav, "_mk_server", lambda: (mock_server, mock_host))

    out_file = tmp_path / "out.json"
    test_args = [
        "generate_arg_action_variations.py",
        "--seed", "123",
        "--max-cases-per-tool", "2",
        "--min-total-cases", "100000",
        "--output", str(out_file),
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        gav.main()
    assert "expected at least 100000" in str(exc.value)
    if hasattr(mock_server, "shutdown"):
        mock_server.shutdown()
