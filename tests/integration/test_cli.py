import json
import os
import sys

from tests._isolated_repo_loader import load_package_module

cli_mod = load_package_module("cli")
_normalize_tool_result = cli_mod._normalize_tool_result


def test_normalize_tool_result_single_json_text_block():
    response = {
        "result": {
            "content": [{"type": "text", "text": '{"ok": true, "value": 7}'}],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {"ok": True, "value": 7}


def test_normalize_tool_result_preserves_multiple_content_blocks():
    response = {
        "result": {
            "content": [
                {"type": "text", "text": '{"ok": true, "value": 7}'},
                {"type": "text", "text": "follow-up note"},
            ],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {
        "content": [
            {"ok": True, "value": 7},
            {"text": "follow-up note", "isError": False},
        ],
        "isError": False,
    }


def test_normalize_tool_result_keeps_non_text_items():
    response = {
        "result": {
            "content": [
                {"type": "image", "url": "file:///tmp/plot.png"},
                {"type": "text", "text": "done"},
            ],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {
        "content": [
            {"type": "image", "url": "file:///tmp/plot.png"},
            {"text": "done", "isError": False},
        ],
        "isError": False,
    }


def test_cli_intelligence_status_shortcut(monkeypatch, capsys):
    calls = []

    class _FakeClient:
        def __init__(self, _cmd):
            pass

        def call(self, method, params=None, request_id=None):
            calls.append((method, params, request_id))
            if method == "initialize":
                return {"result": {"ok": True}}
            return {
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"ok": True, "echo": params})}],
                    "isError": False,
                }
            }

        def close(self):
            return None

    monkeypatch.setattr(cli_mod, "MCPStdioClient", _FakeClient)
    monkeypatch.setattr(sys, "argv", ["ida-pro-mcp-cli", "intelligence", "status"])
    rc = cli_mod.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "intelligence_status" in out
    # Tool name was extracted from `agent` to `intelligence` during the dedup pass.
    # json.dumps emits no whitespace by default so look for compact "name":"intelligence".
    assert '"name":"intelligence"' in out
    # initialize + tools/call
    assert any(c[0] == "tools/call" for c in calls)


def test_cli_capsule_passthrough(monkeypatch):
    captured = {}

    def _fake_capsule_main(argv):
        captured["argv"] = list(argv)
        return 0

    cap_cli = load_package_module("capsule.cli")

    monkeypatch.setattr(cap_cli, "main", _fake_capsule_main)
    monkeypatch.setattr(sys, "argv", [
        "ida-pro-mcp-cli",
        "capsule",
        "semantic-summary",
        "project.sideband",
        "--json",
    ])
    rc = cli_mod.main()
    assert rc == 0
    assert captured["argv"] == ["semantic-summary", "project.sideband", "--json"]
