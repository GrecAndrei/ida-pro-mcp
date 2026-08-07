"""Tests for the ephemeral CLI (``ida_pro_mcp.cli``).

The CLI is a thin JSON-safe wrapper around the stdio MCP server.  These tests
drive it against a tiny fake MCP server process so the real host/IDA stack is
never started; the only boundary that is faked is the spawned process and the
daemon's AF_UNIX socket.
"""

import json
import socket
import sys
import textwrap

import pytest

from ida_pro_mcp import cli

# ---------------------------------------------------------------------------
# Fake stdio MCP server (process boundary)
# ---------------------------------------------------------------------------

_FAKE_SERVER = textwrap.dedent(
    """\
    import json
    import sys

    for line in sys.stdin:
        req = json.loads(line)
        method = req.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": req["params"].get("protocolVersion"),
                "capabilities": {},
                "serverInfo": {"name": "fake-mcp", "version": "0"},
            }
        elif method == "tools/call":
            params = req.get("params", {})
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "ok": True,
                                "tool": params.get("name"),
                                "arguments": params.get("arguments"),
                            }
                        ),
                    }
                ],
                "isError": False,
            }
        else:
            result = {"echoed_method": method, "echoed_params": req.get("params")}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\\n")
        sys.stdout.flush()
    """
)


@pytest.fixture
def fake_server_cmd(tmp_path, monkeypatch):
    """Point the CLI at a fake MCP server process."""
    script = tmp_path / "fake_mcp_server.py"
    script.write_text(_FAKE_SERVER, encoding="utf-8")
    monkeypatch.setattr(cli, "_server_cmd", lambda: [sys.executable, "-u", str(script)])
    return str(script)


# ---------------------------------------------------------------------------
# _normalize_tool_result
# ---------------------------------------------------------------------------


def test_normalize_single_json_item_is_unwrapped():
    response = {
        "result": {
            "content": [{"type": "text", "text": json.dumps({"ok": True, "count": 3})}],
            "isError": False,
        }
    }
    assert cli._normalize_tool_result(response) == {"ok": True, "count": 3}


def test_normalize_multiple_items_keeps_container():
    response = {
        "result": {
            "content": [
                {"type": "text", "text": json.dumps({"a": 1})},
                {"type": "text", "text": json.dumps({"b": 2})},
            ],
            "isError": False,
        }
    }
    normalized = cli._normalize_tool_result(response)
    assert normalized == {"content": [{"a": 1}, {"b": 2}], "isError": False}


def test_normalize_non_json_text_falls_back_to_text_item():
    response = {
        "result": {
            "content": [{"type": "text", "text": "not json"}],
            "isError": True,
        }
    }
    assert cli._normalize_tool_result(response) == {"text": "not json", "isError": True}


def test_normalize_non_text_items_pass_through():
    item = {"type": "resource", "uri": "x"}
    response = {"result": {"content": [item], "isError": False}}
    assert cli._normalize_tool_result(response) == item


def test_normalize_missing_or_non_list_content_returns_result():
    response = {"result": {"hello": "world"}}
    assert cli._normalize_tool_result(response) == {"hello": "world"}


def test_normalize_without_result_returns_response():
    response = {"error": {"code": -32601}}
    assert cli._normalize_tool_result(response) == response


# ---------------------------------------------------------------------------
# JSON payload helpers
# ---------------------------------------------------------------------------


def test_load_json_arg_none_or_empty_is_none():
    assert cli._load_json_arg(None, label="x") is None
    assert cli._load_json_arg("  ", label="x") is None


def test_load_json_arg_parses_object():
    assert cli._load_json_arg('{"action": "status"}', label="x") == {"action": "status"}


def test_load_json_arg_invalid_raises_system_exit():
    with pytest.raises(SystemExit, match="invalid JSON for payload"):
        cli._load_json_arg("{oops", label="payload")


def test_read_stdin_json_empty_is_none(monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("FakeStdin", (), {"read": lambda self: "  \n"})())
    assert cli._read_stdin_json(label="x") is None


def test_read_stdin_json_parses(monkeypatch):
    monkeypatch.setattr(
        sys, "stdin", type("FakeStdin", (), {"read": lambda self: '{"a": 1}'})()
    )
    assert cli._read_stdin_json(label="x") == {"a": 1}


def test_read_stdin_json_invalid_raises_system_exit(monkeypatch):
    monkeypatch.setattr(
        sys, "stdin", type("FakeStdin", (), {"read": lambda self: "[1, 2"})()
    )
    with pytest.raises(SystemExit, match="invalid JSON from stdin"):
        cli._read_stdin_json(label="payload")


# ---------------------------------------------------------------------------
# _StderrTail
# ---------------------------------------------------------------------------


def test_stderr_tail_keeps_only_last_limit_lines():
    tail = cli._StderrTail([], limit=5)
    for i in range(12):
        tail.push(f"line-{i}")
    assert tail.text() == "\n".join(f"line-{i}" for i in range(7, 12))


# ---------------------------------------------------------------------------
# Server command and daemon detection (socket boundary)
# ---------------------------------------------------------------------------


def test_server_cmd_runs_host_server_module():
    cmd = cli._server_cmd()
    assert cmd[:2] == [sys.executable, "-m"]
    assert cmd[2] == "ida_pro_mcp.host.server"


def test_daemon_is_running_false_when_socket_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_DAEMON_SOCKET", str(tmp_path / "missing.sock"))
    assert cli._daemon_is_running() is False


def test_daemon_is_running_true_when_socket_accepts(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "daemon.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(sock_path)
        listener.listen(1)
        monkeypatch.setattr(cli, "_DAEMON_SOCKET", sock_path)
        assert cli._daemon_is_running() is True
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# main() against the fake server
# ---------------------------------------------------------------------------


def test_main_tool_mode_sends_tool_call_and_unwraps_result(fake_server_cmd, capsys):
    assert cli.main(["tool", "session", '{"action": "status"}']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"ok": True, "tool": "session", "arguments": {"action": "status"}}


def test_main_rpc_mode_passes_method_and_params(fake_server_cmd, capsys):
    assert cli.main(["rpc", "tools/list", "{}"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == {"echoed_method": "tools/list", "echoed_params": {}}


def test_main_raw_mode_passes_full_request(fake_server_cmd, capsys):
    payload = {"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {"x": 1}}
    assert cli.main(["raw", json.dumps(payload)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == 9
    assert out["result"]["echoed_method"] == "ping"
    assert out["result"]["echoed_params"] == {"x": 1}


def test_main_tools_list_mode(fake_server_cmd, capsys):
    assert cli.main(["tools-list"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == {"echoed_method": "tools/list", "echoed_params": {}}


def test_main_pretty_flag_prints_indented_json(fake_server_cmd, capsys):
    assert cli.main(["rpc", "tools/list", "{}", "--pretty"]) == 0
    raw_out = capsys.readouterr().out
    assert "\n  " in raw_out
    json.loads(raw_out)  # still valid JSON


def test_main_tool_mode_requires_name(fake_server_cmd):
    with pytest.raises(SystemExit, match="tool mode requires a method/tool name"):
        cli.main(["tool"])


def test_main_invalid_payload_raises_system_exit(fake_server_cmd):
    with pytest.raises(SystemExit, match="invalid JSON for payload"):
        cli.main(["tool", "session", "{nope"])


def test_main_reads_payload_from_stdin(fake_server_cmd, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("FakeStdin", (), {"read": lambda self: '{"a": 1}'})())
    assert cli.main(["tool", "session", "--stdin-json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["tool"] == "session"
    assert out["arguments"] == {"a": 1}
