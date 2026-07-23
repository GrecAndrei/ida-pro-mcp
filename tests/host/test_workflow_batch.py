from __future__ import annotations

from ida_pro_mcp.host.server.server import IDAMCPServer


def test_batch_reports_ok_false_when_any_call_errors(monkeypatch):
    server = IDAMCPServer()

    def fake_execute(tool_name, args):
        if tool_name == "idb":
            return {"ok": True, "action": "overview"}
        return {"ok": False, "error": {"code": "INVALID_ARGS", "message": "bad args"}}

    monkeypatch.setattr(server, "_execute_tool", fake_execute)
    monkeypatch.setattr(server, "_cache_next_page", lambda *_args, **_kwargs: _args[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_args, **_kwargs: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "calc", "arguments": {"action": "eval", "expr": "1+1"}},
            ],
            "continue_on_error": True,
        }
    )

    assert result["ok"] is False
    assert result["summary"]["errors"] == 1
    assert result["summary"]["ok"] == 1


def test_batch_reports_ok_true_when_all_calls_succeed(monkeypatch):
    server = IDAMCPServer()

    monkeypatch.setattr(
        server,
        "_execute_tool",
        lambda tool_name, args: {"ok": True, "tool": tool_name, "action": args.get("action")},
    )
    monkeypatch.setattr(server, "_cache_next_page", lambda *_args, **_kwargs: _args[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_args, **_kwargs: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "calc", "arguments": {"action": "eval", "expr": "1+1"}},
            ],
            "continue_on_error": True,
        }
    )

    assert result["ok"] is True
    assert result["summary"] == {
        "total": 2,
        "ok": 2,
        "errors": 0,
        "stopped_on_error": False,
    }


def test_batch_stops_on_first_error_by_default(monkeypatch):
    server = IDAMCPServer()
    calls_seen: list[str] = []

    def fake_execute(tool_name, args):
        calls_seen.append(tool_name)
        if tool_name == "calc":
            return {"ok": False, "error": {"code": "INVALID_ARGS", "message": "bad args"}}
        return {"ok": True, "tool": tool_name}

    monkeypatch.setattr(server, "_execute_tool", fake_execute)
    monkeypatch.setattr(server, "_cache_next_page", lambda *_args, **_kwargs: _args[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_args, **_kwargs: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "calc", "arguments": {"action": "eval", "expr": "1+1"}},
                {"name": "idb", "arguments": {"action": "overview"}},
            ],
        }
    )

    assert result["ok"] is False
    assert calls_seen == ["idb", "calc"]
    assert result["summary"]["stopped_on_error"] is True
    assert len(result["results"]) == 2
