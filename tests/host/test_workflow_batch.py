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
