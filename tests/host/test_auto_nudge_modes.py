"""Behavior coverage for deterministic action reroutes."""

from __future__ import annotations

from ida_pro_mcp.host import auto_nudge


def test_static_reroutes_preserve_arguments_and_replace_action():
    original = {"action": "bytes", "pattern": "abc", "limit": 3}
    result = auto_nudge.get_reroute("search", "bytes", original)
    assert result == ("search", {"action": "string", "pattern": "abc", "limit": 3})
    assert original["action"] == "bytes"
    assert auto_nudge.get_reroute("search", "text", {})[1]["action"] == "name"
    assert auto_nudge.get_reroute("search", "instruction", {})[1]["action"] == "insns"


def test_disassembly_reroute_requires_explicit_bytes_intent(monkeypatch):
    args = {"type": "bytes", "as_code": True}
    tool, corrected = auto_nudge.get_reroute("memory", "read", args)
    assert (tool, corrected["action"], corrected["limit"]) == ("code", "disasm", 50)
    assert auto_nudge.get_reroute("memory", "read", {"type": "u8", "as_code": True}) is None
    assert auto_nudge.get_reroute("memory", "write", args) is None

    monkeypatch.setenv("IDA_MCP_DISABLE_REROUTE_RULES", "1")
    assert auto_nudge.get_reroute("memory", "read", args) is None
    assert auto_nudge._rule_disasm_reroute("memory", "read", {"type": "bytes", "decode": "yes"}) is True
    assert auto_nudge._rule_disasm_reroute("memory", "read", {"type": "bytes"}) is False


def test_unknown_calls_and_recording_are_safe():
    assert auto_nudge.get_reroute("unknown", "action", None) is None
    auto_nudge.record_tool_call("sample.i64", "code", "disasm", addr="0x401000", query="x")
