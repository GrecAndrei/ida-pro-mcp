"""Behavioral tests for the small, safety-relevant auto-nudge surface."""

from __future__ import annotations

from ida_pro_mcp.host.auto_nudge import get_reroute, record_tool_call


def test_static_reroutes_preserve_arguments_and_replace_only_action():
    args = {"query": "mov", "limit": 7}
    result = get_reroute("search", "bytes", args)

    assert result == ("search", {"query": "mov", "limit": 7, "action": "string"})
    assert args == {"query": "mov", "limit": 7}


def test_static_reroute_map_covers_common_search_aliases():
    assert get_reroute("search", "text", {}) == ("search", {"action": "name"})
    assert get_reroute("search", "instruction", {"limit": 3}) == (
        "search",
        {"limit": 3, "action": "insns"},
    )


def test_disasm_reroute_requires_explicit_bytes_and_intent(monkeypatch):
    base = {"type": "bytes", "address": "0x401000"}
    assert get_reroute("memory", "read", base) is None

    result = get_reroute("memory", "read", {**base, "as_code": True})
    assert result == (
        "code",
        {"type": "bytes", "address": "0x401000", "as_code": True,
         "action": "disasm", "limit": 50},
    )

    monkeypatch.setenv("IDA_MCP_DISABLE_REROUTE_RULES", "1")
    assert get_reroute("memory", "read", {**base, "disasm": True}) is None


def test_reroute_rejects_near_misses_and_none_arguments(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_REROUTE_RULES", raising=False)
    assert get_reroute("memory", "write", None) is None
    assert get_reroute("memory", "read", {"type": "u32", "decode": True}) is None
    assert get_reroute("other", "bytes", {}) is None


def test_record_tool_call_is_a_stable_noop_for_fallback_callers():
    assert record_tool_call("idb", "search", "find", addr="0x401000", query="main") is None
