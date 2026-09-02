"""Cross-mode coverage for noisy-client argument normalization and paging."""

import time

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_args as args_mod
from ida_pro_mcp.host.server.server_args import ServerArgsMixin


class _Harness(ServerArgsMixin):
    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 60


def test_action_cleaning_and_tail_parsing_cover_client_wrappers(monkeypatch):
    h = _Harness()
    assert h._clean_action_text(' action: "find" ') == "find"
    assert h._clean_action_text("find pattern='a b' limit=10") == "find pattern='a b' limit=10"
    assert h._clean_action_text("()") == ""
    assert h._parse_action_tail_tokens('pattern="a b" limit=10 bare') == {
        "pattern": "a b",
        "limit": "10",
        "_positional": "bare",
    }

    original_split = args_mod.shlex.split
    monkeypatch.setattr(args_mod.shlex, "split", lambda _tail: (_ for _ in ()).throw(ValueError("bad quote")))
    try:
        assert h._parse_action_tail_tokens("pattern='broken") == {"pattern": "broken"}
    finally:
        args_mod.shlex.split = original_split


def test_tool_argument_normalization_composes_json_nested_alias_and_positional_forms():
    h = _Harness()
    nested = h._normalize_tool_call_args("search", {"action": {"action": "find", "limit": "[10]"}})
    assert nested["action"] == "find"
    assert nested["limit"] == 10

    parsed = h._normalize_tool_call_args(
        "search",
        {"action": '{"action":"find","pattern":"[recv]"}', "offset": "010"},
    )
    assert parsed["action"] == "find"
    assert parsed["pattern"] == "recv"
    assert parsed["offset"] == 10

    wiki = h._normalize_tool_call_args("wiki", {"action": "read architecture"})
    assert wiki == {"action": "read", "topic": "architecture"}
    positional = h._normalize_tool_call_args("funcs", {"subaction": "metrics"})
    assert positional["action"] == "metrics"
    addrs = h._normalize_tool_call_args("code", {"action": "diff_functions", "addrs": "[0x10, 0x20]"})
    assert addrs["addrs"] == ["0x10", "0x20"]


def test_field_normalization_preserves_declarations_and_rejects_bad_integers():
    h = _Harness()
    declaration = h._normalize_field_variants("types", {"decl": "int *p;", "limit": "5"})
    assert declaration["decl"] == "int *p;"
    assert declaration["limit"] == 5
    result = h._normalize_field_variants("search", {"limit": "not-an-int"})
    assert result["code"] == MCPError.INVALID_ARGS
    assert "decimal integer" in result["hint"]
    union = h._normalize_field_variants("session", {"baseaddr": "not-a-number"})
    assert union["baseaddr"] == "not-a-number"


def test_next_cache_pruning_and_invalid_payloads_are_safe(monkeypatch):
    h = _Harness()
    h._next_cache = {
        "OLD": {"created_at": 0},
        "NEW": {"created_at": time.time()},
    }
    monkeypatch.setattr(args_mod.time, "time", lambda: 1000.0)
    h._prune_next_cache()
    assert "OLD" not in h._next_cache
    assert "NEW" in h._next_cache

    assert h._cache_next_page("search", {}, None) is None
    error = make_error(MCPError.INVALID_ARGS, "bad")
    assert h._cache_next_page("search", {}, error) is error
    assert h._cache_next_page("search", {"action": "find"}, {"truncated": False}) == {"truncated": False}
    post = {"truncated": True, "_post_processed": True}
    assert h._cache_next_page("search", {"action": "find"}, post) is post
    malformed = {"truncated": True, "offset": "bad", "count": 1, "total": 2}
    assert h._cache_next_page("search", {"action": "find"}, malformed) is malformed
    no_action = {"truncated": True, "offset": 0, "count": 1, "total": 2}
    assert h._cache_next_page("search", {}, no_action) is no_action


def test_next_cache_mints_explicit_offset_and_strips_client_tokens(monkeypatch):
    h = _Harness()

    class UUID:
        hex = "abcdef1234567890"

    def uuid4():
        return UUID()

    monkeypatch.setattr(args_mod.uuid, "uuid4", uuid4)
    payload = {"truncated": True, "offset": 2, "count": 3, "total": 20}
    out = h._cache_next_page(
        "search",
        {"action": "find", "next_token": "old", "token": "old", "cursor": "old", "pattern": "x"},
        payload,
    )
    assert out["next_token"] == "ABCDEF123456"
    assert out["next_offset"] == 5
    cached = h._next_cache["ABCDEF123456"]
    assert cached["args"] == {"action": "find", "pattern": "x"}

    explicit = {"truncated": True, "offset": 2, "count": 3, "total": 20, "next_offset": "9"}
    assert h._cache_next_page("search", {"action": "find"}, explicit)["next_offset"] == 9
    backwards = {"truncated": True, "offset": 9, "count": 3, "total": 20, "next_offset": 8}
    assert h._cache_next_page("search", {"action": "find"}, backwards) is backwards
