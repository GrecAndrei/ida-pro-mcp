"""Deep offline coverage for server argument and continuation normalization."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_args as args_module
from ida_pro_mcp.host.server.server_args import ServerArgsMixin


class _Harness(ServerArgsMixin):
    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 60
        self.current_session = SimpleNamespace(session_id="CURRENT")


def test_scope_resolution_fails_closed_across_owner_resolver_and_current_session():
    host = _Harness()

    def fail_owner():
        raise RuntimeError("owner unavailable")

    host._truncation_owner_id = fail_owner
    host._resolve_session_from_idb_ref = lambda _ref: SimpleNamespace(session_id="TARGET")
    assert host._next_cache_scope({"idb": "idb-ref"}) == ("TARGET", "")

    host._resolve_session_from_idb_ref = lambda _ref: (_ for _ in ()).throw(
        RuntimeError("session unavailable")
    )
    assert host._next_cache_scope({"idb": "idb-ref"}) == ("CURRENT", "")

    host._resolve_session_from_idb_ref = None
    assert host._next_cache_scope({"idb": "idb-ref"}) == ("CURRENT", "")

    class _BrokenCurrent(_Harness):
        @property
        def current_session(self):
            raise RuntimeError("current session unavailable")

        @current_session.setter
        def current_session(self, _value):
            pass

    broken = _BrokenCurrent()
    broken._truncation_owner_id = lambda: "owner"
    assert broken._next_cache_scope({}) == ("", "owner")


def test_action_parser_and_cleaner_cover_empty_duplicates_and_json_wrappers(
    monkeypatch,
):
    host = _Harness()
    assert host._parse_action_tail_tokens("") == {}
    assert host._parse_action_tail_tokens("key=one key=two bare ()") == {
        "key": "one",
        "_positional": "bare",
    }
    assert host._clean_action_text("") == ""
    assert host._clean_action_text('"{"action":"find"}"') == '{"action":"find"}'

    monkeypatch.setattr(
        args_module.shlex,
        "split",
        lambda _tail: (_ for _ in ()).throw(ValueError("bad quote")),
    )
    assert host._parse_action_tail_tokens("bare value") == {
        "_positional": "bare value"
    }


def test_field_variants_cover_passthrough_scalars_bracketed_values_and_lists():
    host = _Harness()
    assert host._normalize_field_variants("search", "not-a-dict") == "not-a-dict"
    assert host._normalize_field_variants("search", {"query": "[[[[needle]]]]"})["query"] == "needle"
    assert host._normalize_field_variants("search", {"query": "[[[[needle,other]]]]"})["query"] == "[needle,other]"
    assert host._normalize_field_variants("search", {"query": ""})["query"] == ""
    assert host._normalize_field_variants("code", {"addrs": "0x10, 0x20"})["addrs"] == [
        "0x10",
        "0x20",
    ]
    assert host._normalize_field_variants("code", {"addrs": "[[[[0x10, 0x20]]]]"})["addrs"] == [
        "[0x10",
        "0x20]",
    ]
    assert host._normalize_field_variants("code", {"addrs": "[[[[0x10]]]]"})["addrs"] == "0x10"
    assert host._normalize_field_variants("code", {"addrs": "[]"})["addrs"] == "[]"


def test_tool_normalizer_covers_bad_json_tail_non_string_keys_and_positional_fields(
    monkeypatch,
):
    host = _Harness()
    args = {1: "raw", "action": 4}
    result = host._normalize_tool_call_args("search", args)
    assert result["code"] == "INVALID_ARGS"

    malformed_json = host._normalize_tool_call_args("search", {"action": '{"action":}'})
    assert malformed_json["action"] == 'action":'

    empty_action = host._normalize_tool_call_args("search", {"action": "[]"})
    assert "action" not in empty_action

    with monkeypatch.context() as isolated:
        isolated.setattr(
            host,
            "_parse_action_tail_tokens",
            lambda _tail: {1: "tail-value"},
        )
        with_non_string_tail = host._normalize_tool_call_args(
            "search", {"action": "find value"}
        )
    assert with_non_string_tail[1] == "tail-value"

    search_tool = next(
        name for name, actions in args_module.TOOL_ACTIONS.items() if "search" in actions
    )
    search = host._normalize_tool_call_args(
        search_tool, {"action": "search needle"}
    )
    assert search["query"] == "needle"

    for field in ("addrs", "addr", "pattern"):
        tool = next(
            (
                name
                for name, schema in args_module.TOOL_ARG_SCHEMAS.items()
                if field in schema and args_module.TOOL_ACTIONS.get(name)
            ),
            None,
        )
        if tool is None:
            continue
        action = args_module.TOOL_ACTIONS[tool][0]
        normalized = host._normalize_tool_call_args(
            tool, {"action": f"{action} positional-value"}
        )
        assert normalized.get(field) == "positional-value"

    truncation = host._normalize_tool_call_args(
        "truncation", {"action": "continue positional-pattern"}
    )
    assert truncation["pattern"] == "positional-pattern"

    no_alias_tool = next(
        (
            name
            for name, actions in args_module.TOOL_ACTIONS.items()
            if actions and not args_module.ARG_ALIASES_BY_TOOL.get(name)
        ),
        None,
    )
    if no_alias_tool:
        normalized = host._normalize_tool_call_args(
            no_alias_tool,
            {"action": f"{args_module.TOOL_ACTIONS[no_alias_tool][0]} key=value"},
        )
        assert normalized["key"] == "value"


def test_normalizer_subaction_and_action_json_payload_fallbacks(monkeypatch):
    host = _Harness()
    tool = next(name for name, actions in args_module.TOOL_ACTIONS.items() if actions)
    action = args_module.TOOL_ACTIONS[tool][0]
    assert host._normalize_tool_call_args(tool, {"subaction": action})["action"] == action
    assert "action" not in host._normalize_tool_call_args(tool, {"subaction": "unknown"})

    monkeypatch.setattr(host, "_clean_action_text", lambda _value: "")
    assert "action" not in host._normalize_tool_call_args(tool, {"action": "ignored"})


def test_cache_next_page_rejects_bad_next_offset_and_uses_explicit_scope(monkeypatch):
    host = _Harness()
    malformed = {
        "truncated": True,
        "offset": 0,
        "count": 1,
        "total": 3,
        "next_offset": "bad",
    }
    assert host._cache_next_page("search", {"action": "find"}, malformed) is malformed

    class _UUID:
        hex = "0123456789abcdef"

    monkeypatch.setattr(args_module.uuid, "uuid4", _UUID)
    page = {"truncated": True, "offset": None, "count": 1, "total": 10}
    result = host._cache_next_page(
        "search",
        {"action": "find", "offset": 4},
        page,
        scope=("SESSION", "OWNER"),
    )
    assert result["next_offset"] == 5
    assert host._next_cache["0123456789AB"]["session_id"] == "SESSION"
