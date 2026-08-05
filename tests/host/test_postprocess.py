"""Tests for the post-processing filter pipeline.

Tests the pure functions from postprocess.py (grep, head/tail, pick,
field auto-detection) and the integration through _execute_tool with
mocked IDA calls.

Contract:
- Post-processing params are orthogonal to tool actions.
- grep filters structured items by searching all string values within each.
- head/tail/offset/limit slice items.
- pick projects top-level response fields.
- next_token auto-recovers action+args from cache.
- _post_processed, _field, _count metadata added to results.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None

importlib.import_module("ida_pro_mcp.host")

from ida_pro_mcp.host.server.postprocess import (  # noqa: E402
    PP_KEYS,
    apply_grep,
    apply_head_tail,
    apply_pick,
    apply_post_processing,
    extract_post_process_params,
    has_post_process,
    item_search_text,
    resolve_list_field,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _search_payload(n: int) -> dict:
    """A realistic source payload with a list under 'matches'."""
    return {
        "ok": True,
        "action": "find",
        "matches": [
            {
                "addr": 0x1000 + i,
                "name": f"sub_{i}",
                "tag": "crypto" if i % 2 == 0 else "net",
            }
            for i in range(n)
        ],
        "count": n,
        "total": n,
    }


# ---------------------------------------------------------------------------
# TestExtractParams
# ---------------------------------------------------------------------------

class TestExtractParams:
    def test_splits_pp_keys_from_tool_args(self):
        args = {"action": "find", "pattern": "recv", "grep": "memcpy", "limit": 5, "offset": 2}
        tool_args, pp = extract_post_process_params(args)
        assert tool_args == {"action": "find", "pattern": "recv"}
        assert pp == {"grep": "memcpy", "limit": 5, "offset": 2}

    def test_no_pp_keys_passthrough(self):
        args = {"action": "list", "count": 10}
        tool_args, pp = extract_post_process_params(args)
        assert tool_args == args
        assert pp == {}

    def test_all_pp_keys_recognized(self):
        args = dict.fromkeys(PP_KEYS, "x")
        args["action"] = "find"
        tool_args, pp = extract_post_process_params(args)
        assert "action" in tool_args
        assert all(k in pp for k in PP_KEYS)


# ---------------------------------------------------------------------------
# TestResolveListField
# ---------------------------------------------------------------------------

class TestResolveListField:
    def test_explicit_field(self):
        payload = {"matches": [1, 2, 3], "count": 3}
        items, field = resolve_list_field(payload, "matches")
        assert items == [1, 2, 3]
        assert field == "matches"

    def test_auto_detect_preferred_field(self):
        payload = {"functions": [1, 2], "count": 2}
        items, field = resolve_list_field(payload, None)
        assert items == [1, 2]
        assert field == "functions"

    def test_fallback_to_largest_list(self):
        payload = {"a": [1], "b": [1, 2, 3]}
        items, field = resolve_list_field(payload, None)
        assert items == [1, 2, 3]
        assert field == "b"

    def test_non_dict_payload(self):
        items, field = resolve_list_field([1, 2, 3], None)
        assert items == [1, 2, 3]
        assert field == "payload"

    def test_string_payload_splits_lines(self):
        items, field = resolve_list_field({"content": "a\nb\nc"}, "content")
        assert items == ["a", "b", "c"]

    def test_empty_payload(self):
        items, field = resolve_list_field({}, None)
        assert items == []
        assert field == "payload"


# ---------------------------------------------------------------------------
# TestGrep
# ---------------------------------------------------------------------------

class TestGrep:
    def test_substring_match(self):
        items = _search_payload(10)["matches"]
        result = apply_grep(items, {"grep": "crypto"})
        assert len(result) == 5

    def test_regex_match(self):
        items = _search_payload(10)["matches"]
        result = apply_grep(items, {"grep": r"sub_[0-4]", "grep_regex": True})
        assert len(result) == 5

    def test_invert(self):
        items = _search_payload(10)["matches"]
        result = apply_grep(items, {"grep": "crypto", "grep_invert": True})
        assert len(result) == 5

    def test_case_sensitive(self):
        items = [{"name": "Foo"}, {"name": "foo"}]
        result = apply_grep(items, {"grep": "Foo", "grep_case": True})
        assert len(result) == 1

    def test_case_insensitive_default(self):
        items = [{"name": "Foo"}, {"name": "foo"}]
        result = apply_grep(items, {"grep": "foo"})
        assert len(result) == 2

    def test_searches_nested_values(self):
        items = [{"data": {"inner": "needle_here"}}]
        result = apply_grep(items, {"grep": "needle"})
        assert len(result) == 1

    def test_empty_pattern_returns_all(self):
        items = _search_payload(5)["matches"]
        result = apply_grep(items, {})
        assert len(result) == 5


# ---------------------------------------------------------------------------
# TestHeadTail
# ---------------------------------------------------------------------------

class TestHeadTail:
    def test_head_first_n(self):
        items = list(range(10))
        result, _ = apply_head_tail(items, {"head": 3})
        assert result == [0, 1, 2]

    def test_tail_last_n(self):
        items = list(range(10))
        result, _ = apply_head_tail(items, {"tail": 3})
        assert result == [7, 8, 9]

    def test_offset_skips(self):
        items = list(range(10))
        result, _ = apply_head_tail(items, {"head": 3, "offset": 5})
        assert result == [5, 6, 7]

    def test_limit_alias(self):
        items = list(range(10))
        result, _ = apply_head_tail(items, {"limit": 4})
        assert result == [0, 1, 2, 3]

    def test_no_filter_returns_all(self):
        items = list(range(10))
        result, _ = apply_head_tail(items, {})
        assert result == items

    def test_tail_with_offset(self):
        items = list(range(10))
        result, offset = apply_head_tail(items, {"tail": 3, "offset": 2})
        # offset 2 first → [2,3,4,5,6,7,8,9], then tail 3 → [7,8,9]
        assert result == [7, 8, 9]


# ---------------------------------------------------------------------------
# TestPick
# ---------------------------------------------------------------------------

class TestPick:
    def test_projects_fields(self):
        payload = {"ok": True, "items": [1, 2], "count": 2, "meta": "x"}
        result = apply_pick(payload, {"pick": ["items", "count"]})
        assert set(result.keys()) == {"items", "count"}
        assert result["items"] == [1, 2]

    def test_string_comma_separated(self):
        payload = {"ok": True, "items": [1], "count": 1}
        result = apply_pick(payload, {"pick": "items,count"})
        assert set(result.keys()) == {"items", "count"}

    def test_missing_fields_ignored(self):
        payload = {"ok": True}
        result = apply_pick(payload, {"pick": ["nope"]})
        assert result == {}

    def test_no_pick_returns_original(self):
        payload = {"ok": True, "items": [1]}
        result = apply_pick(payload, {})
        assert result == payload


# ---------------------------------------------------------------------------
# TestPipelineComposition
# ---------------------------------------------------------------------------

class TestPipelineComposition:
    def test_grep_then_head(self):
        payload = _search_payload(10)
        result = apply_post_processing(payload, {"grep": "crypto", "head": 2})
        items = result["matches"]
        assert len(items) == 2
        assert result["_post_processed"] is True
        assert result["_count"] == 2

    def test_full_grep_head_pick(self):
        payload = _search_payload(10)
        result = apply_post_processing(
            payload, {"grep": "sub", "head": 3, "pick": ["ok", "matches"]}
        )
        assert "ok" in result
        assert "matches" in result
        assert len(result["matches"]) == 3
        # count/total should be absent since they weren't picked
        assert "count" not in result

    def test_text_field_populated(self):
        payload = _search_payload(3)
        result = apply_post_processing(payload, {"head": 2})
        assert "_text" in result
        assert result["_count"] == 2

    def test_error_passthrough(self):
        payload = {"ok": False, "error": {"code": "ERR", "message": "fail"}}
        result = apply_post_processing(payload, {"grep": "x"})
        # Error results pass through without modification
        assert result == payload

    def test_non_dict_wrapped(self):
        result = apply_post_processing([1, 2, 3], {"head": 2})
        assert result["_count"] == 2


# ---------------------------------------------------------------------------
# TestItemSearchText
# ---------------------------------------------------------------------------

class TestItemSearchText:
    def test_flat_dict(self):
        texts = item_search_text({"name": "foo", "addr": "0x1000"})
        assert "foo" in texts
        assert "0x1000" in texts

    def test_nested(self):
        texts = item_search_text({"data": {"inner": "deep"}})
        assert "deep" in texts

    def test_list(self):
        texts = item_search_text(["a", "b", {"c": "d"}])
        assert "a" in texts
        assert "d" in texts

    def test_scalar(self):
        texts = item_search_text(42)
        assert "42" in texts


# ---------------------------------------------------------------------------
# TestNextContinuation
# ---------------------------------------------------------------------------

class TestNextContinuation:
    def test_continuation_advances_offset(self):
        """Simulate the dispatch-level next_token flow."""
        from ida_pro_mcp.host.server.server_args import ServerArgsMixin
        from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin

        class _Harness(ServerArgsMixin, ServerDispatchMixin):
            def __init__(self):
                self._next_cache = {}
                self._next_cache_ttl_seconds = 1800
                self._pending_pp = {}
                self.current_session = None

        h = _Harness()

        # Simulate caching a page
        base_args = {"action": "find", "pattern": "recv"}
        pp = {"head": 3, "offset": 0}
        result = {"ok": True, "matches": list(range(10)), "_count": 3, "_total": 10, "_post_processed": True}
        h._cache_post_process_next("search", base_args, pp, result)
        token = result.get("next_token")
        assert token

        # Simulate continuation
        h._pending_pp = {"next_token": token}
        # Mock call_tool to return the full payload
        h.call_tool = lambda tn, ip, **kw: _search_payload(10)
        h.current_session = type("S", (), {"idb_path": "/tmp/test.idb"})()

        cont_result = h._handle_next_continuation("search", token, {"next_token": token})
        assert cont_result["ok"] is True
        assert cont_result["continued_from"] == token

    def test_unknown_token_error(self):
        from ida_pro_mcp.host.server.server_args import ServerArgsMixin
        from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin

        class _Harness(ServerArgsMixin, ServerDispatchMixin):
            def __init__(self):
                self._next_cache = {}
                self._next_cache_ttl_seconds = 1800

        h = _Harness()
        result = h._handle_next_continuation("search", "NOPE", {})
        assert result.get("ok") is not True
        assert result.get("code") == "TRUNCATION_TOKEN_INVALID"


# ---------------------------------------------------------------------------
# TestGrepEdgeCases
# ---------------------------------------------------------------------------

class TestGrepEdgeCases:
    def test_regex_error_raises(self):
        items = [{"name": "foo"}]
        with pytest.raises(ValueError, match="Invalid grep regex"):
            apply_grep(items, {"grep": "[invalid", "grep_regex": True})

    def test_empty_items(self):
        result = apply_grep([], {"grep": "x"})
        assert result == []

    def test_empty_pattern_returns_all(self):
        items = [{"name": "a"}, {"name": "b"}]
        result = apply_grep(items, {})
        assert result == items

    def test_no_match_returns_empty(self):
        items = [{"name": "foo"}]
        result = apply_grep(items, {"grep": "zzz"})
        assert result == []

    def test_grep_on_string_items(self):
        items = ["hello world", "goodbye", "hello there"]
        result = apply_grep(items, {"grep": "hello"})
        assert len(result) == 2

    def test_grep_invert_with_regex(self):
        items = [{"name": "abc"}, {"name": "def"}, {"name": "ghi"}]
        result = apply_grep(items, {"grep": "^a", "grep_regex": True, "grep_invert": True})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# TestHeadTailEdgeCases
# ---------------------------------------------------------------------------

class TestHeadTailEdgeCases:
    def test_head_larger_than_items(self):
        items = [1, 2, 3]
        result, _ = apply_head_tail(items, {"head": 100})
        assert result == [1, 2, 3]

    def test_tail_larger_than_items(self):
        items = [1, 2, 3]
        result, _ = apply_head_tail(items, {"tail": 100})
        assert result == [1, 2, 3]

    def test_offset_beyond_items(self):
        items = [1, 2, 3]
        result, _ = apply_head_tail(items, {"head": 5, "offset": 10})
        assert result == []

    def test_tail_with_large_offset(self):
        items = list(range(20))
        result, _ = apply_head_tail(items, {"tail": 3, "offset": 15})
        # offset 15 → [15,16,17,18,19], tail 3 → [17,18,19]
        assert result == [17, 18, 19]

    def test_empty_items(self):
        result, _ = apply_head_tail([], {"head": 5})
        assert result == []


# ---------------------------------------------------------------------------
# TestPickEdgeCases
# ---------------------------------------------------------------------------

class TestPickEdgeCases:
    def test_string_comma_separated(self):
        payload = {"ok": True, "items": [1], "count": 1}
        result = apply_pick(payload, {"pick": "items,count"})
        assert set(result.keys()) == {"items", "count"}

    def test_non_dict_payload(self):
        result = apply_pick([1, 2, 3], {"pick": ["a"]})
        assert result == [1, 2, 3]

    def test_empty_pick_list(self):
        payload = {"ok": True}
        result = apply_pick(payload, {"pick": []})
        assert result == payload

    def test_pick_preserves_order(self):
        payload = {"z": 1, "a": 2, "m": 3}
        result = apply_pick(payload, {"pick": ["a", "z"]})
        assert list(result.keys()) == ["a", "z"]


# ---------------------------------------------------------------------------
# TestResolveListFieldEdgeCases
# ---------------------------------------------------------------------------

class TestResolveListFieldEdgeCases:
    def test_explicit_field_missing(self):
        payload = {"items": [1, 2]}
        items, field = resolve_list_field(payload, "nonexistent")
        assert items == []
        assert field == "nonexistent"

    def test_explicit_field_non_list(self):
        payload = {"count": 5}
        items, field = resolve_list_field(payload, "count")
        assert items == []
        assert field == "count"

    def test_auto_detect_prefers_first_preferred(self):
        payload = {"results": [1], "functions": [2, 3]}
        items, field = resolve_list_field(payload, None)
        assert items == [1]
        assert field == "results"

    def test_none_payload(self):
        items, field = resolve_list_field(None, None)
        assert items == []
        assert field == "payload"

    def test_string_payload(self):
        items, field = resolve_list_field("line1\nline2\nline3", None)
        # Bare string is not a dict, so it's wrapped in a list as-is
        assert field == "payload"


# ---------------------------------------------------------------------------
# TestItemSearchTextEdgeCases
# ---------------------------------------------------------------------------

class TestItemSearchTextEdgeCases:
    def test_empty_dict(self):
        texts = item_search_text({})
        assert texts == []

    def test_none_value(self):
        texts = item_search_text({"a": None})
        # None is converted to string "None"
        assert any("None" in t for t in texts) or texts == []

    def test_deeply_nested(self):
        item = {"a": {"b": {"c": {"d": "deep"}}}}
        texts = item_search_text(item)
        assert "deep" in texts

    def test_mixed_types(self):
        item = {"name": "foo", "count": 42, "flag": True, "items": [1, "two"]}
        texts = item_search_text(item)
        assert "foo" in texts
        assert "42" in texts

    def test_empty_list(self):
        texts = item_search_text([])
        assert texts == []


# ---------------------------------------------------------------------------
# TestPipelineEdgeCases
# ---------------------------------------------------------------------------

class TestPipelineEdgeCases:
    def test_no_filters_passthrough(self):
        payload = {"ok": True, "items": [1, 2, 3]}
        result = apply_post_processing(payload, {})
        assert result == payload

    def test_error_with_ok_false(self):
        payload = {"ok": False, "error": {"code": "ERR"}}
        result = apply_post_processing(payload, {"grep": "x"})
        assert result == payload

    def test_error_with_error_dict(self):
        payload = {"error": {"code": "ERR", "message": "fail"}}
        result = apply_post_processing(payload, {"head": 5})
        assert result == payload

    def test_grep_on_non_dict_list(self):
        payload = {"ok": True, "results": "line1\nline2\nline3"}
        result = apply_post_processing(payload, {"grep": "line1", "field": "results"})
        assert result["_count"] == 1

    def test_head_then_pick_combined(self):
        payload = _search_payload(10)
        result = apply_post_processing(payload, {"head": 5, "pick": ["ok", "matches"]})
        assert "ok" in result
        assert len(result["matches"]) == 5
        assert "count" not in result

    def test_grep_head_tail_pipeline_order(self):
        """grep filters first, then head/tail slices."""
        payload = _search_payload(10)
        result = apply_post_processing(payload, {"grep": "crypto", "tail": 2})
        # 5 crypto items, tail 2 → last 2
        assert result["_count"] == 2

    def test_offset_with_grep(self):
        payload = _search_payload(10)
        result = apply_post_processing(payload, {"grep": "sub", "head": 3, "offset": 5})
        # All 10 match "sub", offset 5 → [5,6,7,8,9], head 3 → [5,6,7]
        assert result["_count"] == 3

    def test_non_dict_non_list_payload(self):
        result = apply_post_processing("just a string", {"head": 5})
        assert result["ok"] is True
        assert "_post_processed" in result
