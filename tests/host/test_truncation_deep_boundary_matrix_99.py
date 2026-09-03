"""Deep offline coverage for continuation tokens and response truncation."""

from __future__ import annotations

from ida_pro_mcp.host.stores import truncation as t


def _token(response=None, fields=None, **scope):
    return t._store_truncation(
        response or {"items": ["Alpha", "beta"], "text": "Alpha beta"},
        fields
        or {
            "items": {"type": "list", "total": 2, "chunk_size": 1, "next_offset": 0},
            "text": {"type": "string", "total": 10, "chunk_size": 5, "next_offset": 0},
        },
        **scope,
    )


def test_nested_resolution_entry_scope_and_continuation_errors():
    assert t._get_nested(None, "x") is None
    assert t._get_nested({"x": 1}, "") is None
    assert t._get_nested({"x": [{"y": 2}]}, "x.0.y") == 2
    assert t._get_nested({"x": []}, "x.0") is None
    assert t._get_nested({"x": [1]}, "x.bad") is None
    assert t._get_nested({"x": 1}, "x.bad") is None
    assert t._store_truncation({"empty": None}, {"empty": {"type": "string"}})

    token = _token()
    assert t._get_entry(token, session_id="wrong") is None
    assert t._get_entry(token, owner_id="wrong") is None
    assert t._get_entry(token, session_id="S", owner_id="O") is None
    scoped = _token(session_id="S", owner_id="O")
    assert t._get_entry(scoped, session_id="S", owner_id="O") is not None
    assert t._get_entry(scoped, session_id="S") is None

    no_fields = _token()
    t._TRUNCATION_STORE[no_fields]["fields"] = {}
    assert t._resolve_field(t._TRUNCATION_STORE[no_fields], None)[1]["code"] == t.MCPError.TRUNCATION_TOKEN_INVALID
    multi = t._TRUNCATION_STORE[token]
    assert t._resolve_field(multi, None)[1]["code"] == t.MCPError.TRUNCATION_FIELD_MISSING
    assert t._resolve_field(multi, "missing")[1]["code"] == t.MCPError.TRUNCATION_FIELD_MISSING

    nested = _token(
        {"results": [{"code": "one"}]},
        {"results.0.code": {"type": "string", "total": 3, "chunk_size": 2}},
    )
    assert t._resolve_field(t._TRUNCATION_STORE[nested], "results.0.code")[2] == "one"
    t._TRUNCATION_STORE[nested]["values"] = {}
    t._TRUNCATION_STORE[nested]["response"] = {}
    assert t._resolve_field(t._TRUNCATION_STORE[nested], "results.0.code")[1]["code"] == t.MCPError.TRUNCATION_FIELD_MISSING

    assert t.continue_truncated("missing")["code"] == t.MCPError.TRUNCATION_TOKEN_INVALID
    assert t.continue_truncated(token)["code"] == t.MCPError.TRUNCATION_FIELD_MISSING
    list_bad = _token(fields={"items": {"type": "list", "total": 1, "chunk_size": 0}})
    assert t.continue_truncated(list_bad, field="items")["code"] == t.MCPError.INVALID_ARGS
    string_bad = _token(fields={"text": {"type": "string", "total": 1, "chunk_size": 0}})
    assert t.continue_truncated(string_bad, field="text")["code"] == t.MCPError.INVALID_ARGS
    unsupported = _token({"value": 1}, {"value": {"type": "number", "total": 1}})
    assert t.continue_truncated(unsupported, field="value")["code"] == t.MCPError.TRUNCATION_FIELD_MISSING


def test_continuation_peek_search_regex_safety_and_summary_shapes():
    token = _token(
        {"items": ["Alpha", {"name": "beta"}], "text": "Alpha\nbeta\ngamma"},
        {
            "items": {"type": "list", "total": 2, "chunk_size": 1, "next_offset": 0},
            "text": {"type": "string", "total": 16, "chunk_size": 5, "next_offset": 0},
        },
    )
    assert t.continue_truncated(token, field="items", count=1)["items"] == ["Alpha"]
    assert t.continue_truncated(token, field="text", count=5)["text"] == "Alpha"
    peek = t.peek_truncated(token)
    assert peek["ok"] and peek["fields"]["items"]["remaining"] == 1
    assert t.peek_truncated("missing")["code"] == t.MCPError.TRUNCATION_TOKEN_INVALID

    assert t.search_truncated("missing", "x")["code"] == t.MCPError.TRUNCATION_TOKEN_INVALID
    assert t.search_truncated(token, "")["code"] == t.MCPError.INVALID_ARGS
    assert t.search_truncated(token, "x", field="missing")["code"] == t.MCPError.TRUNCATION_FIELD_MISSING
    assert t.search_truncated(token, "alpha", case_sensitive=False)["match_count"]
    assert t.search_truncated(token, "Alpha", case_sensitive=True, field="text")["match_count"]
    assert t.search_truncated(token, r"[", is_regex=True)["code"] == t.MCPError.INVALID_ARGS
    assert t.search_truncated(token, r"(a+)+", is_regex=True)["code"] == t.MCPError.INVALID_ARGS
    assert t.search_truncated(token, "alpha", is_regex=True)["match_count"]
    assert t._is_catastrophic_regex(r"a\\+[(]" ) is False
    assert t._is_catastrophic_regex(")") is False
    assert t._is_catastrophic_regex(r"(ab)+") is False
    assert t._is_catastrophic_regex(r"((a))+") is False
    assert t._is_catastrophic_regex(r"(((a))+)") is False
    assert t.search_truncated(token, "beta", field="items", limit=1)["truncated"] is True
    assert t.search_truncated(token, "a", field="items", limit=1)["truncated"] is True
    assert t.search_truncated(token, "a", field="text", limit=1)["truncated"] is True

    fallback = _token(
        {"nested": {"value": "Needle"}},
        {"nested.value": {"type": "string", "total": 6, "chunk_size": 2}},
    )
    t._TRUNCATION_STORE[fallback]["values"] = {}
    t._TRUNCATION_STORE[fallback]["response"] = {"nested": {"value": "Needle"}}
    assert t.search_truncated(fallback, "needle")["match_count"] == 1
    missing_value = _token({"other": 1}, {"missing": {"type": "string", "total": 1}})
    t._TRUNCATION_STORE[missing_value]["values"] = {}
    assert t.search_truncated(missing_value, "x")["match_count"] == 0
    scalar = _token({"value": 3}, {"value": {"type": "number", "total": 1}})
    assert t.search_truncated(scalar, "3")["match_count"] == 0

    list_summary = t.summary_truncated(token, field="items")
    assert list_summary["categories"]["string"] == 1
    assert list_summary["categories"]["dict"] == 1
    addressed = _token({"items": [{"addr": "0x1"}]}, {"items": {"type": "list", "total": 1, "chunk_size": 1}})
    assert t.summary_truncated(addressed, field="items")["sample"]
    mixed = _token({"items": [{"name": "x"}, 42]}, {"items": {"type": "list", "total": 2, "chunk_size": 1}})
    assert t.summary_truncated(mixed, field="items")["categories"]["other"] == 1
    assert t.summary_truncated(token)["code"] == t.MCPError.TRUNCATION_FIELD_MISSING
    string_summary = t.summary_truncated(token, field="text")
    assert string_summary["total_lines"] == 3
    assert string_summary["last_lines"] == []
    bad = _token({"value": 1}, {"value": {"type": "number", "total": 1}})
    assert t.summary_truncated(bad, field="value")["code"] == t.MCPError.TRUNCATION_FIELD_MISSING
    assert t.summary_truncated("missing")["code"] == t.MCPError.TRUNCATION_TOKEN_INVALID


def test_summary_long_text_and_recursive_size_truncation_edges(monkeypatch):
    token = _token({"text": "\n".join(str(i) for i in range(20))}, {"text": {"type": "string", "total": 50, "chunk_size": 5}})
    summary = t.summary_truncated(token, field="text")
    assert summary["last_lines"]

    assert t._estimate_size("text", 100) > 0
    assert t._estimate_size({"a": ["x", None, 1]}, 100) > 0
    assert t._estimate_size({"a": "x" * 100}, 10) >= 10
    assert t._estimate_size({"a": "x"}, 10, _depth=t._MAX_TRUNCATION_DEPTH + 1) == 0
    assert t._estimate_size((1, 2), 100) > 0

    fields = {}
    assert t._truncate_recursive(list(range(5)), 500, fields) == list(range(5))
    assert t._truncate_recursive(list(range(20)), 10_000, fields) == list(range(20))
    long_list = list(range(40))
    clipped = t._truncate_recursive(long_list, 500, fields, path="items", trunc_offset=100, trunc_limit=2)
    assert clipped == [] and fields["items"]["type"] == "list"
    string_fields = {}
    assert t._truncate_recursive("abcdef", 3, string_fields, path="text", trunc_offset=20, trunc_limit=2) == ""
    nested = {"deep": {"value": "abcdef"}}
    assert t._truncate_recursive(nested, 3, {}, _depth=t._MAX_TRUNCATION_DEPTH) == nested

    response = {"items": list(range(50)), "traceback": "x" * 300, "small": "ok"}
    pruned = t.truncate_response(response, max_tokens=500, session_id="S", owner_id="O")
    assert pruned["_truncated"] is True
    assert pruned["traceback"].endswith("[stripped for context economy]")
    assert "_continue" in pruned
    assert response["traceback"] == "x" * 300
    assert t.truncate_response({"small": "ok"}, max_tokens=1) == {"small": "ok"}
    paged = t.truncate_response({"items": list(range(20))}, max_tokens=500, trunc_offset=100, trunc_limit=2)
    assert paged["_truncated"] is True

    monkeypatch.setattr(t, "_MAX_TRUNCATION_DEPTH", 1)
    deep = {"a": {"b": {"c": "d"}}}
    assert t.truncate_response(deep, max_tokens=500, trunc_limit=1)["_truncated"] is True
