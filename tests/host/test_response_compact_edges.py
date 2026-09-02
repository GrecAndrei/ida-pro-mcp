"""Behavioral edge coverage for the host response compaction pipeline."""

from __future__ import annotations

from ida_pro_mcp.host.config import _COMPACT_DROP
from ida_pro_mcp.host.server.server_response_compact import ServerResponseCompactMixin


class _CompactHost(ServerResponseCompactMixin):
    default_response_mode = "compact"
    default_qol_mode = "balanced"
    default_compact_max_items = 10
    default_compact_max_string = 100
    default_compact_char_budget = 5_000
    default_table_mode = False
    default_batch_compact = False
    default_error_detail_level = "basic"
    _qol_profiles = {
        "tiny": {"mode": "compact", "max_items": 2, "max_string": 64},
        "balanced": {"mode": "compact", "max_items": 10, "max_string": 100},
        "debug": {"mode": "full", "max_items": 100, "max_string": 500},
    }

    @staticmethod
    def _pop_first(mapping, keys, default=None):
        for key in keys:
            if key in mapping:
                return mapping.pop(key)
        return default


def _opts(**overrides):
    result = {
        "mode": "compact",
        "fields": [],
        "omit": [],
        "max_items": 10,
        "max_string": 100,
        "char_budget": 0,
        "drop_empty": True,
        "drop_false": True,
        "drop_ok": False,
        "dedupe_counts": True,
        "strip_meta": True,
        "table_mode": False,
        "batch_compact": True,
        "error_details": "basic",
    }
    result.update(overrides)
    return result


def test_extract_response_options_handles_aliases_precedence_and_preserves_backend_args():
    host = _CompactHost()
    args = {
        "qol_mode": "tiny",
        "response_mode": "full",
        "compact": True,
        "_response_max_items": "0",
        "_response_max_string": "999999999",
        "_response_char_budget": "bad",
        "_response_fields": "address, name",
        "_response_omit": ["debug", "meta"],
        "query": "decrypt",
        "mode": "backend-mode",
    }

    exec_args, opts = host._extract_response_options(args)

    assert exec_args == {"query": "decrypt", "mode": "backend-mode"}
    assert opts["qol_mode"] == "tiny"
    assert opts["mode"] == "compact"  # compact toggle wins over response_mode
    assert opts["max_items"] == 1
    assert opts["max_string"] == 500_000
    assert opts["char_budget"] == 5_000
    assert opts["fields"] == ["address", "name"]
    assert opts["omit"] == ["debug", "meta"]


def test_extract_response_options_invalid_modes_fall_back_to_defaults():
    host = _CompactHost()

    args, opts = host._extract_response_options({"qol_mode": "unknown", "response_mode": "wat"})
    assert args == {}
    assert opts["qol_mode"] == "balanced"
    assert opts["mode"] == "compact"
    assert opts["error_details"] == "basic"

    _args, full = host._extract_response_options({"response_mode": "full", "_error_details": "wat"})
    assert full["mode"] == "full"
    assert full["error_details"] == "full"


def test_extract_response_options_non_mapping_is_safe():
    host = _CompactHost()
    args, opts = host._extract_response_options(["not", "a", "mapping"])
    assert args == {}
    assert opts == host._default_response_options()


def test_compact_error_details_supports_full_none_and_basic_levels():
    host = _CompactHost()
    details = {
        "message": "x" * 120,
        "items": list(range(5)),
        "traceback": "secret-metadata",
        "nested": {"keep": True},
    }

    assert host._compact_error_details(details, _opts(error_details="full")) is details
    assert host._compact_error_details(details, _opts(error_details="none")) is None
    compact = host._compact_error_details(details, _opts(max_items=2, max_string=64))
    assert compact["message"].startswith("x" * 64)
    assert compact["message"].endswith("chars)")
    assert compact["items"] == [0, 1]
    assert compact["items_more"] == 3
    assert "traceback" not in compact
    assert compact["nested"] == {"keep": True}


def test_compact_error_details_keeps_scalar_details_and_drops_empty_basic_dict():
    host = _CompactHost()
    assert host._compact_error_details("plain error", _opts()) == "plain error"
    assert host._compact_error_details({"traceback": "only metadata"}, _opts()) is None


def test_table_mode_only_tableifies_uniform_dict_rows_and_limits_rows():
    host = _CompactHost()
    rows = [{"name": f"f{i}", "ea": i} for i in range(5)]

    table = host._maybe_tableify(rows, _opts(table_mode=True, max_items=3))

    assert table == {
        "columns": ["name", "ea"],
        "rows": [["f0", 0], ["f1", 1], ["f2", 2]],
        "count": 3,
        "total": 5,
    }


def test_table_mode_leaves_non_uniform_or_small_values_unchanged():
    host = _CompactHost()
    assert host._maybe_tableify([{"a": 1}] * 3, _opts(table_mode=True)) == [{"a": 1}] * 3
    assert host._maybe_tableify([{"a": 1}, {"b": 2}, {"a": 3}, {"b": 4}], _opts(table_mode=True)) == [
        {"a": 1}, {"b": 2}, {"a": 3}, {"b": 4}
    ]
    assert host._maybe_tableify([{"a": 1}, "not-a-row", {"a": 3}, {"a": 4}], _opts(table_mode=True)) == [
        {"a": 1}, "not-a-row", {"a": 3}, {"a": 4}
    ]
    assert host._maybe_tableify("not-a-list", _opts(table_mode=True)) == "not-a-list"


def test_compact_value_trims_strings_lists_and_drops_empty_values():
    host = _CompactHost()
    out = host._compact_value(
        {"long": "x" * 70, "items": list(range(5)), "empty": "", "none": None, "false": False},
        _opts(max_items=2, max_string=64),
    )
    assert out["long"] == "x" * 64 + "...(+6 chars)"
    assert out["items"] == [0, 1]
    assert "empty" not in out
    assert "none" not in out
    assert "false" not in out


def test_compact_value_preserves_semantic_booleans_and_explicit_firmware_false():
    host = _CompactHost()
    out = host._compact_value(
        {"analysis_ready": False, "safe_mode": False, "firmware_detected": False, "other": False},
        _opts(),
    )
    assert out == {
        "analysis_ready": False,
        "safe_mode": False,
        "firmware_detected": False,
    }


def test_compact_value_deduplicates_counts_without_removing_pagination_cursor():
    host = _CompactHost()
    out = host._compact_value(
        {
            "items": [1, 2],
            "results": ["a", "b"],
            "count": 2,
            "total": 2,
            "limit": 2,
            "offset": 0,
            "next_offset": 2,
        },
        _opts(),
    )
    assert out["next_offset"] == 2
    assert "offset" not in out
    assert "count" not in out
    assert out["total"] == 2
    assert out["limit"] == 2

    out_with_count = host._compact_value(
        {"items": [1, 2, 3], "count": 2, "total": 2, "limit": 2},
        _opts(),
    )
    assert out_with_count["count"] == 2
    assert "total" not in out_with_count
    assert "limit" not in out_with_count


def test_compact_value_prefers_text_functions_unless_items_are_requested():
    host = _CompactHost()
    payload = {"functions": "f()\ng()", "items": [{"name": "f"}], "count": 1}
    compact = host._compact_value(payload, _opts())
    assert "functions" in compact
    assert "items" not in compact

    kept = host._compact_value(payload, _opts(fields=["items"]))
    assert "items" in kept


def test_project_top_level_fields_keeps_error_contract_and_applies_omit():
    host = _CompactHost()
    payload = {
        "address": "0x1000",
        "name": "fn",
        "debug": "details",
        "error": True,
        "code": "E_FAIL",
        "message": "failed",
        "workflow_meta": {"phase": "x"},
    }
    out = host._project_top_level_fields(payload, {"fields": ["address"], "omit": ["address", "message"]})
    assert out == {
        "error": True,
        "code": "E_FAIL",
        "message": "failed",
        "workflow_meta": {"phase": "x"},
    }


def test_compact_batch_result_reduces_tool_rows_and_preserves_metadata():
    host = _CompactHost()
    payload = {
        "results": [
            {"name": "search", "result": {"items": [1]}},
            {"name": "code", "result": {"error": True, "message": "bad"}},
            {"name": "opaque", "result": "raw"},
        ],
        "summary": {"ok": 2, "failed": 1},
        "error": "partial failure",
        "workflow_meta": {"batch": True},
    }

    out = host._compact_batch_result(payload, _opts(batch_compact=True))

    assert out["results"] == [
        {"tool": "search", "ok": True, "data": {"items": [1]}},
        {"tool": "code", "ok": False, "data": {"error": True, "message": "bad"}},
        {"tool": "opaque", "ok": True, "data": "raw"},
    ]
    assert out["summary"] == payload["summary"]
    assert out["error"] == "partial failure"
    assert out["workflow_meta"] == {"batch": True}


def test_compact_value_preserves_false_ok_and_drops_metadata_only_details():
    host = _CompactHost()
    out = host._compact_value(
        {"traceback": "internal", "ok": False, "details": {"traceback": "only"}},
        _opts(drop_ok=True),
    )
    assert out == {"ok": False}


def test_compact_value_tableifies_uniform_rows_and_drops_empty_list_items():
    host = _CompactHost()
    rows = host._compact_value(
        [{"name": "a", "ea": 1}, {"name": "b", "ea": 2}, {"name": "c", "ea": 3}, {"name": "d", "ea": 4}],
        _opts(table_mode=True),
    )
    assert rows["columns"] == ["name", "ea"]
    assert len(rows["rows"]) == 4
    assert "count" not in rows
    assert host._compact_value([""], _opts()) is _COMPACT_DROP


def test_table_mode_leaves_empty_or_wide_rows_and_batch_keeps_opaque_entries():
    host = _CompactHost()
    assert host._maybe_tableify([{}, {}, {}, {}], _opts(table_mode=True)) == [{}, {}, {}, {}]
    wide = {f"key_{i}": i for i in range(25)}
    assert host._maybe_tableify([wide] * 4, _opts(table_mode=True)) == [wide] * 4
    out = host._compact_batch_result(
        {"results": [{"name": "search", "result": {}}, "opaque"]},
        _opts(batch_compact=True),
    )
    assert out["results"][1] == "opaque"


def test_compact_batch_result_is_noop_when_not_enabled_or_shape_is_not_batch():
    host = _CompactHost()
    payload = {"results": []}
    assert host._compact_batch_result(payload, _opts(batch_compact=False)) is payload
    assert host._compact_batch_result([payload], _opts(batch_compact=True)) == [payload]
