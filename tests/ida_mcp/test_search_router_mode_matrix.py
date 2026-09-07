"""Route-level coverage for the public search surface and its mode aliases."""

import builtins
import json
import sys
import types

from tests._isolated_repo_loader import load_tool_submodule


def _load_search(monkeypatch):
    from tests.ida_mcp.support_fakes import make_fake_ida

    for name, module in make_fake_ida().items():
        monkeypatch.setitem(sys.modules, name, module)
    return load_tool_submodule("search")


def _stub(*_args, **_kwargs):
    return {"ok": True, "items": [], "results": "", "count": 0}


def test_search_router_dispatches_every_public_action(monkeypatch):
    search = _load_search(monkeypatch)
    handler_names = [
        "search_bytes", "search_string", "search_immediate", "search_name", "search_insns",
        "search_text", "search_operand", "search_comment", "search_data_ref", "search_code_ref",
        "search_regex", "search_func_by_sig", "search_find", "search_callers", "search_callees",
        "search_api", "search_constants", "search_decompiled", "search_structured", "search_type",
        "search_export", "search_summary", "search_bool", "search_analyze", "search_neighborhood",
        "search_outlier", "search_fingerprint", "search_path", "search_reach", "search_noreach",
        "search_symbol", "search_symbol_info", "search_demangle", "search_xrefs_to_string",
        "search_data_value",
    ]
    for name in handler_names:
        monkeypatch.setattr(search, name, _stub)
    monkeypatch.setattr(search, "_search_nl_impl", _stub)
    monkeypatch.setattr(search, "_search_behavior_impl", _stub)
    monkeypatch.setattr(search, "run_query_lang", _stub)
    monkeypatch.setattr(search, "normalize_search_result", lambda result, **_kwargs: result)

    actions = [
        "bytes", "string", "immediate", "name", "insns", "mnemonic", "instruction", "text",
        "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig", "find", "callers",
        "callees", "api", "vulnerable", "constants", "decompiled", "structured", "type", "export",
        "summary", "query_lang", "nl", "behavior", "bool", "analyze", "neighborhood", "outlier",
        "fingerprint", "path", "reach", "noreach", "symbol", "symbol_info", "demangle",
        "xrefs_to_string", "data_value",
    ]
    no_pattern = {"vulnerable", "constants", "summary", "outlier", "noreach", "demangle", "symbol_info"}
    for action in actions:
        kwargs = {"action": action, "pattern": None if action in no_pattern else "query"}
        if action == "path":
            kwargs.update(pattern="src", dst="dst")
        if action == "structured":
            kwargs.update(pattern="query", constraints={})
        result = search.search(**kwargs)
        assert result["ok"] is True, (action, result)


def test_search_router_validates_ranges_exports_structured_and_radius(monkeypatch):
    search = _load_search(monkeypatch)
    monkeypatch.setattr(search, "validate_range", lambda _start, _end: (None, None, {"code": "BAD_RANGE"}))
    assert search.search(action="find", pattern="x", start="0x1", end="0x2")["code"] == "BAD_RANGE"
    assert search.search(action="find", pattern="x", start="0x1")["code"] == "INVALID_ARGS"
    assert search.search(action="export")["code"] == "INVALID_ARGS"
    assert search.search(action="structured")["code"] == "INVALID_ARGS"

    search.validate_addr = lambda value, require_func=False: (None, {"code": "INVALID_ADDR"}) if value == "bad" else (int(value, 0), None)
    search._search_nl_impl = _stub
    assert search.search(action="nl", pattern="x", radius=2)["code"] == "INVALID_ARGS"
    assert search.search(action="nl", pattern="x", address="bad")["code"] == "INVALID_ADDR"
    result = search.search(action="nl", pattern="x", addr="0x1000", radius=2, mode="quick")
    assert result["ok"] is True


def test_search_router_composes_l1_tag_filter_and_data_value_modes(monkeypatch):
    search = _load_search(monkeypatch)
    search.normalize_search_result = lambda result, **_kwargs: result
    search._query_insight_by_tags = lambda tags, mode="and": ["0x1000", "0x2000"]
    search.search_structured = lambda constraints, *_args: {
        "ok": True,
        "results": "0x1000  keep\n0x3000  remove",
        "items": ["not-a-dict", {"addr": "0x1000", "name": "keep"}, {"addr": "0x3000", "name": "remove"}],
        "count": 3,
    }
    filtered = search.search(
        action="structured",
        constraints={"behavior_tags": ["crypto_symmetric"]},
    )
    assert filtered["count"] == 1
    assert filtered["items"] == [{"addr": "0x1000", "name": "keep"}]
    assert filtered["results"] == "0x1000  keep"

    class _ExplodingAddr:
        def __str__(self):
            raise RuntimeError("explode")

    search._query_insight_by_tags = lambda tags, mode="and": [_ExplodingAddr()]
    assert search.search(action="structured", constraints={"behavior_tags": ["crypto"]})["ok"] is True

    calls = []

    def data_value(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True, "mode": "data_value"}

    def string_search(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True, "mode": "string"}

    search.search_data_value = data_value
    search.search_string = string_search
    assert search.search(action="data_value", value="0x401000")["mode"] == "data_value"
    search.looks_like_address = lambda _value: False
    assert search.search(action="data_value", value="needle")["mode"] == "string"
    assert search.search(action="data_value")["code"] == "INVALID_ARGS"
    assert len(calls) == 2


def test_insight_index_helpers_cover_missing_corrupt_and_tag_modes(monkeypatch, tmp_path):
    search = _load_search(monkeypatch)
    path = tmp_path / "insight.json"
    assert search._load_insight_index(str(path)) == {}
    path.write_text("not-json", encoding="utf-8")
    assert search._load_insight_index(str(path)) == {}
    path.write_text(json.dumps({
        "tag_map": {"crypto": [None, "0x1000", "0x2000"], "network": ["0x2000", "0x3000"], "bad": "not-list"},
        "func_map": {"0x1000": {}, "0x2000": {}},
    }), encoding="utf-8")
    assert search._load_insight_index(str(path))["func_map"]
    monkeypatch.setattr(search, "_insight_index_path", lambda: str(path))
    assert search._query_insight_by_tags([], mode="and") == []
    assert search._query_insight_by_tags(["crypto", "network"], mode="and") == ["0x2000"]
    assert set(search._query_insight_by_tags(["crypto", "network"], mode="or")) == {"0x1000", "0x2000"}
    assert search._query_insight_by_tags(["missing"], mode="or") == []
    assert search._query_insight_by_tags(["bad"], mode="and") == []
    assert search._query_insight_by_tags(["bad"], mode="or") == []
    assert set(search._extract_tags_from_pattern("crypto and NETWORK and unknown")) == {"crypto", "network"}
    assert search._extract_tags_from_pattern("") == []


def test_search_router_normalizes_aliases_intents_and_limits(monkeypatch):
    search = _load_search(monkeypatch)
    monkeypatch.setattr(search, "normalize_search_result", lambda result, **_kwargs: result)
    monkeypatch.setattr(search, "_query_insight_by_tags", lambda *_args, **_kwargs: [])
    captured = []

    def handler(*args, **kwargs):
        captured.append((args, kwargs))
        return {"ok": True, "items": [], "results": "", "count": 0}

    monkeypatch.setattr(search, "search_bytes", handler)
    alias = search.search(action="byte", pattern="90", limit="9999", offset=-4, timeout_ms="bad")
    assert alias["ok"] is True
    assert captured[-1][0][0] == "90"
    assert captured[-1][0][-2:] == (500, "bad")

    monkeypatch.setattr(search, "search_callers", handler)
    intent = search.search(action="find", pattern="callers of main")
    assert intent["interpreted_action"] == "callers"
    assert intent["interpreted_query"] == "main"

    search.validate_range = lambda _start, _end: (0x1000, 0x2000, None)
    monkeypatch.setattr(search, "search_name", handler)
    ranged = search.search(action="name", query="main", start="0x1", end="0x2", min_score="bad")
    assert ranged["ok"] is True
    assert captured[-1][0][0] == "main"


def test_search_router_handles_handler_failure_and_data_value_aliases(monkeypatch):
    search = _load_search(monkeypatch)
    monkeypatch.setattr(search, "normalize_search_result", lambda result, **_kwargs: result)

    def broken(*_args, **_kwargs):
        raise RuntimeError("handler exploded")

    monkeypatch.setattr(search, "search_name", broken)
    result = search.search(action="name", pattern="x")
    assert result["ok"] is False and "handler exploded" in result["error"]

    calls = []
    monkeypatch.setattr(search, "search_data_value", lambda *args, **kwargs: calls.append((args, kwargs)) or {"ok": True})
    monkeypatch.setattr(search, "looks_like_address", lambda _value: True)
    assert search.search(action="pointer", pattern="0x401000", endian="little")["ok"] is True
    assert calls[-1][1]["endian"] == "le"


def test_insight_helpers_cover_direct_malformed_payloads_and_fallback_import(monkeypatch):
    search = _load_search(monkeypatch)

    monkeypatch.setattr(search, "_load_insight_index", list)
    assert search._query_insight_by_tags(["crypto"]) == []
    monkeypatch.setattr(search, "_load_insight_index", lambda: {"tag_map": [], "func_map": {}})
    assert search._query_insight_by_tags(["crypto"]) == []
    monkeypatch.setattr(search, "_load_insight_index", lambda: {"tag_map": {}, "func_map": []})
    assert search._query_insight_by_tags(["crypto"]) == []
    monkeypatch.setattr(search, "_load_insight_index", lambda: {"tag_map": {}, "func_map": {}})
    assert search._query_insight_by_tags(["  ", 1]) == []

    monkeypatch.setattr(
        search,
        "_load_insight_index",
        lambda: {"tag_map": {"crypto": ["0x1"], "empty": []}, "func_map": {"0x1": {}}},
    )
    assert search._query_insight_by_tags(["crypto", "empty"]) == []
    assert search._query_insight_by_tags(["crypto", "broken"], mode="or") == ["0x1"]

    fallback = types.ModuleType("host.intelligence.insight_paths")
    fallback.resolve_insight_index_path = lambda: "/tmp/fallback-insight.json"
    monkeypatch.setitem(sys.modules, "host", types.ModuleType("host"))
    monkeypatch.setitem(sys.modules, "host.intelligence", types.ModuleType("host.intelligence"))
    monkeypatch.setitem(sys.modules, "host.intelligence.insight_paths", fallback)
    real_import = builtins.__import__

    def import_without_package(name, *args, **kwargs):
        if name == "ida_pro_mcp.host.intelligence.insight_paths":
            raise ImportError("package layout unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_package)
    assert search._insight_index_path() == "/tmp/fallback-insight.json"


def test_search_router_covers_numeric_data_value_and_blackboard_context(monkeypatch):
    search = _load_search(monkeypatch)
    monkeypatch.setattr(search, "normalize_search_result", lambda result, **_kwargs: result)
    captured = {}

    def data_value(*args, **kwargs):
        captured["data"] = (args, kwargs)
        return {"ok": True, "items": [], "results": "", "count": 0}

    monkeypatch.setattr(search, "search_data_value", data_value)
    assert search.search(action="data_value", pattern=42, endian="big", word_size="u32")["ok"] is True
    assert captured["data"][0][0] == 42
    assert captured["data"][1]["endian"] == "be"
    assert captured["data"][1]["word_size"] == "u32"

    class Store:
        def list(self, **kwargs):
            assert kwargs["addr"] == "0x1000"
            return [{"title": "note", "category": "finding", "confidence": 0.8}]

    blackboard = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    blackboard.BlackboardStore = Store
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", blackboard)
    monkeypatch.setattr(
        search,
        "search_find",
        lambda *_args, **_kwargs: {
            "ok": True,
            "items": [{"addr": "0x1000", "name": "f"}, {"name": "no-address"}],
            "results": "0x1000  f",
            "count": 2,
        },
    )
    enriched = search.search(action="find", pattern="f")
    assert enriched["blackboard_context"] == {
        "0x1000": [{"title": "note", "category": "finding", "confidence": 0.8}]
    }

    class FailingStore:
        def list(self, **kwargs):
            raise RuntimeError("store lookup failed")

    blackboard.BlackboardStore = FailingStore
    failing_bb = search.search(action="find", pattern="f")
    assert "blackboard_context" not in failing_bb


def test_search_router_covers_validation_defaults_and_path_error(monkeypatch):
    search = _load_search(monkeypatch)
    monkeypatch.setattr(search, "normalize_search_result", lambda result, **_kwargs: result)
    monkeypatch.setattr(search, "search_name", lambda *_args: {"ok": True, "items": []})

    result = search.search(action="name", pattern="x", limit="bad", offset="bad", semantic_min_score="bad")
    assert result["ok"] is True
    assert search.search(action="find")["code"] == "INVALID_ARGS"
    assert search.search(action="export")["code"] == "INVALID_ARGS"
    assert search.search(action="structured")["code"] == "INVALID_ARGS"
    assert search.search(action="path", pattern="src")["code"] == "INVALID_ARGS"

    monkeypatch.setattr(search, "search_structured", lambda *_args, **_kwargs: {"ok": True, "items": []})
    structured = search.search(
        action="structured",
        constraints={"behavior_tags": "crypto"},
        query="q",
    )
    assert structured["ok"] is True
