"""Exercise compositional search through its shared graph and resolver modes."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.ida_mcp.tools.search import combinators


def test_bool_tokenizer_parser_and_primitive_modes(monkeypatch, fresh_fake_idb):
    assert combinators._tokenize_bool('name:"main entry" && !leaf || no_callers') == [
        "name:main entry", "AND", "NOT", "leaf:true", "OR", "no_callers:true"
    ]
    assert combinators._tokenize_bool('string:"unterminated') == ['string:"unterminated']
    assert combinators._tokenize_bool("name:main || name:helper") == [
        "name:main", "OR", "name:helper"
    ]
    assert combinators.search_bool("", False, 0, 10)["error"] is True
    assert combinators.search_bool("???", False, 0, 10)["error"] is True

    # These calls use the same fake IDB, allowing boolean composition to see
    # the function/name/mnemonic/call-graph state exposed by the primitives.
    for expr in (
        "name:main",
        "name:main OR name:helper",
        "name:main AND NOT name:missing",
        "leaf",
        "no_callers",
        "size:1-10000",
        "args:1+",
        "mnem:ret",
        'string:"return"',
    ):
        result = combinators.search_bool(expr, False, 0, 20)
        assert result.get("ok") is True, (expr, result)

    assert combinators.search_bool("name:main trailing", False, 0, 10)["error"] is True
    assert combinators.search_bool("name:(", False, 0, 10)["error"] is True


def test_graph_path_reachability_and_unreachable_modes(monkeypatch):
    names = {0x1000: "main", 0x1100: "worker", 0x1200: "sink", 0x1300: "dead"}
    edges = {0x1000: {0x1100}, 0x1100: {0x1200}, 0x1200: set(), 0x1300: set()}
    monkeypatch.setattr(combinators, "resolve_target", lambda value: (next((ea for ea, n in names.items() if value in (n, hex(ea))), combinators.idaapi.BADADDR), None, {}))
    monkeypatch.setattr(combinators._compat, "get_func_start", lambda ea: ea if ea in names else None)
    monkeypatch.setattr(combinators, "_func_callees", lambda ea: edges.get(ea, set()))
    monkeypatch.setattr(combinators, "_func_name", lambda ea: names.get(ea, hex(ea)))
    monkeypatch.setattr(combinators.idautils, "Functions", lambda *args: iter(names))
    monkeypatch.setattr(combinators, "_all_entry_points", lambda: [0x1000])

    assert combinators._bfs_path(0x1000, 0x1000, 1) == [0x1000]
    assert combinators._bfs_path(0x1000, 0x1200, 3) == [0x1000, 0x1100, 0x1200]
    assert combinators._bfs_path(0x1000, 0x1200, 1) is None
    path = combinators.search_path("main", "sink", 5)
    assert path["ok"] is True and path["hops"] == 2
    assert combinators.search_path("missing", "sink", 5)["error"] is True
    assert combinators.search_reach("main", 2, 0, 10)["total"] == 2
    assert combinators.search_reach("main", 0, 0, 10)["total"] == 0
    noreach = combinators.search_noreach(2, 0, 10)
    assert noreach["ok"] is True
    assert any(item["name"] == "dead" for item in noreach["items"])

    monkeypatch.setattr(combinators, "_all_entry_points", list)
    assert combinators.search_noreach(2, 0, 10)["error"] is True


def test_analyze_scopes_use_same_fake_graph_and_fallbacks(monkeypatch, fresh_fake_idb):
    combinators._CALL_GRAPH_CACHE.clear()
    monkeypatch.setattr(combinators, "_get_index_metadata", lambda _ea: None)
    monkeypatch.setattr(combinators, "_get_embedding_similar", lambda _ea, top_k=10: [{"addr": "0x140001050", "name": "helper", "similarity": 0.8}])
    monkeypatch.setattr(combinators, "_get_behavior_tags", lambda _ea: ["loader"])

    neighborhood = combinators.search_analyze(
        addr="0x140001000", scope="neighborhood", radius=5, include_items=True
    )
    assert neighborhood["ok"] is True
    assert neighborhood["scope"] == "neighborhood"
    assert neighborhood["tags"] == ["loader"]
    assert neighborhood["similar"][0]["name"] == "helper"

    for metric in ("size", "tiny", "huge", "bb_count", "orphan", "leaf", "deep", "hub"):
        result = combinators.search_analyze(scope="outlier", metric=metric, limit=10)
        assert result.get("ok") is True, (metric, result)
    assert combinators.search_analyze(scope="outlier", metric="bogus")["error"] is True
    assert combinators.search_analyze(scope="outlier", metric="complexity")["error"] is True

    similar = combinators.search_analyze(addr="0x140001000", scope="similar", include_items=False)
    assert similar["ok"] is True
    assert similar["items"][0]["name"] == "helper"
    assert combinators.search_analyze(scope="similar")["error"] is True

    assert combinators.search_analyze(scope="auto", metric=None)["error"] is True
    assert combinators.search_neighborhood("0x140001000", 2, 0, 5)["ok"] is True
    assert combinators.search_outlier("size", 3, 0, 5)["ok"] is True
    assert combinators.search_fingerprint("0x140001000", 3, 0, 5)["ok"] is True

    monkeypatch.setattr(combinators, "_get_call_graph", lambda: {"callers": {}, "callees": {}})
    vulnerable = combinators.search_analyze(scope="vulnerable", depth=2, limit=10)
    assert vulnerable["ok"] is True
    assert vulnerable["taint_sources"] == 0
    assert combinators.search_analyze(scope="semantic")["error"] is True
