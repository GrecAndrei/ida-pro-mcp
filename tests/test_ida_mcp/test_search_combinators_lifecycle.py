"""Behavior coverage for graph and structural search combinations.

The tests drive the public combinator handlers against a deterministic IDA
boundary.  They deliberately cover fallback paths used when no embedding index
or optional backend is available.
"""

from __future__ import annotations

from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.combinators")


def _function_surface(monkeypatch, comb):
    names = {0x1000: "main", 0x2000: "helper", 0x3000: "unused"}
    spans = {
        0x1000: SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        0x2000: SimpleNamespace(start_ea=0x2000, end_ea=0x2080),
        0x3000: SimpleNamespace(start_ea=0x3000, end_ea=0x5000),
    }
    monkeypatch.setattr(comb.idautils, "Functions", lambda: list(names), raising=False)
    monkeypatch.setattr(comb, "_func_name", lambda ea: names.get(ea, hex(ea)))
    monkeypatch.setattr(comb._compat, "get_func_info", spans.get)
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea in names else None)
    return names, spans


def test_boolean_composition_handles_primitives_quotes_and_errors(monkeypatch):
    comb = _module()
    _function_surface(monkeypatch, comb)

    result = comb.search_bool(
        '(name:"main" OR name:helper) AND NOT name:unused',
        case_sensitive=False,
        offset=0,
        limit=10,
    )
    assert result["ok"] is True
    assert result["total"] == 2
    assert {item["name"] for item in result["items"]} == {"main", "helper"}
    assert "10 primitives" in result["note"]

    assert comb.search_bool("leaf", False, 0, 10)["ok"] is True
    assert comb.search_bool("", False, 0, 10)["error"] is True
    assert comb.search_bool("name:main trailing", False, 0, 10)["error"] is True
    assert comb.search_bool("(name:main", False, 0, 10)["error"] is True


def test_graph_primitives_and_path_reachability(monkeypatch):
    comb = _module()
    names, _spans = _function_surface(monkeypatch, comb)
    graph = {
        "callees": {0x1000: {0x2000}, 0x2000: {0x3000}, 0x3000: set()},
        "callers": {0x2000: {0x1000}, 0x3000: {0x2000}},
    }
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: graph["callees"].get(ea, set()))
    def resolve_target(target):
        try:
            return int(target, 0), None, {}
        except (TypeError, ValueError):
            return comb.idaapi.BADADDR, "invalid target", {}

    monkeypatch.setattr(comb, "resolve_target", resolve_target)
    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda _name: comb.idaapi.BADADDR, raising=False)

    path = comb.search_path("0x1000", "0x3000", max_depth=4)
    assert path["ok"] is True
    assert path["hops"] == 2
    assert path["items"][-1]["name"] == names[0x3000]
    assert "dst" in path["results"]

    no_path = comb.search_path("0x3000", "0x1000", max_depth=2)
    assert no_path["ok"] is True and no_path["count"] == 0
    assert comb.search_path("bad", "0x1000", 2)["error"] is True

    reached = comb.search_reach("0x1000", depth=1, offset=0, limit=10)
    assert reached["ok"] is True
    assert reached["total"] == 1
    assert reached["items"][0]["name"] == names[0x2000]
    assert comb.search_reach("0x9999", 1, 0, 10)["error"] is True


def test_noreach_uses_exports_and_fallback_entry_point(monkeypatch):
    comb = _module()
    names, _spans = _function_surface(monkeypatch, comb)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())
    monkeypatch.setattr(comb.ida_nalt, "get_entry_qty", lambda: 1, raising=False)
    monkeypatch.setattr(comb.ida_nalt, "get_entry_ordinal", lambda index: index + 1, raising=False)
    monkeypatch.setattr(comb.ida_nalt, "get_entry", lambda _ordinal: 0x1000, raising=False)
    monkeypatch.setattr(comb, "_all_func_eas", lambda: set(names))

    result = comb.search_noreach(depth=1, offset=0, limit=10)
    assert result["ok"] is True
    assert result["entry_points"] == ["0x1000"]
    assert result["total"] == 1
    assert result["items"][0]["name"] == "unused"

    monkeypatch.setattr(comb.ida_nalt, "get_entry_qty", lambda: 0, raising=False)
    monkeypatch.setattr(
        comb.idc,
        "get_name_ea_simple",
        lambda name: 0x1000 if name == "main" else comb.idaapi.BADADDR,
        raising=False,
    )
    assert comb._all_entry_points() == [0x1000]

    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda _name: comb.idaapi.BADADDR, raising=False)
    assert comb.search_noreach(1, 0, 10)["error"] is True


def test_outlier_metrics_use_direct_ida_fallback(monkeypatch):
    comb = _module()
    _names, spans = _function_surface(monkeypatch, comb)
    spans[0x1000].end_ea = 0x1008
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    monkeypatch.setattr(comb._compat, "get_flow_chart", lambda ea: [ea, ea + 1])

    tiny = comb.search_analyze(scope="outlier", metric="tiny", offset=0, limit=10)
    assert tiny["ok"] is True
    assert tiny["total"] == 1 and tiny["items"][0]["name"] == "main"

    huge = comb.search_analyze(scope="outlier", metric="huge", offset=0, limit=10)
    assert huge["ok"] is True
    assert huge["total"] == 1 and huge["items"][0]["name"] == "unused"

    blocks = comb.search_analyze(scope="outlier", metric="bb_count", offset=0, limit=10)
    assert blocks["ok"] is True and blocks["items"][0]["bb_count"] == 2
    complexity = comb.search_analyze(scope="outlier", metric="complexity")
    assert complexity["error"] is True
    assert comb.search_analyze(scope="outlier", metric="not-a-metric")["error"] is True


def test_outlier_graph_metrics_and_neighborhood_context(monkeypatch):
    comb = _module()
    _function_surface(monkeypatch, comb)
    graph = {
        "callees": {0x1000: {0x2000}, 0x2000: set(), 0x3000: set()},
        "callers": {0x2000: {0x1000}, 0x3000: set()},
    }
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    for metric, expected_name in (("orphan", "main"), ("leaf", "helper"), ("hub", "helper"), ("deep", "main")):
        result = comb.search_analyze(scope="outlier", metric=metric, offset=0, limit=10)
        assert result["ok"] is True
        assert result["items"]
        assert result["items"][0]["name"] == expected_name

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: {"func_size": 16, "bb_count": 2, "cyclomatic": 1})
    monkeypatch.setattr(comb, "_get_behavior_tags", lambda _ea: ["network"])
    monkeypatch.setattr(comb, "_get_embedding_similar", lambda _ea, top_k=10: [{"addr": "0x2000", "name": "helper", "similarity": 0.876}])
    neighborhood = comb.search_analyze(scope="neighborhood", addr="0x1000", include_items=True)
    assert neighborhood["ok"] is True
    assert neighborhood["metrics"]["func_size"] == 16
    assert neighborhood["tags"] == ["network"]
    assert neighborhood["similar"][0]["score"] == 0.876
    assert neighborhood["items"]
    no_items = comb.search_analyze(scope="neighborhood", addr="0x1000", include_items=False)
    assert no_items["ok"] is True and no_items["items"] == []


def test_similar_vulnerable_and_semantic_fallbacks(monkeypatch):
    comb = _module()
    names, _spans = _function_surface(monkeypatch, comb)
    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb, "_get_embedding_similar", lambda _ea, top_k=10: [{"ea": "0x2000", "addr": "0x2000", "name": "helper", "similarity": 0.8}])
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: {"func_size": 8, "bb_count": 1, "cyclomatic": 1})
    similar = comb.search_analyze(scope="similar", addr="0x1000", offset=0, limit=1)
    assert similar["ok"] is True
    assert similar["items"][0]["size"] == 8
    assert comb.search_analyze(scope="similar")["error"] is True

    graph = {"callees": {0x1000: {0x4000}}, "callers": {0x2000: {0x1000}}}
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000, 0x4000], raising=False)
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x2000, "read")], raising=False)
    monkeypatch.setattr(comb.idc, "get_func_name", lambda ea: {0x1000: "handler", 0x2000: "read", 0x4000: "memcpy"}.get(ea, ""), raising=False)
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x4000 else "", raising=False)
    vulnerable = comb.search_analyze(scope="vulnerable", pattern="memcpy", depth=2)
    assert vulnerable["ok"] is True
    assert vulnerable["count"] == 1
    assert vulnerable["items"][0]["vuln_type"] == "buffer_overflow"
    assert vulnerable["items"][0]["function"] == names[0x1000]

    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    semantic = comb.search_analyze(scope="semantic", pattern="crypto")
    assert semantic["error"] is True
    assert comb.search_analyze(scope="nope")["error"] is True


def test_prim_size_mnemonic_api_and_text_paths(monkeypatch):
    comb = _module()
    _function_surface(monkeypatch, comb)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x2000 else "", raising=False)
    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda _name: comb.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(comb.idaapi, "GN_VISIBLE", 0, raising=False)
    monkeypatch.setattr(comb.idc, "print_insn_mnem", lambda ea: "call" if ea == 0x1000 else "ret", raising=False)
    monkeypatch.setattr(comb.idc, "next_head", lambda ea, _end: ea + 1 if ea == 0x1000 else comb.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(comb.idautils, "FuncItems", lambda _ea: [0x1000], raising=False)
    monkeypatch.setattr(comb.idautils, "XrefsFrom", lambda *_args: [], raising=False)

    assert comb._prim_funcs_by_name("main") == {0x1000}
    assert comb._prim_size(">16") == {0x2000, 0x3000}
    assert comb._prim_size("10-20") == {0x1000}
    assert comb._prim_funcs_by_mnem("call") == {0x1000}
    assert comb._prim_funcs_by_api("mem") == {0x1000}
    assert comb._prim_leaf("true") == {0x2000, 0x3000}
    monkeypatch.setattr(
        comb.idautils,
        "XrefsTo",
        lambda ea, *_args: [SimpleNamespace(iscode=True)] if ea == 0x2000 else [],
        raising=False,
    )
    assert comb._prim_no_callers("true") == {0x1000, 0x3000}
