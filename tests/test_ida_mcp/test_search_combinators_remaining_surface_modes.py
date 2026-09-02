"""Exercise remaining search-combinator modes through stable boundaries."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.combinators")


def _function_surface(monkeypatch):
    comb = _module()
    names = {0x1000: "main", 0x2000: "helper", 0x3000: "unused"}
    spans = {
        0x1000: SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        0x2000: SimpleNamespace(start_ea=0x2000, end_ea=0x2080),
        0x3000: SimpleNamespace(start_ea=0x3000, end_ea=0x5000),
    }
    edges = {0x1000: {0x2000}, 0x2000: {0x3000}, 0x3000: set()}
    monkeypatch.setattr(comb.idautils, "Functions", lambda: list(names))
    monkeypatch.setattr(comb, "_func_name", lambda ea: names.get(ea, hex(ea)))
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea in names else None)
    monkeypatch.setattr(comb._compat, "get_func_info", spans.get)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: edges.get(ea, set()))
    return comb, names, edges


def test_boolean_composition_handles_primitives_quotes_and_errors(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    monkeypatch.setattr(comb.idc, "print_insn_mnem", lambda ea: "ret" if ea == 0x1000 else "call")
    monkeypatch.setattr(comb.idc, "next_head", lambda ea, _end: comb.idaapi.BADADDR)
    monkeypatch.setattr(comb.idautils, "FuncItems", lambda _ea: [0x1000])
    monkeypatch.setattr(comb.idautils, "XrefsFrom", lambda *_args: [])
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x2000 else "")
    monkeypatch.setattr(comb.idaapi, "GN_VISIBLE", 0, raising=False)

    hexrays = types.ModuleType("ida_hexrays")
    hexrays.decompile = lambda ea: "return secret" if ea == 0x1000 else None
    monkeypatch.setitem(sys.modules, "ida_hexrays", hexrays)

    expressions = (
        'name:"main" AND NOT name:missing',
        "name:main OR name:helper",
        "leaf",
        "no_callers",
        "size:1-10000",
        "args:1+",
        "mnem:ret",
        'string:"return"',
    )
    for expression in expressions:
        result = comb.search_bool(expression, False, 0, 20)
        assert result.get("ok") is True, (expression, result)

    for expression in ("", "???", "name:main trailing", "name:(", "name:main AND"):
        assert comb.search_bool(expression, False, 0, 10)["error"] is True


def test_graph_primitives_and_path_reachability(monkeypatch):
    comb, names, edges = _function_surface(monkeypatch)
    monkeypatch.setattr(
        comb,
        "resolve_target",
        lambda target: (int(target, 0), None, {}) if target in {hex(ea) for ea in names} else (comb.idaapi.BADADDR, "missing", {}),
    )

    assert comb._bfs_path(0x1000, 0x1000, 1) == [0x1000]
    assert comb._bfs_path(0x1000, 0x3000, 3) == [0x1000, 0x2000, 0x3000]
    assert comb._bfs_path(0x1000, 0x3000, 1) is None
    path = comb.search_path("0x1000", "0x3000", 5)
    assert path["ok"] is True and path["hops"] == 2
    assert comb.search_path("0x1000", "0x9999", 5)["error"] is True

    reached = comb.search_reach("0x1000", 2, 0, 20)
    assert reached["ok"] is True and reached["total"] == 2
    assert comb.search_reach("0x1000", 0, 0, 20)["total"] == 0
    assert comb.search_reach("0x9999", 2, 0, 20)["error"] is True


def test_noreach_uses_exports_and_main_fallback(monkeypatch):
    comb, names, _edges = _function_surface(monkeypatch)
    all_entry_points = comb._all_entry_points
    monkeypatch.setattr(comb, "_all_entry_points", lambda: [0x1000])
    assert comb.search_noreach(2, 0, 20)["ok"] is True

    monkeypatch.setattr(comb, "_all_entry_points", all_entry_points)
    monkeypatch.setattr(comb, "_compat", SimpleNamespace(get_func_start=lambda ea: ea))
    monkeypatch.setattr(comb, "ida_nalt", SimpleNamespace(get_entry_qty=lambda: 0))
    monkeypatch.setattr(comb.idaapi, "BADADDR", -1, raising=False)
    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda name: 0x1000 if name == "main" else comb.idaapi.BADADDR)
    assert comb._all_entry_points() == [0x1000]
    assert comb.search_noreach(0, 0, 20)["ok"] is True

    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda _name: comb.idaapi.BADADDR)
    assert comb.search_noreach(2, 0, 20)["error"] is True
    monkeypatch.setattr(comb, "_all_entry_points", lambda: list(names))
    monkeypatch.setattr(comb, "_reach_from", lambda *_args: set())
    assert comb.search_noreach(2, 0, 1)["truncated"] is True


def test_outlier_direct_metrics_cover_thresholds_and_failures(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    for metric in ("size", "tiny", "huge", "bb_count"):
        result = comb.search_analyze(scope="outlier", metric=metric, limit=10)
        assert result["ok"] is True
        assert result["note"].endswith("direct IDA enumeration.")
    assert comb.search_analyze(scope="outlier", metric="complexity")["error"] is True

    monkeypatch.setattr(comb._compat, "get_flow_chart", lambda _ea: (_ for _ in ()).throw(RuntimeError("flow chart")))
    rows = comb._outlier_rows_from_ida("bb_count")
    assert all(row[2] == 0 for row in rows)
    assert comb._outlier_rows_from_ida("complexity") == []


def test_outlier_graph_metrics_and_neighborhood_context(monkeypatch):
    comb, _names, edges = _function_surface(monkeypatch)
    comb._CALL_GRAPH_CACHE.clear()
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: {"func_size": 16, "bb_count": 2, "cyclomatic": 1})
    monkeypatch.setattr(comb, "_get_behavior_tags", lambda _ea: ["loader"])
    monkeypatch.setattr(comb, "_get_embedding_similar", lambda _ea, top_k=10: [{"addr": "0x2000", "name": "helper", "similarity": 0.8}])
    neighborhood = comb.search_analyze(addr="0x1000", scope="neighborhood", radius=5, include_items=True)
    assert neighborhood["ok"] is True
    assert neighborhood["tags"] == ["loader"]
    assert neighborhood["similar"][0]["name"] == "helper"
    assert neighborhood["items"]

    for metric in ("orphan", "leaf", "hub", "deep"):
        result = comb.search_analyze(scope="outlier", metric=metric, limit=10)
        assert result["ok"] is True, (metric, result)
    assert comb.search_analyze(scope="outlier", metric="bogus")["error"] is True

    monkeypatch.setattr(comb, "_get_call_graph", lambda: {"callers": {}, "callees": {}})
    assert comb.search_analyze(scope="vulnerable", depth=2)["ok"] is True
    assert comb.search_analyze(scope="auto", metric=None)["error"] is True


def test_similar_vulnerable_and_semantic_fallbacks(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb, "_get_embedding_similar", lambda *_args, **_kwargs: [{"addr": "0x2000", "name": "helper", "similarity": 0.75}])
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: None)
    similar = comb.search_analyze(addr="0x1000", scope="similar", include_items=False)
    assert similar["ok"] is True and similar["items"][0]["name"] == "helper"
    assert comb.search_analyze(scope="similar")["error"] is True

    graph = {"callers": {0x1000: {0x2000}}, "callees": {0x2000: {0x3000}}}
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x1000, "read")])
    monkeypatch.setattr(comb.idc, "get_func_name", lambda ea: {0x1000: "read", 0x2000: "handler"}.get(ea, ""))
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x3000 else "")
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: None)
    vulnerable = comb.search_analyze(scope="vulnerable", depth=1)
    assert vulnerable["ok"] is True and vulnerable["taint_sources"] == 1
    assert comb.search_analyze(scope="vulnerable", depth=1, pattern="unmatched")["count"] == 0

    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    assert comb.search_analyze(scope="semantic", pattern="crypto")["error"] is True


def test_primitive_size_mnemonic_api_and_text_paths(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x2000 else "")
    monkeypatch.setattr(comb.idaapi, "GN_VISIBLE", 0, raising=False)
    monkeypatch.setattr(comb.idc, "print_insn_mnem", lambda ea: "ret" if ea == 0x1000 else "call")
    monkeypatch.setattr(comb.idc, "next_head", lambda _ea, _end: comb.idaapi.BADADDR)
    assert comb._prim_size("16") == {0x1000}
    assert comb._prim_size("invalid") == set()
    assert comb._prim_funcs_by_mnem("ret") == {0x1000}
    assert comb._prim_funcs_by_api("mem") == {0x1000}
    assert comb._prim_leaf("true") == {0x2000, 0x3000}

    monkeypatch.setattr(comb.idautils, "XrefsTo", lambda ea, *_args: [SimpleNamespace(frm=0x1000, iscode=True)] if ea == 0x2000 else [])
    assert comb._prim_no_callers("true") == {0x1000, 0x3000}
