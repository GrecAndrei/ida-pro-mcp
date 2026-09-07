"""Exercise remaining search-combinator modes through stable boundaries."""

from __future__ import annotations

import sqlite3
import struct
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
    monkeypatch.setattr(
        comb.idc,
        "print_insn_mnem",
        lambda ea: "nop" if ea == 0x1000 else ("ret" if ea == 0x1004 else "call"),
    )
    monkeypatch.setattr(
        comb.idc,
        "next_head",
        lambda cur, _end: 0x1004 if cur == 0x1000 else comb.idaapi.BADADDR,
    )
    assert comb._prim_size("16") == {0x1000}
    assert comb._prim_size("invalid") == set()
    assert comb._prim_funcs_by_mnem("ret") == {0x1000}
    assert comb._prim_funcs_by_api("mem") == {0x1000}
    assert comb._prim_leaf("true") == {0x2000, 0x3000}

    monkeypatch.setattr(comb.idautils, "XrefsTo", lambda ea, *_args: [SimpleNamespace(frm=0x1000, iscode=True)] if ea == 0x2000 else [])
    assert comb._prim_no_callers("true") == {0x1000, 0x3000}


def test_primitives_swallow_exceptions_and_empty_functions(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idautils, "Functions", lambda: (_ for _ in ()).throw(RuntimeError("no funcs")))
    assert comb._all_func_eas() == set()

    monkeypatch.setattr(comb.idc, "get_func_name", lambda _ea: (_ for _ in ()).throw(RuntimeError("no name")))
    assert comb._func_name(0x1000) == "0x1000"

    assert comb._tokenize_bool('"standalone \\"quoted\\""') == ['LITERAL:standalone "quoted"']

    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000])

    hexrays = types.ModuleType("ida_hexrays")
    hexrays.decompile = lambda _ea: (_ for _ in ()).throw(RuntimeError("decomp error"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", hexrays)
    assert comb._prim_funcs_by_string("query") == set()

    monkeypatch.setattr(comb, "_func_callees", lambda _ea: (_ for _ in ()).throw(RuntimeError("callees error")))
    assert comb._prim_funcs_by_api("api") == set()
    assert comb._prim_leaf("leaf") == set()

    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: (_ for _ in ()).throw(RuntimeError("func info error")))
    assert comb._prim_funcs_by_mnem("ret") == set()
    assert comb._prim_size("16") == set()

    ida_typeinf = types.ModuleType("ida_typeinf")
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("tinfo error"))
    monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)
    assert comb._prim_args("2") == set()

    monkeypatch.setattr(comb.idautils, "XrefsTo", lambda *_args: (_ for _ in ()).throw(RuntimeError("xrefs error")))
    assert comb._prim_no_callers("true") == set()


def test_graph_traversals_handle_diamond_visited_nodes(monkeypatch):
    comb = _module()
    edges = {
        0x1000: {0x2000, 0x3000},
        0x2000: {0x4000},
        0x3000: {0x4000},
        0x4000: {0x5000},
        0x5000: set(),
    }
    monkeypatch.setattr(comb, "_func_callees", lambda ea: edges.get(ea, set()))
    path = comb._bfs_path(0x1000, 0x5000, max_depth=5)
    assert path is not None
    reachable = comb._reach_from(0x1000, max_depth=5)
    assert reachable == {0x1000, 0x2000, 0x3000, 0x4000, 0x5000}


def test_get_entry_points_handles_exceptions_and_symbol_fallbacks(monkeypatch):
    comb = _module()
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_entry_qty = lambda: 1
    ida_nalt.get_entry_ordinal = lambda _idx: (_ for _ in ()).throw(RuntimeError("nalt error"))
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)

    calls = [0]

    def fake_get_name_ea(sym):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("symbol lookup error")
        return 0x1000 if sym == "_start" else comb.idaapi.BADADDR

    monkeypatch.setattr(comb.idc, "get_name_ea_simple", fake_get_name_ea)
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea == 0x1000 else None)
    assert comb._all_entry_points() == [0x1000]


def test_outliers_fallback_skips_missing_func(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    monkeypatch.setattr(comb._compat, "get_func_info", lambda ea: None if ea == 0x1000 else SimpleNamespace(start_ea=0x2000, end_ea=0x2040))
    monkeypatch.setattr(comb, "_func_name", hex)
    rows = comb._outlier_rows_from_ida("size")
    assert len(rows) == 1 and rows[0][0] == 0x2000


def test_index_metadata_and_embedding_similar_sqlite(monkeypatch, tmp_path):
    comb = _module()

    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    assert comb._get_index_metadata(0x1000) is None
    assert comb._get_embedding_similar(0x1000) == []

    db_path = tmp_path / "test_embeddings.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE func_embeddings ("
        "ea TEXT PRIMARY KEY, func_size INT, bb_count INT, has_loops INT, "
        "api_count INT, string_count INT, segment TEXT, is_thunk INT, cyclomatic INT, vec_blob BLOB)"
    )
    vec_bytes = struct.pack("<3f", 0.1, 0.2, 0.3)
    conn.execute(
        "INSERT INTO func_embeddings VALUES ('0x1000', 64, 4, 1, 3, 2, '.text', 0, 5, ?)",
        (vec_bytes,)
    )
    conn.commit()

    class MockIndex:
        size = 1

        def _conn(self):
            return sqlite3.connect(str(db_path))

        def similar_vec(self, _v, top_k, threshold):
            return [
                {"ea": "0x1000", "addr": "0x1000", "name": "self", "similarity": 1.0},
                {"ea": "0x2000", "addr": "0x2000", "name": "sim", "similarity": 0.85},
            ]

    services = types.ModuleType("ida_pro_mcp.services")
    asm = SimpleNamespace(_get_index=lambda _path: MockIndex())
    services.get_assembler = lambda: asm
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.idb", raising=False)

    meta = comb._get_index_metadata(0x1000)
    assert meta is not None and meta["func_size"] == 64 and meta["cyclomatic"] == 5

    sim = comb._get_embedding_similar(0x1000)
    assert len(sim) == 1 and sim[0]["name"] == "sim"
    assert comb._get_embedding_similar(0x9999) == []

    class BrokenConnIndex:
        size = 1

        def _conn(self):
            raise RuntimeError("sqlite open error")

    asm._get_index = lambda _path: BrokenConnIndex()
    assert comb._get_index_metadata(0x1000) is None
    assert comb._get_embedding_similar(0x1000) == []

    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]
    package._load_insight_index = lambda: {"tag_map": {"crypto": ["0x1000"]}}
    tags = comb._get_behavior_tags(0x1000)
    assert tags == ["crypto"]


def test_search_analyze_auto_scope_matrix(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    monkeypatch.setattr(comb, "resolve_target", lambda target: (0x1000, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1020))
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: SimpleNamespace(_get_index=lambda _path: None)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)

    r1 = comb.search_analyze(addr="0x1000", metric="bb_count")
    assert r1.get("scope") == "outlier"

    r2 = comb.search_analyze(addr="0x1000", pattern="crypto")
    assert r2.get("error") is True and "indexed" in r2.get("message", "").lower()

    r3 = comb.search_analyze(addr="0x1000")
    assert r3.get("scope") == "neighborhood"

    r4 = comb.search_analyze(pattern="crypto")
    assert r4.get("error") is True and "indexed" in r4.get("message", "").lower()

    r5 = comb.search_analyze(metric="size")
    assert r5.get("scope") == "outlier"


def test_search_analyze_neighborhood_blackboard_and_errors(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)
    assert comb.search_analyze(scope="neighborhood")["error"] is True

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (comb.idaapi.BADADDR, "not found", {}))
    assert comb.search_analyze(scope="neighborhood", addr="bad")["error"] is True

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1020))
    monkeypatch.setattr(comb, "_get_call_graph", lambda: {"callers": {0x1000: {0x2000}}, "callees": {0x1000: {0x3000}}})

    class Store:
        def list(self, **_kwargs):
            return [{"title": "Vuln found", "category": "vuln", "confidence": 0.9}]

    blackboard = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    blackboard.BlackboardStore = Store
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", blackboard)

    res = comb.search_analyze(scope="neighborhood", addr="0x1000")
    assert res["ok"] is True
    assert "blackboard (1): Vuln found" in res["results"]
    assert "callers (1):" in res["results"]

    class BrokenStore:
        def list(self, **_kwargs):
            raise RuntimeError("store broken")

    blackboard.BlackboardStore = BrokenStore
    res_broken = comb.search_analyze(scope="neighborhood", addr="0x1000")
    assert res_broken["ok"] is True


def test_search_analyze_similar_and_vulnerable_deep_branches(monkeypatch):
    comb, _names, _edges = _function_surface(monkeypatch)

    monkeypatch.setattr(comb, "_outlier_rows_from_ida", lambda _m: (_ for _ in ()).throw(RuntimeError("calc failed")))
    res_err = comb.search_analyze(scope="outlier", metric="size")
    assert res_err["error"] is True and "Could not compute" in res_err["message"]

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (comb.idaapi.BADADDR, "bad", {}))
    assert comb.search_analyze(scope="similar", addr="bad")["error"] is True

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x9999, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_start", lambda _ea: None)
    assert comb.search_analyze(scope="similar", addr="0x9999")["error"] is True

    graph = {"callers": {0x1000: set()}, "callees": {0x1000: {0x2000}}}
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x1000, "read"), (0x1050, "recv")])
    monkeypatch.setattr(comb.idc, "get_func_name", lambda ea: "read" if ea == 0x1000 else "")
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x2000 else "")

    class VulnerableIndex:
        size = 1

        def search(self, q, **_kwargs):
            if "fail" in q:
                raise RuntimeError("search failed")
            return [
                {"ea": "0x3000", "similarity": 0.8},
                {"ea": "0x4000", "similarity": 0.7},
            ]

    services = types.ModuleType("ida_pro_mcp.services")
    asm = SimpleNamespace(
        _get_index=lambda _path: VulnerableIndex(),
        _behavior_classifier=SimpleNamespace,
    )
    services.get_assembler = lambda: asm
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.idb", raising=False)

    seen_1050 = [False]

    def func_start_candidates(ea):
        if ea == 0x1050:
            if not seen_1050[0]:
                seen_1050[0] = True
                return 0x1050
            return None
        if ea == 0x1000:
            return 0x1000
        if ea == 0x3000:
            return None
        if ea == 0x4000:
            return 0x4000
        return None

    monkeypatch.setattr(comb._compat, "get_func_start", func_start_candidates)
    comb._VULN_ANCHORS = ["fail_query", "anchor2"]
    res_vuln = comb.search_analyze(scope="vulnerable", depth=5)
    assert res_vuln["ok"] is True
