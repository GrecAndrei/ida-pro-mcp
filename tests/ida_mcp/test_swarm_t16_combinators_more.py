"""Composed offline coverage for boolean, graph, and structural searches."""

from __future__ import annotations

import sys
import types

import pytest

from tests._isolated_repo_loader import load_tool_submodule

BADADDR = -1


def _module():
    mod = load_tool_submodule("search.combinators")
    mod.idaapi.BADADDR = BADADDR
    mod.idc.get_func_name = lambda ea: {0x1000: "root", 0x2000: "child", 0x3000: "leaf"}.get(ea, hex(ea))
    mod.idc.get_name = lambda ea, *_args: {0x4000: "memcpy"}.get(ea, "")
    mod.idc.get_name_ea_simple = lambda _name: BADADDR
    mod._compat.get_func_start = lambda ea: ea
    mod._compat.get_func_info = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 0x20)
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000, 0x3000])
    return mod


def test_function_callees_call_filter_and_import_fallback():
    mod = _module()
    call_type = next(iter(mod.CALL_XREF_TYPES))
    refs = [
        types.SimpleNamespace(type=call_type, to=0x2000),
        types.SimpleNamespace(type=999, to=0x3000),
        types.SimpleNamespace(type=call_type, to=0x5000),
    ]
    mod.idautils.FuncItems = lambda _ea: iter([0x1000, 0x1004])
    mod.idautils.XrefsFrom = lambda ea, _flow: iter(refs if ea == 0x1000 else [])
    mod._compat.get_func_start = lambda ea: None if ea == 0x5000 else ea
    mod.idc.get_name = lambda ea, *_args: "._memcpy" if ea == 0x5000 else ""
    mod.idc.get_name_ea_simple = lambda name: 0x4000 if name == "memcpy" else BADADDR
    assert mod._func_callees(0x1000) == {0x2000, 0x4000}
    mod._compat.get_func_start = lambda _ea: None
    assert mod._func_callees(0x1000) == set()


def test_primitives_cover_names_strings_api_mnemonics_and_shapes():
    mod = _module()
    mod.idaapi.GN_VISIBLE = 1
    mod._func_name = lambda ea: {0x1000: "Main", 0x2000: "worker"}.get(ea, "")
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    assert mod._prim_funcs_by_name("main") == {0x1000}

    mod.ida_hexrays.decompile = lambda ea: "secret" if ea == 0x1000 else None
    assert mod._prim_funcs_by_string("secret") == {0x1000}
    mod._func_callees = lambda ea: {0x4000} if ea == 0x1000 else set()
    mod.idc.get_name = lambda ea, *_args: "CryptoEncrypt" if ea == 0x4000 else ""
    assert mod._prim_funcs_by_api("crypto") == {0x1000}

    mod.idautils.FuncItems = lambda ea: iter([ea])
    mod.idc.print_insn_mnem = lambda _ea: "mov"
    mod.idc.next_head = lambda _ea, _end: BADADDR
    assert mod._prim_funcs_by_mnem("mov") == {0x1000, 0x2000}

    mod.resolve_target = lambda target: (0x2000, None, None) if target == "worker" else (BADADDR, {"error": True}, None)
    mod.idautils.XrefsTo = lambda _ea, _flow: iter([types.SimpleNamespace(iscode=True, frm=0x1000)])
    assert mod._prim_callers("worker") == {0x1000}
    assert mod._prim_callers("missing") == set()
    mod._func_callees = lambda _ea: {0x3000}
    assert mod._prim_callees("worker") == {0x3000}
    assert mod._prim_callees("missing") == set()

    mod._compat.get_func_info = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + {0x1000: 120, 0x2000: 20}.get(ea, 0))
    assert mod._prim_size(">100") == {0x1000}
    assert mod._prim_size("10-30") == {0x2000}
    assert mod._prim_size("garbage") == set()

    class Tinfo:
        def get_func_details(self, data):
            data.size = lambda: 3
            return True

    mod.ida_typeinf.tinfo_t = Tinfo
    mod.ida_typeinf.func_type_data_t = types.SimpleNamespace
    mod.ida_nalt.get_tinfo = lambda *_args: True
    assert mod._prim_args("3") == {0x1000, 0x2000}
    assert mod._prim_args("2+") == {0x1000, 0x2000}
    assert mod._prim_args("nope") == set()

    mod._func_callees = lambda ea: {0x3000} if ea == 0x1000 else set()
    mod.idautils.XrefsTo = lambda ea, _flow: iter([] if ea != 0x1000 else [types.SimpleNamespace(iscode=False, frm=0x2000)])
    assert mod._prim_leaf("true") == {0x2000}
    assert mod._prim_no_callers("true") == {0x1000, 0x2000}


def test_bool_tokenizer_parser_and_response_errors(monkeypatch):
    mod = _module()
    assert mod._tokenize_bool('(name:"foo \\"bar\\"" && !leaf) || no_callers') == [
        "(", 'name:foo "bar"', "AND", "NOT", "leaf:true", ")", "OR", "no_callers:true",
    ]
    assert mod._tokenize_bool("name:foo || name:bar")[-2:] == ["OR", "name:bar"]
    parser = mod._BoolParser(["name:x", "AND", "name:y"])
    monkeypatch.setitem(mod._BOOL_PRIMITIVES, "name", lambda value, **_kw: {0x1000} if value == "x" else {0x1000, 0x2000})
    assert parser.parse_expr() == {0x1000}
    assert mod._BoolParser(["NOT", "name:x"]).parse_expr() == {0x2000, 0x3000}

    mod._BOOL_PRIMITIVES["name"] = lambda value, **_kw: {0x1000} if value else set()
    mod._all_func_eas = lambda: {0x1000, 0x2000}
    assert mod.search_bool("name:yes", False, 0, 1)["truncated"] is False
    assert mod.search_bool("", False, 0, 5)["code"] == "INVALID_ARGS"
    assert mod.search_bool("!!!", False, 0, 5)["code"] == "INVALID_ARGS"
    assert mod.search_bool("unknown:x", False, 0, 5)["code"] == "INVALID_ARGS"
    assert mod.search_bool("name:yes trailing", False, 0, 5)["code"] == "INVALID_ARGS"


def test_path_reachability_and_entry_point_fallbacks(monkeypatch):
    mod = _module()
    graph = {0x1000: {0x2000}, 0x2000: {0x3000}, 0x3000: set()}
    mod._func_callees = lambda ea: graph.get(ea, set())
    assert mod._bfs_path(0x1000, 0x1000, 2) == [0x1000]
    assert mod._bfs_path(0x1000, 0x3000, 3) == [0x1000, 0x2000, 0x3000]
    assert mod._bfs_path(0x1000, 0x3000, 1) is None
    mod.resolve_target = lambda target: (int(target, 0), None, None)
    mod._compat.get_func_start = lambda ea: ea if ea in graph else None
    found = mod.search_path("0x1000", "0x3000", 3)
    assert found["hops"] == 2 and "<-- dst" in found["results"]
    missing = mod.search_path("0x3000", "0x1000", 2)
    assert missing["count"] == 0

    reached = mod._reach_from(0x1000, 1)
    assert reached == {0x1000, 0x2000}
    reach = mod.search_reach("0x1000", 2, 0, 10)
    assert reach["items"][0]["ea"] == 0x2000
    mod.resolve_target = lambda *_args: (BADADDR, {"error": True}, None)
    assert mod.search_reach("bad", 2, 0, 10)["code"] == "INVALID_ARGS"

    mod.ida_nalt.get_entry_qty = lambda: 0
    mod.idc.get_name_ea_simple = lambda name: 0x1000 if name == "main" else BADADDR
    assert mod._all_entry_points() == [0x1000]
    mod.idc.get_name_ea_simple = lambda _name: BADADDR
    assert mod._all_entry_points() == []
    assert mod.search_noreach(2, 0, 10)["code"] == "INVALID_ARGS"

    monkeypatch.setattr(mod, "_all_entry_points", lambda: [0x1000])
    mod._all_func_eas = lambda: {0x1000, 0x2000, 0x3000}
    assert mod.search_noreach(1, 0, 10)["items"] == [{"addr": "0x3000", "ea": 0x3000, "name": "leaf"}]


def test_outlier_direct_metrics_and_delegating_actions(monkeypatch):
    mod = _module()
    mod._compat.get_func_info = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + (8 if ea == 0x1000 else 5000))
    mod._compat.get_flow_chart = lambda _ea: [1, 2]
    mod._func_name = lambda ea: {0x1000: "tiny", 0x2000: "huge"}[ea]
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    assert mod._outlier_rows_from_ida("tiny") == [(0x1000, "tiny", 8)]
    assert mod._outlier_rows_from_ida("huge") == [(0x2000, "huge", 5000)]
    assert mod._outlier_rows_from_ida("bad") == []
    assert mod.search_analyze(scope="outlier", metric="tiny", limit=10)["count"] == 1
    assert mod.search_analyze(scope="outlier", metric="huge", limit=10)["count"] == 1
    assert mod.search_analyze(scope="outlier", metric="complexity")["code"] == "NOT_FOUND"
    assert mod.search_analyze(scope="outlier", metric="bad")["code"] == "INVALID_ARGS"

    monkeypatch.setattr(mod, "search_analyze", lambda **kwargs: {"scope": kwargs["scope"], "addr": kwargs.get("addr")})
    assert mod.search_neighborhood("0x1000", 2, 0, 5)["scope"] == "neighborhood"
    assert mod.search_outlier("size", 2, 0, 5)["scope"] == "outlier"
    assert mod.search_fingerprint("0x1000", 2, 0, 5)["scope"] == "similar"


def test_neighborhood_similar_vulnerable_and_semantic_scopes(monkeypatch):
    mod = _module()
    mod.resolve_target = lambda _addr: (0x1000, None, None)
    mod._compat.get_func_info = lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1040)
    mod._func_name = lambda ea: {0x1000: "root", 0x2000: "caller", 0x3000: "callee"}.get(ea, hex(ea))
    mod._get_index_metadata = lambda _ea: {"func_size": 64, "bb_count": 2, "cyclomatic": 2}
    mod._get_call_graph = lambda: {"callers": {0x1000: {0x2000}}, "callees": {0x1000: {0x3000}}}
    mod._get_behavior_tags = lambda _ea: ["crypto"]
    mod._get_embedding_similar = lambda _ea, top_k=10: [{"addr": "0x4000", "name": "similar", "similarity": 0.876}]
    mod._get_blackboard_context_for_addr = lambda _addr: []
    neighborhood = mod.search_analyze(addr="0x1000", scope="neighborhood", include_items=False)
    assert neighborhood["tags"] == ["crypto"] and neighborhood["items"] == []

    similar = mod.search_analyze(addr="0x1000", scope="similar", top_k=2)
    assert similar["items"][0]["score"] == 0.876
    assert mod.search_analyze(scope="neighborhood")["code"] == "INVALID_ARGS"

    mod._get_call_graph = lambda: {"callers": {0x1000: {0x2000}}, "callees": {0x2000: {0x4000}}}
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    mod.idautils.Names = lambda: iter([(0x1000, "recv"), (0x2000, "handler")])
    mod.idc.get_func_name = lambda ea: {0x1000: "recv", 0x2000: "handler"}.get(ea, "")
    mod.idc.get_name = lambda ea, *_args: "memcpy" if ea == 0x4000 else ""
    mod._TAINT_SOURCE_NAMES = {"recv"}
    mod._DANGEROUS_APIS = {"memcpy": "buffer_overflow"}
    vuln = mod.search_analyze(scope="vulnerable", pattern="buffer")
    assert vuln["count"] == 1 and vuln["items"][0]["api"] == "memcpy"

    class Index:
        size = 1

        def hybrid_search(self, *_args, **_kwargs):
            return [{"ea": "0x1000", "name": "root", "score": 0.8, "similarity": 0.7}]

    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: types.SimpleNamespace(_get_index=lambda _path: Index())
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    mod.idc.get_idb_path = lambda: "/tmp/fake.idb"
    semantic = mod.search_analyze(scope="semantic", pattern="crypto")
    assert semantic["count"] == 1 and semantic["items"][0]["name"] == "root"
    assert mod.search_analyze(scope="semantic")["code"] == "INVALID_ARGS"
