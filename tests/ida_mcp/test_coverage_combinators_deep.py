"""Behavior coverage for search combinators across fallback and index modes."""

from __future__ import annotations

import struct
import sys
import types

from tests._isolated_repo_loader import load_tool_submodule

BADADDR = -1


def _module():
    mod = load_tool_submodule("search.combinators")
    mod.idaapi.BADADDR = BADADDR
    return mod


def test_set_helpers_and_graph_fallbacks_handle_sdk_failures(monkeypatch):
    mod = _module()

    def _broken_functions():
        raise RuntimeError("Functions unavailable")

    mod.idautils.Functions = _broken_functions
    assert mod._all_func_eas() == set()
    mod.idc.get_func_name = lambda _ea: (_ for _ in ()).throw(RuntimeError("name"))
    assert mod._func_name(0x1234) == "0x1234"
    mod._func_name = lambda _ea: (_ for _ in ()).throw(RuntimeError("name"))
    assert mod._set_to_items({0x1234}, 0, 1) == [
        {"addr": "0x1234", "ea": 0x1234, "name": "0x1234"}
    ]

    mod._compat.get_func_start = lambda _ea: 0x1000
    mod.idautils.FuncItems = lambda _ea: iter([0x1000])
    mod.idautils.XrefsFrom = lambda *_args: (_ for _ in ()).throw(RuntimeError("xref"))
    assert mod._func_callees(0x1000) == set()


def test_primitive_searches_keep_bad_rows_and_sdk_errors_isolated(monkeypatch):
    mod = _module()
    mod.idaapi.GN_VISIBLE = 1
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    mod._func_name = lambda ea: {0x1000: "alpha", 0x2000: "beta"}[ea]

    mod.idc.get_func_name = lambda ea: {0x1000: "alpha", 0x2000: "beta"}[ea]
    mod._compat.get_func_info = lambda ea: (
        types.SimpleNamespace(start_ea=ea, end_ea=ea + 4) if ea == 0x1000 else None
    )
    mod.idc.print_insn_mnem = lambda _ea: "ret"
    mod.idc.next_head = lambda _ea, _end: BADADDR
    assert mod._prim_funcs_by_mnem("ret") == {0x1000}

    mod._func_callees = lambda _ea: (_ for _ in ()).throw(RuntimeError("callee"))
    assert mod._prim_funcs_by_api("mem*") == set()

    mod.resolve_target = lambda _target: (0x1000, None, None)
    mod.idautils.XrefsTo = lambda *_args: iter([
        types.SimpleNamespace(iscode=False, frm=0x1100),
        types.SimpleNamespace(iscode=True, frm=0x1200),
    ])
    mod._compat.get_func_start = lambda _ea: None
    assert mod._prim_callers("alpha") == set()

    mod._compat.get_func_info = lambda _ea: (_ for _ in ()).throw(RuntimeError("info"))
    assert mod._prim_size(">1") == set()
    mod.ida_nalt.get_tinfo = lambda *_args: False
    assert mod._prim_args("1") == set()


class _Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class _Connection:
    def __init__(self, row, vec_blob=None):
        self.row = row
        self.vec_blob = vec_blob

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, *_args):
        if len(_args) > 0 and "vec_blob" in str(_args[0]):
            return _Cursor((self.vec_blob,))
        return _Cursor(self.row)


class _Index:
    size = 1

    def __init__(self, row, similar=(), vec_blob=None):
        self.row = row
        self.similar = list(similar)
        self.vec_blob = vec_blob

    def _conn(self):
        return _Connection(self.row, self.vec_blob)

    def similar_vec(self, *_args, **_kwargs):
        return list(self.similar)


def _services(monkeypatch, index):
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: types.SimpleNamespace(_get_index=lambda _path: index)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)


def test_index_metadata_and_embedding_similarity_paths(monkeypatch):
    mod = _module()
    mod.idc.get_idb_path = lambda: "/tmp/combinator-test.i64"
    metadata_row = (32, 2, 1, 3, 4, ".text", 0, 2)
    index = _Index(metadata_row, similar=[
        {"ea": "0x1000", "addr": "0x1000", "name": "self", "similarity": 1.0},
        {"ea": "0x2000", "addr": "0x2000", "name": "other", "similarity": 0.8},
    ], vec_blob=struct.pack("<2f", 1.0, 0.0))
    _services(monkeypatch, index)
    assert mod._get_index_metadata(0x1000) == {
        "func_size": 32, "bb_count": 2, "has_loops": True, "api_count": 3,
        "string_count": 4, "segment": ".text", "is_thunk": False, "cyclomatic": 2,
    }
    mod._get_index_metadata = lambda _ea: None
    assert mod._get_embedding_similar(0x1000, top_k=1) == [
        {"ea": "0x2000", "addr": "0x2000", "name": "other", "similarity": 0.8}
    ]

    mod.idc.get_idb_path = lambda: ""
    assert mod._get_index_metadata(0x1000) is None
    assert mod._get_embedding_similar(0x1000) == []


def test_neighborhood_and_outlier_graph_modes_shape_results(monkeypatch):
    mod = _module()
    names = {0x1000: "root", 0x2000: "caller", 0x3000: "callee"}
    mod._func_name = lambda ea: names.get(ea, hex(ea))
    mod.resolve_target = lambda _addr: (0x1000, None, None)
    mod._compat.get_func_info = lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1040)
    mod._get_index_metadata = lambda _ea: {
        "func_size": 64, "bb_count": 3, "cyclomatic": 2,
    }
    mod._get_call_graph = lambda: {
        "callers": {0x1000: {0x2000}}, "callees": {0x1000: {0x3000}},
    }
    mod._get_behavior_tags = lambda _ea: ["crypto"]
    mod._get_embedding_similar = lambda _ea, top_k=10: [
        {"addr": "0x4000", "name": "similar", "similarity": 0.75}
    ]
    blackboard = types.ModuleType("ida_mcp.ida_mcp.tools.blackboard")
    blackboard.BlackboardStore = lambda: types.SimpleNamespace(
        list=lambda **_kwargs: [{"title": "note", "category": "finding", "confidence": 0.9}]
    )
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", blackboard)
    monkeypatch.setitem(sys.modules, "ida_mcp.ida_mcp.tools.blackboard", blackboard)
    neighborhood = mod.search_analyze(addr="root", scope="neighborhood", radius=3)
    assert neighborhood["tags"] == ["crypto"]
    assert neighborhood["blackboard"] == [{"title": "note", "category": "finding", "confidence": 0.9}]
    assert neighborhood["items"] == [
        {"type": "caller", "addr": "0x2000", "name": "caller"},
        {"type": "callee", "addr": "0x3000", "name": "callee"},
    ]

    mod.idautils.Functions = lambda: iter([0x1000, 0x2000, 0x3000])
    mod._get_call_graph = lambda: {
        "callers": {0x1000: {0x2000}},
        "callees": {0x1000: {0x3000}},
    }
    for metric in ("orphan", "leaf", "hub", "deep"):
        result = mod.search_analyze(scope="outlier", metric=metric, limit=10)
        assert result["ok"] is True and result["metric"] == metric


def test_vulnerable_and_semantic_index_candidates_are_returned(monkeypatch):
    mod = _module()
    names = {0x1000: "recv", 0x2000: "handler", 0x3000: "candidate", 0x4000: "memcpy"}
    mod.idautils.Functions = lambda: iter(names)
    mod.idautils.Names = lambda: iter([(0x1000, "recv")])
    mod.idc.get_func_name = lambda ea: names.get(ea, "")
    mod.idc.get_name = lambda ea, *_args: names.get(ea, "")
    mod._compat.get_func_start = lambda ea: ea if ea in names else None
    mod._get_call_graph = lambda: {
        "callers": {0x1000: {0x2000}, 0x2000: {0x3000}},
        "callees": {0x2000: {0x4000}},
    }
    mod._TAINT_SOURCE_NAMES = {"recv"}
    mod._DANGEROUS_APIS = {"memcpy": "buffer_overflow"}

    class VulnerabilityIndex:
        size = 1

        def search(self, *_args, **_kwargs):
            return [{"addr": "0x3000", "similarity": 0.8}]

    class Assembler:
        def _get_index(self, _path):
            return VulnerabilityIndex()

        def _behavior_classifier(self):
            return object()

    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = Assembler
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    mod.idc.get_idb_path = lambda: "/tmp/combinator-test.i64"
    vulnerable = mod.search_analyze(scope="vulnerable", pattern="behavior", depth=20)
    assert vulnerable["ok"] is True
    assert any(item["vuln_type"] == "behavior_candidate" for item in vulnerable["items"])

    class SemanticIndex:
        size = 1

        def hybrid_search(self, *_args, **_kwargs):
            return [{"ea": "0x3000", "name": "candidate", "score": 0.8, "similarity": 0.7}]

    services.get_assembler = lambda: types.SimpleNamespace(_get_index=lambda _path: SemanticIndex())
    mod._get_index_metadata = lambda _ea: {
        "func_size": 12, "bb_count": 1, "cyclomatic": 1,
    }
    semantic = mod.search_analyze(scope="semantic", pattern="crypto", limit=2)
    assert semantic["items"][0]["size"] == 12
    assert semantic["truncated"] is False


def test_call_graph_fingerprint_and_embedding_failures_are_fail_open(monkeypatch):
    mod = _module()
    mod.idc.get_idb_path = lambda: "/tmp/combinator-test.i64"
    mod.idautils.Functions = lambda: (_ for _ in ()).throw(RuntimeError("functions"))
    mod.idautils.Names = lambda: (_ for _ in ()).throw(RuntimeError("names"))
    assert mod._idb_cheap_key() == "unknown"
    assert mod._idb_fingerprint() == "unknown"
    mod._CALL_GRAPH_CACHE.clear()
    mod.idautils.Functions = lambda: iter(())
    assert mod._get_call_graph() == {"callers": {}, "callees": {}}
    mod.idc.get_idb_path = lambda: (_ for _ in ()).throw(RuntimeError("path"))
    assert mod._idb_cheap_key() == "unknown"
    assert mod._get_embedding_similar(0x1000) == []
