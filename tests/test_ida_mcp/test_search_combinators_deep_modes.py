"""Exercise indexed, cached, and vulnerability-analysis combinator modes."""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.combinators")


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class _Conn:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, _params=()):
        if "COUNT(*)" in query:
            return _Rows([(2,)])
        if "vec_blob" in query:
            return _Rows([(b"",)])
        return _Rows(self.rows)


class _Index:
    size = 2

    def __init__(self, rows):
        self.rows = rows

    def _conn(self):
        return _Conn(self.rows)

    def hybrid_search(self, *_args, **_kwargs):
        return [
            {"ea": "0x1000", "addr": "0x1000", "name": "entry", "score": 0.9, "similarity": 0.8},
            {"ea": "0x2000", "addr": "0x2000", "name": "helper", "score": 0.7, "similarity": 0.6},
        ]


def test_call_graph_cache_cold_warm_and_fingerprint_modes(monkeypatch):
    comb = _module()
    comb._CALL_GRAPH_CACHE.clear()
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "", raising=False)
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000], raising=False)
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x1000, "entry")], raising=False)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())
    first = comb._get_call_graph()
    second = comb._get_call_graph()
    assert first is second
    assert first["callees"][0x1000] == {0x2000}
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000], raising=False)
    rebuilt = comb._get_call_graph()
    assert rebuilt["callees"][0x1000] == {0x2000}
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: (_ for _ in ()).throw(OSError("no idb")), raising=False)
    assert comb._idb_cheap_key() == "unknown"
    monkeypatch.setattr(comb.idautils, "Functions", lambda: (_ for _ in ()).throw(RuntimeError("no functions")), raising=False)
    assert comb._idb_fingerprint() == "unknown"


def test_index_backed_outlier_and_semantic_modes(monkeypatch):
    comb = _module()
    index = _Index([("0x1000", "entry", 100), ("0x2000", "helper", 10)])
    assembler = types.SimpleNamespace(_get_index=lambda _path: index)
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: assembler
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    for metric in ("size", "tiny", "huge", "bb_count"):
        result = comb.search_analyze(scope="outlier", metric=metric, offset=0, limit=1)
        assert result["ok"] is True
        assert result["note"].endswith("embedding index.")
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: None)
    monkeypatch.setattr(comb, "_coerce_ea", lambda value: int(str(value), 0))
    semantic = comb.search_analyze(scope="semantic", pattern="crypto", offset=0, limit=1)
    assert semantic["ok"] is True
    assert semantic["truncated"] is True
    assert semantic["items"][0]["name"] == "entry"


def test_vulnerable_scope_bridges_aliases_and_pattern_filters(monkeypatch):
    comb = _module()
    graph = {"callers": {0x1000: {0x2000}}, "callees": {0x2000: {0x3000}}}
    monkeypatch.setattr(comb, "_get_call_graph", lambda: graph)
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000, 0x3000], raising=False)
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x1000, "read")], raising=False)
    monkeypatch.setattr(comb.idc, "get_func_name", lambda ea: {0x1000: "read", 0x2000: "handler", 0x3000: "memcpy"}.get(ea, ""), raising=False)
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_args: "memcpy" if ea == 0x3000 else "", raising=False)
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea in {0x1000, 0x2000, 0x3000} else None)
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: None)
    result = comb.search_analyze(scope="vulnerable", depth=2)
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["taint_sources"] == 1
    filtered = comb.search_analyze(scope="vulnerable", depth=2, pattern="unmatched")
    assert filtered["count"] == 0
    assert filtered["items"] == []
