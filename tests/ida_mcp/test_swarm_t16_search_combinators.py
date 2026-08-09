"""Regression tests for t16_search_combinators audit fixes.

Covers:
  - search_bool threading `case_sensitive` through the parser/primitives
    (previously declared but silently ignored).
  - embedding-index outlier path emitting `truncated` so pagination engages.
  - semantic scope using fetch-one-extra so `truncated`/`total` are honest.
  - string: primitive degrading to an empty set when ida_hexrays is absent.
  - call-graph cache warm path avoiding full-program enumeration.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402


def _module(modname: str):
    return load_tool_submodule(modname)


# ---------------------------------------------------------------------------
# search_bool — case_sensitive passthrough
# ---------------------------------------------------------------------------

def _bool_env(comb):
    comb.idaapi.BADADDR = -1
    comb.idautils.Functions = lambda: [0x1000, 0x2000]
    comb._func_name = lambda ea: {0x1000: "Main", 0x2000: "main"}.get(ea, hex(ea))


def test_search_bool_honors_case_sensitive():
    comb = _module("search.combinators")
    _bool_env(comb)
    resp = comb.search_bool("name:main", True, 0, 10)
    assert resp["ok"] is True
    assert resp["total"] == 1
    assert resp["items"][0]["ea"] == 0x2000
    assert resp["items"][0]["name"] == "main"


def test_search_bool_default_is_case_insensitive():
    comb = _module("search.combinators")
    _bool_env(comb)
    resp = comb.search_bool("name:main", False, 0, 10)
    assert resp["ok"] is True
    assert resp["total"] == 2


def test_search_bool_bare_literal_respects_case_sensitive():
    comb = _module("search.combinators")
    _bool_env(comb)
    resp = comb.search_bool("Main", True, 0, 10)
    assert resp["total"] == 1
    assert resp["items"][0]["name"] == "Main"
    resp2 = comb.search_bool("Main", False, 0, 10)
    assert resp2["total"] == 2


# ---------------------------------------------------------------------------
# _prim_funcs_by_string — graceful degradation without ida_hexrays
# ---------------------------------------------------------------------------

def test_prim_funcs_by_string_degrades_without_hexrays():
    comb = _module("search.combinators")
    saved = sys.modules.pop("ida_hexrays", None)
    try:
        # The stub installs an empty ida_hexrays module; removing it makes the
        # guarded `import ida_hexrays` raise, and the primitive must return an
        # empty set instead of propagating the ImportError.
        assert comb._prim_funcs_by_string("secret") == set()
    finally:
        if saved is not None:
            sys.modules["ida_hexrays"] = saved


# ---------------------------------------------------------------------------
# search_analyze outlier — embedding-index path emits `truncated`
# ---------------------------------------------------------------------------

class _Cursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeConn:
    """Minimal sqlite-ish connection mirroring the embedding index API."""

    def __init__(self, count, rows):
        self.count = count
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        if sql.startswith("SELECT COUNT(*)"):
            return _Cursor([(self.count,)])
        if "WHERE ea = ?" in sql:
            # embedding-metadata lookup: no row present
            return _Cursor([])
        return _Cursor(self.rows)


class _FakeIdx:
    def __init__(self, size=100, count=0, rows=(), hits=()):
        self.size = size
        self._conn_factory = _FakeConn(count, rows)
        self._hits = hits

    def _conn(self):
        return self._conn_factory

    def hybrid_search(self, query, top_k=10, threshold=0.0, **kw):
        return list(self._hits[: int(top_k)])


class _FakeAsm:
    def __init__(self, idx):
        self.idx = idx

    def _get_index(self, idb_path):
        return self.idx


def _install_fake_services(monkeypatch, asm):
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: asm
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)


def test_analyze_outlier_index_path_reports_truncated(monkeypatch):
    comb = _module("search.combinators")
    monkeypatch.setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/fake.idb", raising=False)
    idx = _FakeIdx(size=100, count=10, rows=[("0x1000", "fn1", 100)])
    _install_fake_services(monkeypatch, _FakeAsm(idx))
    resp = comb.search_analyze(scope="outlier", metric="size", offset=0, limit=1)
    assert resp["ok"] is True
    assert resp["total"] == 10
    assert resp["count"] == 1
    assert resp["truncated"] is True
    assert resp["items"][0]["addr"] == "0x1000"


def test_analyze_outlier_index_path_not_truncated(monkeypatch):
    comb = _module("search.combinators")
    monkeypatch.setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/fake.idb", raising=False)
    idx = _FakeIdx(size=100, count=1, rows=[("0x1000", "fn1", 100)])
    _install_fake_services(monkeypatch, _FakeAsm(idx))
    resp = comb.search_analyze(scope="outlier", metric="size", offset=0, limit=5)
    assert resp["ok"] is True
    assert resp["total"] == 1
    assert resp["count"] == 1
    assert resp["truncated"] is False


# ---------------------------------------------------------------------------
# search_analyze semantic — fetch-one-extra so truncated/total are honest
# ---------------------------------------------------------------------------

def test_analyze_semantic_scope_marks_truncated(monkeypatch):
    comb = _module("search.combinators")
    monkeypatch.setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/fake.idb", raising=False)
    hits = [
        {"ea": "0x1000", "name": "fn1", "score": 0.9},
        {"ea": "0x2000", "name": "fn2", "score": 0.8},
    ]
    idx = _FakeIdx(size=100, hits=hits)
    _install_fake_services(monkeypatch, _FakeAsm(idx))
    resp = comb.search_analyze(scope="semantic", pattern="crypto", offset=0, limit=1)
    assert resp["ok"] is True
    assert resp["count"] == 1
    assert resp["total"] == 2
    assert resp["truncated"] is True


def test_analyze_semantic_scope_not_truncated_when_exhausted(monkeypatch):
    comb = _module("search.combinators")
    monkeypatch.setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/fake.idb", raising=False)
    hits = [{"ea": "0x1000", "name": "fn1", "score": 0.9}]
    idx = _FakeIdx(size=100, hits=hits)
    _install_fake_services(monkeypatch, _FakeAsm(idx))
    resp = comb.search_analyze(scope="semantic", pattern="crypto", offset=0, limit=5)
    assert resp["ok"] is True
    assert resp["count"] == 1
    assert resp["total"] == 1
    assert resp["truncated"] is False


# ---------------------------------------------------------------------------
# call-graph cache — warm path avoids full-program enumeration
# ---------------------------------------------------------------------------

def test_call_graph_cache_warm_path_skips_enumeration():
    comb = _module("search.combinators")
    calls = {"n": 0}

    def counting():
        calls["n"] += 1
        return [0x1000]

    comb.idautils.Functions = counting
    comb.idautils.Names = list
    comb._func_callees = lambda fea: {0x2000}
    comb._CALL_GRAPH_CACHE.clear()

    g1 = comb._get_call_graph()
    assert g1["callees"] == {0x1000: {0x2000}}
    assert g1["callers"] == {0x2000: {0x1000}}
    n_after_first = calls["n"]
    assert n_after_first >= 2  # fingerprint + build loop

    g2 = comb._get_call_graph()
    assert g2 is g1
    assert calls["n"] == n_after_first  # warm path did not re-enumerate


def test_call_graph_cache_rebuilds_when_idb_changes(monkeypatch):
    comb = _module("search.combinators")
    calls = {"n": 0}

    def counting():
        calls["n"] += 1
        return [0x1000]

    class _Stat:
        def __init__(self):
            self.st_mtime = 100
            self.st_size = 100

    stat = _Stat()
    monkeypatch.setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/fake.idb", raising=False)
    # `os` reaches this module via `from .._common import *` in production;
    # the test stub does not re-export it, so provide a patchable stand-in.
    comb.os = types.SimpleNamespace(stat=lambda path: stat)
    comb.idautils.Functions = counting
    comb.idautils.Names = list
    comb._func_callees = lambda fea: {0x2000}
    comb._CALL_GRAPH_CACHE.clear()

    g1 = comb._get_call_graph()
    n1 = calls["n"]

    g2 = comb._get_call_graph()
    assert g2 is g1
    assert calls["n"] == n1  # warm hit

    stat.st_mtime = 200  # simulated save
    g3 = comb._get_call_graph()
    assert g3 is not g1
    assert calls["n"] > n1  # rebuilt
