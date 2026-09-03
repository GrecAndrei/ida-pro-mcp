"""Deep offline coverage for the IDA-side knowledge bridge."""

from __future__ import annotations

import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module


def _load(monkeypatch):
    from tests.ida_mcp.support_fakes import make_fake_ida

    for name, module in make_fake_ida().items():
        monkeypatch.setitem(sys.modules, name, module)
    mod = load_tool_module("knowledge")
    mod.ida_name.SN_FORCE = 1
    return mod


class _Store:
    def __init__(self, path=None):
        self.db_path = path or "/tmp/knowledge.db"
        self.rows = []
        self.lookup = []

    def query_symbols(self, query, limit):
        return [{"query": query, "limit": limit}]

    def upsert_symbol(self, row):
        self.rows.append(row)
        return row.get("source_addr") != "0x2000"

    def lookup_by_fingerprint(self, _fingerprint, limit):
        return self.lookup[:limit]


def test_lazy_store_fallback_and_fingerprint_collection_edges(monkeypatch):
    mod = _load(monkeypatch)
    fallback = types.ModuleType("host.stores.symbol_db")
    fallback.SymbolDB = _Store
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", None)
    monkeypatch.setitem(sys.modules, "host.stores.symbol_db", fallback)
    assert mod._symbol_db_class() is _Store

    mod._compat.get_func_start = lambda _ea: None
    mod.idautils.CodeRefsTo = lambda *_args: []
    mod.idautils.CodeRefsFrom = lambda *_args: []
    assert mod._collect_string_refs(0x1000) == []
    assert mod._fingerprint_function(0x1000)["strings"] == []

    mod._compat.get_func_start = lambda ea: ea
    mod.idautils.FuncItems = lambda _ea: [0x1000]
    mod.idautils.DataRefsFrom = lambda _ea: [1, 2, 3]
    mod.idc.STRTYPE_C = 0
    mod.idc.get_strlit_contents = lambda ea, _size, _stype: {
        1: None,
        2: b" duplicate ",
        3: b"third",
    }[ea]
    assert mod._collect_string_refs(0x1000, limit=1) == ["duplicate"]
    assert mod._collect_string_refs(0x1000, limit=10) == ["duplicate", "third"]


def test_knowledge_export_import_and_error_edges(monkeypatch):
    mod = _load(monkeypatch)
    store = _Store
    mod.SymbolDB = store
    mod.idc.get_idb_path = lambda: "/tmp/sample.idb"
    mod.idautils.Functions = lambda: [0x1000, 0x2000, 0x3000]
    mod.idc.get_func_name = lambda ea: {
        0x1000: "named",
        0x2000: "named_two",
        0x3000: "sub_3000",
    }[ea]
    mod._fingerprint_function = lambda _ea: {"fingerprint": "fp", "callgraph_hash": "cg", "strings": []}
    exported = mod.knowledge(action="export_session", db_path="/tmp/db")
    assert exported["exported"] == 1

    # Import skips already named functions, empty lookups, weak confidence,
    # and blank candidate names; a failed set_name remains a proposal.
    mod.idautils.Functions = lambda: [0x1000, 0x2000, 0x3000, 0x4000]
    mod.idc.get_func_name = lambda ea: {
        0x1000: "sub_1000",
        0x2000: "already_named",
        0x3000: "sub_3000",
        0x4000: "sub_4000",
    }[ea]
    mod._fingerprint_function = lambda _ea: {"fingerprint": "fp", "callgraph_hash": "cg", "strings": []}
    state = iter([
        [],
        [{"symbol_name": "weak", "confidence": 0.1}],
        [{"symbol_name": "", "confidence": 1.0}],
    ])
    store.lookup = []
    store.lookup_by_fingerprint = lambda self, _fp, limit: next(state)
    mod.idc.set_name = lambda *_args: False
    imported = mod.knowledge(action="import_symbols", min_confidence=0.8, limit=0)
    assert "imported" in imported, imported
    assert imported["imported"] == 0
    assert imported["proposals"] == []

    # A failing store construction is converted to the stable error envelope.
    class BrokenStore:
        def __init__(self, _path=None):
            raise RuntimeError("database unavailable")

    mod.SymbolDB = BrokenStore
    result = mod.knowledge(action="symbol_lookup", query="x")
    assert result["ok"] is False and "database unavailable" in result["error"]


def test_knowledge_import_applies_false_and_true_names(monkeypatch):
    mod = _load(monkeypatch)

    class Store(_Store):
        def lookup_by_fingerprint(self, _fp, limit):
            return [{"symbol_name": "restored", "confidence": 0.9, "source_binary": "other"}]

    mod.SymbolDB = Store
    mod.idautils.Functions = lambda: [0x1000, 0x2000]
    mod.idc.get_func_name = lambda _ea: "sub_1000"
    mod._fingerprint_function = lambda _ea: {"fingerprint": "fp", "callgraph_hash": "cg", "strings": []}
    mod.idc.set_name = lambda ea, *_args: ea == 0x1000
    result = mod.knowledge(action="import_symbols", limit=2)
    assert "imported" in result, result
    assert result["imported"] == 1
    assert result["proposals"][0]["applied"] is True
