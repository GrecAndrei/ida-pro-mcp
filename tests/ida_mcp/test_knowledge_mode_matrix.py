"""Composed fake-IDB coverage for symbol knowledge import/export workflows."""

import sys

from tests._isolated_repo_loader import load_tool_module


class _SymbolStore:
    rows = []
    lookup_rows = []

    def __init__(self, path=None):
        self.db_path = path or "/tmp/knowledge.db"
        self.upserts = []

    def query_symbols(self, query, limit):
        return [{"symbol_name": query, "limit": limit}]

    def upsert_symbol(self, row):
        self.upserts.append(row)
        self.rows.append(row)
        return row.get("symbol_name") != "skip"

    def lookup_by_fingerprint(self, _fingerprint, limit):
        return self.lookup_rows[:limit]


def _load_knowledge(monkeypatch):
    from tests.ida_mcp.test_support_engines_and_integration import _make_fake_ida

    for name, module in _make_fake_ida().items():
        monkeypatch.setitem(sys.modules, name, module)
    mod = load_tool_module("knowledge")
    monkeypatch.setattr(mod, "SymbolDB", _SymbolStore)
    return mod


def test_knowledge_lookup_validates_query_and_bounds_limit(monkeypatch):
    mod = _load_knowledge(monkeypatch)

    assert mod.knowledge(action="symbol_lookup")["code"] == "INVALID_ARGS"
    result = mod.knowledge(action="symbol_lookup", query="memcpy", limit=999)
    assert result == {
        "ok": True,
        "matches": [{"symbol_name": "memcpy", "limit": 200}],
        "count": 1,
    }


def test_knowledge_export_fingerprints_callers_callees_and_strings(monkeypatch):
    mod = _load_knowledge(monkeypatch)
    mod.idc.get_idb_path = lambda: "/tmp/sample.idb"
    mod.idc.STRTYPE_C = 0
    mod.idautils.Functions = lambda: [0x1000, 0x2000, 0x3000]
    mod.idc.get_func_name = lambda ea: {
        0x1000: "sub_1000",
        0x2000: "named_function",
        0x3000: "sub_3000",
    }[ea]
    def get_func_start(ea):
        return {0x1000: 0x1000, 0x1100: 0x1000, 0x2000: 0x2000, 0x2100: 0x2000}.get(ea)

    monkeypatch.setattr(mod._compat, "get_func_start", get_func_start)
    mod.idautils.CodeRefsTo = lambda ea, _flow: [0x1100] if ea == 0x2000 else []
    mod.idautils.CodeRefsFrom = lambda ea, _flow: [0x2100] if ea == 0x2000 else []
    mod.idautils.FuncItems = lambda _ea: [0x2000]
    mod.idautils.DataRefsFrom = lambda _ea: [0x9000, 0x9004, 0x9008]
    mod.idc.get_strlit_contents = lambda ea, _size, _stype: {
        0x9000: b"alpha",
        0x9004: b"alpha",
        0x9008: b" beta ",
    }.get(ea)

    result = mod.knowledge(action="export_session", session_id="s1", chip_family="arm")

    assert result["ok"] is True, result
    assert result["exported"] == 1
    assert result["db_path"] == "/tmp/knowledge.db"
    row = _SymbolStore.rows[-1]
    assert row["symbol_name"] == "named_function"
    assert row["source_addr"] == "0x2000"
    assert row["strings"] == ["alpha", "beta"]
    assert row["source_session"] == "s1"
    assert row["chip_family"] == "arm"
    assert row["callgraph_hash"]
    assert row["fingerprint"]


def test_knowledge_import_applies_confident_fingerprint_matches(monkeypatch):
    mod = _load_knowledge(monkeypatch)
    mod.idautils.Functions = lambda: [0x1000, 0x2000, 0x3000, 0x4000]
    mod.idc.get_func_name = lambda ea: {
        0x1000: "sub_1000",
        0x2000: "already_named",
        0x3000: "sub_3000",
        0x4000: "sub_4000",
    }[ea]
    monkeypatch.setattr(mod._compat, "get_func_start", lambda ea: ea)
    mod.idautils.FuncItems = lambda _ea: []
    mod.idautils.CodeRefsTo = lambda _ea, _flow: []
    mod.idautils.CodeRefsFrom = lambda _ea, _flow: []
    mod.idc.set_name = lambda ea, name, _flags: ea == 0x1000 and bool(name)
    mod.ida_name.SN_FORCE = 1
    _SymbolStore.lookup_rows = [
        {"symbol_name": "restored_name", "confidence": 0.95, "source_binary": "other.idb"},
    ]

    result = mod.knowledge(action="import_symbols", min_confidence=0.8, limit=1)

    assert result["ok"] is True, result
    assert result["imported"] == 1
    assert result["proposals"] == [{
        "addr": "0x1000",
        "name": "restored_name",
        "confidence": 0.95,
        "applied": True,
        "source_binary": "other.idb",
    }]

    _SymbolStore.lookup_rows = [
        {"symbol_name": "low_conf", "confidence": 0.2},
        {"symbol_name": "", "confidence": 1.0},
    ]
    assert mod.knowledge(action="import_symbols", min_confidence=0.8)["imported"] == 0
    assert mod.knowledge(action="unknown")["code"] == "INVALID_ARGS"
