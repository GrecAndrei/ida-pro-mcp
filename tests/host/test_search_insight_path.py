from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from ida_pro_mcp.host.intelligence.insight_paths import resolve_insight_index_path


def test_insight_index_path_prefers_active_idb(monkeypatch):
    fake_idc = SimpleNamespace(get_idb_path=lambda: "/tmp/analysis/sample.i64")
    monkeypatch.setitem(sys.modules, "idc", fake_idc)

    assert resolve_insight_index_path() == "/tmp/analysis/sample.i64.insight_index.json"


def test_insight_index_path_falls_back_to_cache_dir(monkeypatch, tmp_path):
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    cache_dir = str(tmp_path / "cache")

    assert resolve_insight_index_path(cache_dir=cache_dir) == str(
        tmp_path / "cache" / "insight_index.json"
    )


def test_insight_index_path_ignores_blank_idb_path(monkeypatch, tmp_path):
    fake_idc = ModuleType("idc")
    fake_idc.get_idb_path = lambda: "   "
    monkeypatch.setitem(sys.modules, "idc", fake_idc)
    cache_dir = str(tmp_path / "cache")

    assert resolve_insight_index_path(cache_dir=cache_dir) == str(
        tmp_path / "cache" / "insight_index.json"
    )
