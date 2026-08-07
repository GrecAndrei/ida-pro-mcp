"""Insight index path resolution (filesystem helper)."""

from __future__ import annotations

import os
import sys
import types

from ida_pro_mcp.host.intelligence.insight_paths import resolve_insight_index_path


def test_uses_idb_path_when_ida_available(monkeypatch):
    idc = types.ModuleType("idc")

    def get_idb_path():
        return "/tmp/example.idb"

    idc.get_idb_path = get_idb_path
    monkeypatch.setitem(sys.modules, "idc", idc)
    assert resolve_insight_index_path() == "/tmp/example.idb.insight_index.json"


def test_falls_back_to_env_cache_dir(monkeypatch):
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", "/cache/dir")
    assert resolve_insight_index_path() == "/cache/dir/insight_index.json"


def test_falls_back_to_data_dir(monkeypatch):
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    monkeypatch.delenv("IDA_MCP_CACHE_DIR", raising=False)
    monkeypatch.setenv("IDA_MCP_DATA_DIR", "/data/dir")
    assert resolve_insight_index_path() == "/data/dir/insight_index.json"


def test_falls_back_to_tmpdir(monkeypatch, tmp_path):
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    monkeypatch.delenv("IDA_MCP_CACHE_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_DATA_DIR", raising=False)
    path = resolve_insight_index_path()
    assert path.endswith(os.path.join("ida-pro-mcp", "insight_index.json"))


def test_explicit_cache_dir_wins(monkeypatch):
    monkeypatch.delitem(sys.modules, "idc", raising=False)
    assert resolve_insight_index_path("/explicit") == "/explicit/insight_index.json"
