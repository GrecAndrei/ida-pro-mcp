from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.server.server import IDAMCPServer


def test_insight_index_is_scoped_per_session(monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    first = SimpleNamespace(session_id="SESS-A")
    second = SimpleNamespace(session_id="SESS-B")

    index_a = server._insight_index_for_session(first)
    index_b = server._insight_index_for_session(second)

    assert index_a is not index_b
    index_a.index_function("0x401000", {"behavior_tags": ["crypto"], "name": "enc"})
    assert index_a.get_function("0x401000") is not None
    assert index_b.get_function("0x401000") is None


def test_insight_index_property_follows_current_session(monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server.current_session = SimpleNamespace(session_id="CURRENT")

    current_index = server._insight_index
    current_index.index_function("0x402000", {"behavior_tags": ["parser"], "name": "parse"})

    other_index = server._insight_index_for_session(SimpleNamespace(session_id="OTHER"))
    assert other_index.get_function("0x402000") is None
    assert server._insight_index.get_function("0x402000") is not None


def test_insight_index_persists_to_session_specific_file(monkeypatch, tmp_path):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server.cache_dir = str(tmp_path / "cache")
    session = SimpleNamespace(session_id="PERSIST")

    index = server._insight_index_for_session(session)
    index.index_function("0x403000", {"behavior_tags": ["network"], "name": "send"})
    index.save()

    path = tmp_path / "cache" / "insight_indexes" / "PERSIST.json"
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "0x403000" in payload["func_map"]
