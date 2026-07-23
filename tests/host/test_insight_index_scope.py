from __future__ import annotations

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
