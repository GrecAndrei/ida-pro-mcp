from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.server.server import IDAMCPServer


def test_truncation_owner_id_is_stable_per_connection(monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()

    first = server._truncation_owner_id()
    second = server._truncation_owner_id()
    assert first
    assert first == second

    # Simulate a second daemon client connection with its own request state.
    other = server._begin_client_connection()
    try:
        assert server._truncation_owner_id() != first
    finally:
        server._end_client_connection(other)
