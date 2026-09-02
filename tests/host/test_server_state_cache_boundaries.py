"""Behavioral coverage for server request state and scoped insight caches."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import ida_pro_mcp.host.server.server as server_module
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_client_state import _ClientRequestState


def test_request_properties_and_global_insight_cache_fallback(monkeypatch, tmp_path):
    server = IDAMCPServer.__new__(IDAMCPServer)
    state = _ClientRequestState()
    server._client_request_state = lambda: state
    server.current_session = None
    server._insight_indexes = None
    server._insight_index_lock = threading.Lock()
    server.cache_dir = str(tmp_path)

    server._last_spawn_error = "spawn failed"
    assert server._last_spawn_error == "spawn failed"
    server.vertex_compat = 1
    assert server.vertex_compat is True
    server.vertex_compat = 0
    assert server.vertex_compat is False

    created = []

    class FakeIndex:
        def __init__(self, persistence_path):
            self.persistence_path = persistence_path
            created.append(self)

        def save(self):
            return None

    monkeypatch.setattr(server_module, "InsightIndex", FakeIndex)
    global_index = server._insight_index_for_session()
    assert global_index.persistence_path.endswith("/_GLOBAL.json")
    assert server._insight_indexes["_GLOBAL"] is global_index
    assert server._insight_index is global_index

    replacement = object()
    server._insight_indexes = None
    server._insight_index = replacement
    assert server._insight_indexes["_GLOBAL"] is replacement
    assert len(created) == 1


def test_insight_cache_evicts_oldest_and_survives_persistence_failure(monkeypatch, tmp_path):
    server = IDAMCPServer.__new__(IDAMCPServer)
    server.current_session = SimpleNamespace(session_id="new-session")
    server._insight_indexes = {}
    server._insight_index_lock = threading.Lock()
    server.cache_dir = str(tmp_path)
    server._MAX_INSIGHT_INDEXES = 2

    class OldIndex:
        def save(self):
            raise OSError("cache is read-only")

    class FakeIndex:
        def __init__(self, persistence_path):
            self.persistence_path = persistence_path

        def save(self):
            return None

    server._insight_indexes["FIRST"] = OldIndex()
    server._insight_indexes["SECOND"] = FakeIndex("second")
    monkeypatch.setattr(server_module, "InsightIndex", FakeIndex)

    index = server._insight_index_for_session()
    assert index.persistence_path.endswith("/NEW-SESSION.json")
    assert list(server._insight_indexes) == ["SECOND", "NEW-SESSION"]


def test_analysis_gate_lifecycle_ignores_uninitialized_session_registry():
    server = IDAMCPServer.__new__(IDAMCPServer)
    server.session_mgr = SimpleNamespace(sessions=None)
    server._restore_analysis_gates_from_metadata()
    server._persist_analysis_gates_on_shutdown()
