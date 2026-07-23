from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def _blackboard_server(tmp_path) -> ServerBlackboardMixin:
    server = object.__new__(ServerBlackboardMixin)
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    return server


def test_get_blackboard_store_returns_none_without_session_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None

    assert server._get_blackboard_store() is None


def test_migrates_legacy_shared_sha256_notebook_into_session_scoped_db(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"migrate-me")
    server = _blackboard_server(tmp_path)
    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "a.i64"),
        session_id="sess-a",
    )

    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    shared_path = shared_dir / f"sha256-{digest}.db"
    shared_store = BlackboardStore(str(shared_path))
    shared_store.write(title="Shared finding", content="from old release")

    session_path = server._session_blackboard_path(session_obj=session)

    assert session_path.endswith(f"sha256-{digest}-sess-a.db")
    assert os.path.isfile(session_path)
    session_store = BlackboardStore(session_path)
    assert session_store.stats()["total_entries"] == 1
    assert session_store.list(limit=1)[0]["title"] == "Shared finding"


def test_blackboard_write_runs_evidence_gravity_only_on_create(tmp_path, monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server.cache_dir = str(tmp_path / "cache")

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"gravity-test")
    server.current_session = SimpleNamespace(
        session_id="GRAVITY",
        binary_path=str(binary),
        idb_path=str(tmp_path / "gravity.i64"),
    )

    gravity_calls: list[dict] = []

    def fake_gravity(self, store, source_entry_id: str, addr: str, source_text: str = ""):
        gravity_calls.append(
            {
                "entry_id": source_entry_id,
                "addr": addr,
                "source_text": source_text,
            }
        )
        return {"ok": True, "entry_id": "gravity-row"}

    monkeypatch.setattr(type(server), "_evidence_gravity", fake_gravity)

    first = server._handle_blackboard(
        {
            "action": "write",
            "name": "Parser length unchecked",
            "addr": "0x401000",
            "notes": "Initial observation",
        }
    )
    second = server._handle_blackboard(
        {
            "action": "write",
            "name": "Parser length unchecked",
            "addr": "0x401000",
            "notes": "Merged follow-up",
        }
    )

    assert first["ok"] is True
    assert first.get("created") is True
    assert first.get("gravity") == {"ok": True, "entry_id": "gravity-row"}
    assert second["ok"] is True
    assert second.get("created") is False
    assert second.get("gravity") is None
    assert len(gravity_calls) == 1
    assert gravity_calls[0]["addr"] == "0x401000"


def test_blackboard_store_rejects_empty_db_path():
    with pytest.raises(ValueError, match="db_path is required"):
        BlackboardStore(db_path="")
