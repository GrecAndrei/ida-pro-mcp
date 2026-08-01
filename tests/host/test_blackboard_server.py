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


def test_legacy_shared_sha256_notebook_is_the_workspace(tmp_path):
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

    assert session_path == str(shared_path)
    assert os.path.isfile(session_path)
    session_store = BlackboardStore(session_path)
    assert session_store.stats()["total_entries"] == 1
    assert session_store.list(limit=1)[0]["title"] == "Shared finding"


def test_per_session_workspaces_from_previous_releases_are_adopted(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"adopt-me")
    server = _blackboard_server(tmp_path)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()

    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    # Two sessions of the same binary from the previous (per-session) layout.
    old_a = shared_dir / f"sha256-{digest}-aaaa1111.db"
    old_b = shared_dir / f"sha256-{digest}-bbbb2222.db"
    store_a = BlackboardStore(str(old_a))
    store_a.write(title="Finding from session A", content="x", addr="0x401000")
    store_b = BlackboardStore(str(old_b))
    store_b.write(title="Finding from session B", content="y", addr="0x402000")

    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "a.i64"),
        session_id="new-session",
    )
    workspace = server._session_blackboard_path(session_obj=session)

    assert workspace.endswith(f"sha256-{digest}.db")
    store = BlackboardStore(workspace)
    titles = {e["title"] for e in store.list(limit=50)}
    assert "Finding from session A" in titles
    assert "Finding from session B" in titles


def test_legacy_idb_sidecar_notebook_is_adopted_into_shared_workspace(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"legacy-me")
    server = _blackboard_server(tmp_path)

    idb_path = tmp_path / "a.i64"
    legacy_path = str(idb_path) + ".blackboard.db"
    legacy_store = BlackboardStore(legacy_path)
    legacy_store.write(title="Legacy notebook finding", content="from <idb>.blackboard.db")

    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(idb_path),
        session_id="sess-a",
    )
    workspace = server._session_blackboard_path(session_obj=session)

    store = BlackboardStore(workspace)
    titles = {e["title"] for e in store.list(limit=50)}
    assert "Legacy notebook finding" in titles


def test_seeding_never_overwrites_existing_workspace_rows(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"keep-me")
    server = _blackboard_server(tmp_path)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()

    shared_dir = tmp_path / "cache" / "blackboards"
    shared_dir.mkdir(parents=True)
    shared_path = shared_dir / f"sha256-{digest}.db"
    fresh_store = BlackboardStore(str(shared_path))
    fresh_store.write(title="Fresh finding", content="written by the new session")

    old_path = shared_dir / f"sha256-{digest}-aaaa1111.db"
    old_store = BlackboardStore(str(old_path))
    old_store.write(title="Old finding", content="older layout")

    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "a.i64"),
        session_id="sess-a",
    )
    workspace = server._session_blackboard_path(session_obj=session)
    assert workspace == str(shared_path)

    store = BlackboardStore(workspace)
    titles = {e["title"] for e in store.list(limit=50)}
    assert "Fresh finding" in titles
    assert "Old finding" not in titles


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
