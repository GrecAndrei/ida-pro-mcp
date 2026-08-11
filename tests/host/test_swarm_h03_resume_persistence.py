"""h03 resume-persistence regression tests.

Pins the durable analysis-gate field, honest metadata-write failures, stale
owner.json cleanup, sticky ownership adoption (D3-F10), mid-spawn teardown
guards, and group rehydration across restarts (D3-F9). Standalone: no live IDA,
``_FakeIdaProcess``-style fakes only.
"""

from __future__ import annotations

import errno
import json
import os
import threading

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_multi_session import (
    ServerMultiSessionMixin,
    SessionGroup,
)
from ida_pro_mcp.host.server.session import Session, SessionManager


class _FakeIdaProcess:
    """A fake idat subprocess that is always alive (poll() is None)."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


def _live_runtime(sid: str) -> dict:
    return {
        "process": _FakeIdaProcess(),
        "port": 12345,
        "idb_path": f"/fake/{sid}.i64",
    }


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    monkeypatch.setattr(server, "_ensure_runtime_and_idb", lambda session: None)
    return server


def _owned_session(server: IDAMCPServer, binary: str = "/samples/alpha.bin"):
    """Create a session and record it as this connection's current/owned one."""
    session = server.session_mgr.create_session(binary)
    server.current_session = session
    return session


# ---------------------------------------------------------------------------
# session.py: durable analysis_gate field round-trip
# ---------------------------------------------------------------------------


def test_analysis_gate_round_trips_through_to_dict_from_dict():
    s = Session("ABC12345", "/tmp/SID_ABC12345_x.i64", "/tmp/x.bin", analysis_gate="pending")
    restored = Session.from_dict(s.to_dict())
    assert restored.analysis_gate == "pending"
    assert s.to_dict()["analysis_gate"] == "pending"

    # "complete" and None round-trip too.
    c = Session.from_dict({"session_id": "ABC12345", "analysis_gate": "complete"})
    assert c.analysis_gate == "complete"
    n = Session.from_dict({"session_id": "ABC12345"})
    assert n.analysis_gate is None

    # Unknown gate values are normalized to None so h05 never sees a state it
    # cannot interpret after a restart.
    junk = Session("ABC12345", "/tmp/a.i64", "/tmp/a.bin", analysis_gate="WARPED")
    assert junk.analysis_gate is None


def test_analysis_gate_survives_manager_save_and_reload(tmp_path):
    mgr1 = SessionManager(str(tmp_path))
    session = mgr1.create_session("/tmp/z.bin")
    sid = session.session_id
    mgr1.update_session(sid, analysis_gate="pending")

    mgr2 = SessionManager(str(tmp_path))
    loaded = mgr2.get_session(sid)
    assert loaded is not None
    assert loaded.analysis_gate == "pending"
    # First-class metadata.json field (h01 persists, h05 restores).
    with open(mgr1._get_metadata_path(sid), encoding="utf-8") as f:
        assert json.load(f)["analysis_gate"] == "pending"


# ---------------------------------------------------------------------------
# session.py: delete_session drops the owner.json claim (D3-F7)
# ---------------------------------------------------------------------------


def test_delete_session_removes_owner_and_lease_files(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    sid = session.session_id
    lease_dir = os.path.join(str(tmp_path), "runtime_leases")
    os.makedirs(lease_dir, exist_ok=True)
    owner_path = os.path.join(lease_dir, f"SID_{sid}.owner.json")
    lease_path = os.path.join(lease_dir, f"SID_{sid}.lease.json")
    with open(owner_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": sid, "owner_pid": os.getpid()}, f)
    with open(lease_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": sid, "pid": 12345}, f)

    assert mgr.delete_session(sid) is True
    assert not os.path.exists(owner_path)
    assert not os.path.exists(lease_path)


# ---------------------------------------------------------------------------
# session.py: honest metadata-write failures (D2-F11)
# ---------------------------------------------------------------------------


def test_metadata_write_failure_surfaces_disk_full_warning(tmp_path, monkeypatch):
    import ida_pro_mcp.host.server.session as session_mod

    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")
    sid = session.session_id

    messages: list[str] = []
    monkeypatch.setattr(session_mod, "log_rpc", lambda msg: messages.append(str(msg)))

    def boom(src, dst):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(session_mod.os, "replace", boom)
    mgr._save_metadata(session)

    assert any("[DISK-FULL]" in m and "ENOSPC" in m for m in messages), messages
    # The pid-scoped temp file is still cleaned up after the failed rename.
    assert not os.path.exists(f"{mgr._get_metadata_path(sid)}.{os.getpid()}.tmp")


def test_metadata_write_failure_other_error_logs_generic(tmp_path, monkeypatch):
    import ida_pro_mcp.host.server.session as session_mod

    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session("/tmp/x.bin")

    messages: list[str] = []
    monkeypatch.setattr(session_mod, "log_rpc", lambda msg: messages.append(str(msg)))

    def boom(src, dst):
        raise PermissionError("nope")

    monkeypatch.setattr(session_mod.os, "replace", boom)
    mgr._save_metadata(session)

    assert messages, "a non-ENOSPC write failure must still be logged"
    assert not any("[DISK-FULL]" in m for m in messages)


# ---------------------------------------------------------------------------
# server_client_state.py: sticky ownership adoption (D3-F10)
# ---------------------------------------------------------------------------


def test_adoption_refused_while_recorded_owner_still_connected(tmp_path, monkeypatch):
    """A sibling cannot adopt a session whose recorded owner connection is still
    connected even though no runtime is running (the owner's runtime died)."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    assert not server._session_ownership_report(sid)["locked"]

    result: dict = {}

    def sibling() -> None:
        server._begin_client_connection()
        result["res"] = server._ensure_client_owns_session(session)

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    server._end_client_connection(token_a)

    res = result["res"]
    assert res is not None
    assert res.get("code") == MCPError.FILE_LOCKED
    assert res["details"]["holder"] == "this-host-owner"
    assert res["details"]["owner_alive"] is True
    assert res["details"]["owner_pid"] == os.getpid()


def test_adoption_allowed_after_recorded_owner_disconnects(tmp_path, monkeypatch):
    """Sticky ownership releases when the owning connection's socket closes: a
    restarted client re-adopts the disconnected owner's session (keep=true)."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    server._end_client_connection(token_a)

    token_b = server._begin_client_connection()
    try:
        assert server._ensure_client_owns_session(session) is None
        assert server._client_owns_session(sid)
    finally:
        server._end_client_connection(token_b)
        server.shutdown()


def test_actively_running_foreign_session_is_never_shared(tmp_path, monkeypatch):
    """A session with a live runtime stays FILE_LOCKED for a foreign connection
    regardless of the sticky rule (existing daemon contract preserved)."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    server.session_runtimes[sid] = _live_runtime(sid)

    result: dict = {}

    def sibling() -> None:
        server._begin_client_connection()
        result["res"] = server._ensure_client_owns_session(session)

    thread = threading.Thread(target=sibling)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    server._end_client_connection(token_a)

    res = result["res"]
    assert res is not None
    assert res.get("code") == MCPError.FILE_LOCKED
    assert res["details"]["holder"] == "this-host-runtime"


# ---------------------------------------------------------------------------
# server_client_state.py: mid-spawn teardown guard
# ---------------------------------------------------------------------------


def _claim_owner_file(server, sid: str) -> None:
    os.makedirs(server._runtime_lease_dir, exist_ok=True)
    with open(server._runtime_owner_path(sid), "w", encoding="utf-8") as f:
        json.dump(
            {"session_id": sid, "owner_pid": os.getpid(), "owner_id": server._runtime_owner_id},
            f,
        )


def test_end_connection_does_not_abort_mid_spawn_without_explicit_owner(tmp_path, monkeypatch):
    """A disconnect must not tear down a session whose runtime is mid-spawn
    (owner.json claimed, no runtime registered yet) when this connection is not
    the explicitly recorded owner — even when nobody is recorded."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    server._session_current_owner.pop(sid, None)  # no explicit owner recorded
    _claim_owner_file(server, sid)

    cleaned: list[str] = []
    server._cleanup_runtime = lambda s: cleaned.append(str(s))

    server._end_client_connection(token_a)
    assert sid not in cleaned, "a mid-spawn runtime must survive an unattributed disconnect"


def test_end_connection_aborts_own_mid_spawn_runtime(tmp_path, monkeypatch):
    """The guard allows the explicitly recorded owner to abort its own mid-spawn
    runtime on disconnect."""
    server = _make_server(tmp_path, monkeypatch)
    token_a = server._begin_client_connection()
    session = _owned_session(server)
    sid = session.session_id
    _claim_owner_file(server, sid)

    cleaned: list[str] = []
    server._cleanup_runtime = lambda s: cleaned.append(str(s))

    server._end_client_connection(token_a)
    assert sid in cleaned


# ---------------------------------------------------------------------------
# server_multi_session.py: group persistence and rehydration (D3-F9)
# ---------------------------------------------------------------------------


def _group_server(tmp_path, mgr: SessionManager):
    class Fake(ServerMultiSessionMixin):
        def __init__(self, cache_dir: str):
            self.cache_dir = cache_dir
            self.session_mgr = mgr

        def _dispatch_to_session(self, session_id, tool, tool_args):
            if tool == "symbols":
                return {"ok": True, "exports": [{"name": "magic", "ea": "0x1000"}]}
            if tool == "imports_deep":
                return {"ok": True, "imports": [{"name": "magic"}]}
            return {"ok": True}

    return Fake(str(tmp_path))


def test_groups_persist_and_rehydrate_across_restart(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s1 = mgr.create_session("/tmp/a.bin")
    s2 = mgr.create_session("/tmp/b.bin")

    srv1 = _group_server(tmp_path, mgr)
    srv1._init_multi_session()
    created = srv1._ms_group_create(
        {
            "group_id": "g1",
            "session_ids": [s1.session_id, s2.session_id],
            "metadata": {"label": "firmware"},
        }
    )
    assert created["ok"] is True
    linked = srv1._ms_group_link({"group_id": "g1"})
    assert linked["ok"] is True and linked["links_built"] >= 1
    assert os.path.exists(os.path.join(str(tmp_path), "groups.json"))

    # A fresh host rehydrates membership, metadata, and the link table.
    srv2 = _group_server(tmp_path, mgr)
    srv2._init_multi_session()
    group = srv2._get_group("g1")
    assert group is not None
    assert set(group.session_ids) == {s1.session_id, s2.session_id}
    assert group.metadata == {"label": "firmware"}
    assert group.links["magic"]["provider_sid"] == s1.session_id
    assert s2.session_id in group.links["magic"]["importer_sids"]


def test_group_remove_persists_and_drop_reconciles(tmp_path):
    mgr = SessionManager(str(tmp_path))
    s1 = mgr.create_session("/tmp/a.bin")
    s2 = mgr.create_session("/tmp/b.bin")

    srv1 = _group_server(tmp_path, mgr)
    srv1._init_multi_session()
    srv1._ms_group_create(
        {"group_id": "g1", "session_ids": [s1.session_id, s2.session_id]}
    )
    srv1._ms_group_remove({"group_id": "g1"})

    # Removal is persisted: a restarted host no longer sees the group.
    srv2 = _group_server(tmp_path, mgr)
    srv2._init_multi_session()
    assert srv2._get_group("g1") is None

    # _drop_sid_from_groups reconciles and persists the surviving groups.
    srv1._ms_group_create(
        {"group_id": "g2", "session_ids": [s1.session_id, s2.session_id]}
    )
    srv1._drop_sid_from_groups(s1.session_id)
    srv3 = _group_server(tmp_path, mgr)
    srv3._init_multi_session()
    g = srv3._get_group("g2")
    assert g is not None
    assert g.session_ids == [s2.session_id]


def test_require_group_hints_groups_persist_across_restart(tmp_path):
    srv = _group_server(tmp_path, SessionManager(str(tmp_path)))
    srv._init_multi_session()
    group, err = srv._require_group({"group_id": "nope"})
    assert group is None
    assert err is not None
    assert err.get("code") == MCPError.NOT_FOUND
    assert "survive restarts" in err["hint"]


def test_session_group_round_trips_links_and_metadata():
    g = SessionGroup("g1", "G")
    g.session_ids = ["A1B2C3D4", "E5F6A7B8"]
    g.links["sym"] = {"provider_sid": "A1B2C3D4", "export_ea": "0x1000", "importer_sids": ["E5F6A7B8"]}
    g.metadata = {"label": "fw"}
    restored = SessionGroup.from_dict(g.to_dict())
    assert restored.group_id == "g1"
    assert restored.session_ids == ["A1B2C3D4", "E5F6A7B8"]
    assert restored.links == g.links
    assert restored.metadata == {"label": "fw"}
