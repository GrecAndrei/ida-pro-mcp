"""Exercise session reads, switching, and the runtime/IDB handoff boundary."""

from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.host.errors import MCPError
from tests.host.test_session_action_modes_full import _host, _Session


def test_get_and_list_include_runtime_and_ownership_forensics(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    session.binary_path = str(tmp_path / "sample.bin")
    Path(session.binary_path).write_bytes(b"binary")
    process = type("Process", (), {"poll": lambda self: None})()
    runtime = {"process": process, "port": 43123}
    monkeypatch.setattr(host, "_ensure_client_owns_session", lambda _session: None)
    monkeypatch.setattr(host, "_safe_mode_active", lambda _sid: False)
    monkeypatch.setattr(host, "_analysis_is_complete", lambda _sid: True)
    monkeypatch.setattr(
        host,
        "_session_ownership_report",
        lambda _sid: {"locked": True, "holder": "local", "owner_id": "owner", "owner_pid": 9, "owner_alive": True, "idat_pid": 10, "lease_age_seconds": 1.2},
    )
    monkeypatch.setattr(host, "_runtime_record", lambda _sid: runtime)
    result = host._session_action_get({"session_id": session.session_id.lower()})
    assert result["ok"] is True
    assert result["session"]["is_running"] is True
    assert result["session"]["port"] == 43123
    assert result["session"]["holder"] == "local"

    foreign = _Session("FOREIGN9", tmp_path)
    manager.list_sessions = lambda **_kwargs: {
        "sessions": [session.to_dict(), foreign.to_dict()],
        "total": 2,
    }
    monkeypatch.setattr(host, "_client_owns_session", lambda sid: sid == session.session_id)
    monkeypatch.setattr(host, "_session_is_busy", lambda sid: sid == foreign.session_id)
    monkeypatch.setattr(host, "_runtime_record", lambda sid: runtime if sid == session.session_id else None)
    listed = host._session_action_list({"limit": "2", "offset": "0"})
    assert listed["ok"] is True
    assert listed["count"] == 1
    assert listed["sessions"][0]["is_running"] is True
    assert host._session_action_get({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS


def test_switch_composes_diff_spawn_analysis_and_failure_modes(tmp_path, monkeypatch):
    host, manager, target = _host(tmp_path)
    old = _Session("OLD12345", tmp_path)
    target.binary_path = str(tmp_path / "target.bin")
    target.idb_path = str(tmp_path / "target.i64")
    Path(target.binary_path).write_bytes(b"target")
    Path(target.idb_path).write_bytes(b"idb")
    host.current_session = old
    manager.session = target
    monkeypatch.setattr(host, "_ensure_client_owns_session", lambda _session: None)
    monkeypatch.setattr(host, "_mark_analysis_pending", lambda _session: None)
    diffs = []
    monkeypatch.setattr(host, "_trigger_session_diff", lambda old_idb, new_idb: diffs.append((old_idb, new_idb)))
    process = type("Process", (), {"poll": lambda self: None})()
    runtime = {"process": process, "port": 4444}
    monkeypatch.setattr(host, "_runtime_alive", lambda value: value is runtime)
    monkeypatch.setattr(host, "_runtime_record", lambda _sid: runtime)
    monkeypatch.setattr(host, "_safe_mode_active", lambda _sid: True)
    monkeypatch.setattr(host, "_analysis_is_complete", lambda _sid: False)
    monkeypatch.setattr(host, "_start_server", lambda _session: {"ok": True})
    result = host._session_action_switch({"session_id": target.session_id, "reopen": True})
    assert result["ok"] is True
    assert result["runtime_attached"] is True
    assert result["safe_mode"] is True
    assert diffs == [(old.idb_path, target.idb_path)]

    host.current_session = old
    monkeypatch.setattr(host, "_start_server", lambda _session: {"error": True, "code": MCPError.IDA_CRASHED, "message": "failed"})
    failed = host._session_action_switch({"session_id": target.session_id, "reopen": True})
    assert failed["ok"] is True
    assert failed["session"]["session_id"] == old.session_id
    assert failed["spawn_error"]["code"] == MCPError.IDA_CRASHED


def test_wait_for_idb_and_ensure_runtime_cover_recovery_outcomes(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    session.binary_path = str(tmp_path / "firmware")
    session.idb_path = str(tmp_path / "recorded.i64")
    Path(session.binary_path).write_bytes(b"bin")
    assert host._wait_for_idb(session, timeout=0) is False

    adjacent = Path(session.binary_path + ".i64")
    adjacent.write_bytes(b"idb")
    assert host._wait_for_idb(session, timeout=0) is True
    # The alternate path is in the same directory as the recorded path, so
    # the session keeps its explicit metadata while still acknowledging the
    # IDB's presence.
    assert session.idb_path.endswith("recorded.i64")
    adjacent.unlink()
    (Path(session.idb_path).parent / f"SID_{session.session_id}.id0").write_bytes(b"component")
    assert host._wait_for_idb(session, timeout=0) is True

    process = type("Process", (), {"poll": lambda self: None})()
    runtime = {"process": process}
    host.session_runtimes = {}
    host.session_runtimes[session.session_id] = runtime
    monkeypatch.setattr(host, "_runtime_alive", lambda _runtime: True)
    monkeypatch.setattr(host, "_runtime_record", lambda _sid: runtime)
    monkeypatch.setattr(host, "_wait_for_idb", lambda *_args, **_kwargs: False)
    missing = host._ensure_runtime_and_idb(session, timeout=0)
    assert missing["code"] == MCPError.IDA_CRASHED

    host.session_runtimes.clear()
    monkeypatch.setattr(host, "_runtime_record", lambda _sid: None)
    monkeypatch.setattr(host, "_start_server", lambda _session: {"error": True, "code": MCPError.FILE_LOCKED})
    failed = host._ensure_runtime_and_idb(session)
    assert failed["code"] == MCPError.FILE_LOCKED

    monkeypatch.setattr(host, "_start_server", lambda _session: (_ for _ in ()).throw(RuntimeError("spawn")))
    raised = host._ensure_runtime_and_idb(session)
    assert raised["code"] == MCPError.IDA_CRASHED


def test_idle_purge_closes_old_runtime_and_prunes_orphan(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    old = session.to_dict()
    old["last_accessed"] = "2000-01-01T00:00:00+00:00"
    orphan = {"session_id": "DEADBEEF", "last_accessed": "2000-01-01T00:00:00+00:00", "binary_path": str(tmp_path / "gone.bin"), "idb_path": str(tmp_path / "gone.i64")}
    snapshots = iter([[old], [orphan]])
    manager.list_sessions = lambda **_kwargs: {"sessions": next(snapshots)}
    monkeypatch.setattr(host, "_require_owned_session_id", lambda _sid: None)
    monkeypatch.setattr(host, "_runtime_record", lambda value: {"process": object()} if value == sid else None)
    monkeypatch.setattr(host, "_cleanup_runtime", lambda _sid: None)
    manager.delete_session = lambda _sid: True
    forgotten = []
    monkeypatch.setattr(host, "_forget_analysis_state", forgotten.append)
    dropped = []
    monkeypatch.setattr(host, "_drop_sid_from_groups", dropped.append)
    exported = []
    monkeypatch.setattr(host, "_export_session_hypotheses_to_symbol_db", exported.append)

    result = host._session_action_idle_purge({"idle_seconds": 1})
    assert result["closed_sids"] == [sid]
    assert result["orphan_sids"] == ["DEADBEEF"]
    assert result["count"] == 1 and result["orphan_count"] == 1
    assert exported == [sid]
    assert set(forgotten) == {sid, "DEADBEEF"}
    assert set(dropped) == {sid, "DEADBEEF"}
    assert host.current_session is None
