"""Exercise session actions across validation, runtime, and composed modes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from tests.host.test_session_action_modes_full import _error, _host, _Process, _Session


def test_session_switch_and_runtime_wait_modes(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    binary = Path(session.binary_path)
    binary.write_bytes(b"MZ")
    Path(session.idb_path).unlink(missing_ok=True)
    old_idb = str(tmp_path / "old.i64")
    session.idb_path = old_idb
    Path(old_idb).write_bytes(b"old")
    calls = []
    host._client_owns_session = lambda _sid: True
    host._session_is_busy = lambda _sid: False
    host._trigger_session_diff = lambda old, new: calls.append((old, new))
    host._runtime_record = lambda _sid: None
    host._runtime_alive = lambda _runtime: False
    host._mark_analysis_pending = lambda _session: calls.append("pending")
    host._start_server = lambda _session: {"ok": True}
    wait_for_idb = host._wait_for_idb
    host._wait_for_idb = lambda _session, timeout: calls.append(timeout) or True
    assert host._session_action_switch({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_switch({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_switch({"session_id": "missing"})["code"] == MCPError.SESSION_NOT_FOUND
    result = host._session_action_switch({"session_id": sid, "reopen": True})
    assert result["ok"] is True
    assert result["session"]["session_id"] == sid
    assert "pending" in calls

    host._start_server = lambda _session: {"error": True, "message": "no idat"}
    failed = host._session_action_switch({"session_id": sid, "reopen": True})
    assert failed["ok"] is True
    assert failed["spawn_error"]["message"] == "no idat"

    host._start_server = lambda _session: (_ for _ in ()).throw(RuntimeError("boom"))
    crashed = host._session_action_switch({"session_id": sid, "reopen": True})
    assert crashed["spawn_error"]["code"] == MCPError.IDA_CRASHED

    component = Path(f"{session.binary_path}.i64")
    component.write_bytes(b"component")
    session.idb_path = str(tmp_path / "metadata" / "missing.i64")
    host._wait_for_idb = wait_for_idb
    assert host._wait_for_idb(session, timeout=0) is True
    assert session.idb_path == str(component)
    assert host._wait_for_idb(SimpleNamespace(session_id=sid), timeout=0) is False

    component.unlink()
    session.idb_path = str(tmp_path / "missing.i64")
    host._runtime_record = lambda _sid: {"process": _Process(alive=False)}
    monkeypatch.setattr("ida_pro_mcp.host.server.server_session.os.listdir", lambda _path: (_ for _ in ()).throw(OSError("gone")))
    assert host._wait_for_idb(session, timeout=0) is False


def test_session_target_state_and_visibility_error_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    host.current_session = None
    assert host._session_action_close({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_state({})["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_action_state({"idb": "bad/id"})["code"] == MCPError.INVALID_ARGS
    manager.get_session = lambda _sid: (_ for _ in ()).throw(RuntimeError("db"))
    assert host._session_action_state({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND

    host, manager, session = _host(tmp_path)
    host._client_owns_session = lambda value: value == sid
    host._session_is_busy = lambda value: value != sid
    manager.rows = [session.to_dict(), {"session_id": "OTHER01"}]
    manager.list_sessions = lambda **_kwargs: {"sessions": list(manager.rows), "total": 2}
    manager.get_session = lambda value: session if value == sid else None
    host._runtime_record = lambda _sid: {"process": _Process()} if _sid == sid else None
    host._safe_mode_active = lambda _sid: False
    host._analysis_is_complete = lambda _sid: True
    host._session_ownership_report = lambda _sid: {"locked": False}
    listed = host._session_action_list({"limit": "0", "offset": "bad"})
    assert listed["count"] == 1
    manager.search_notes = lambda _query: [session, SimpleNamespace(session_id="OTHER01", to_dict=lambda: {"session_id": "OTHER01"}), SimpleNamespace(to_dict=dict)]
    assert host._session_action_search_notes({})["code"] == MCPError.INVALID_ARGS
    searched = host._session_action_search_notes({"query": "needle"})
    assert searched["count"] == 1


def test_session_state_payload_firmware_and_failure_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    host._execute_tool = lambda action, _args: (
        {
            "meta": {
                "binary_path": "firmware.bin",
                "processor": "arm",
                "file_type": "raw",
                "file_type_id": "not-a-number",
                "import_count": "not-a-number",
            },
            "summary": {"imports": "also-bad"},
        }
        if action == "idb"
        else {"functions": "0x10 4 xrefs=0 sub_start\n0x20 4 xrefs=1 useful"}
    )
    host._bb_store = lambda: None
    manager.active_session_id = session.session_id
    state = host._build_state_payload()
    assert state["binary"]["is_firmware"] is True
    assert state["coverage"]["total_functions"] == 2
    assert state["coverage"]["named_functions"] == 1
    assert state["session"]["active_session_id"] == session.session_id
    assert state["_next_actions"]

    host._execute_tool = lambda *_args: (_ for _ in ()).throw(RuntimeError("rpc"))
    host._get_cached_coverage = lambda _sid: {}
    failed = host._build_state_payload()
    assert failed["binary"] == {}
    assert "blackboard" not in failed


def test_session_action_validation_and_skill_boundary_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.export_session = lambda _sid: None
    host.current_session = None
    assert host._session_action_export_session({})["code"] == MCPError.INVALID_ARGS
    host.current_session = session
    assert host._session_action_export_session({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_action_import_session({})["code"] == MCPError.INVALID_ARGS
    host._normalize_ida_args = lambda _value: (_ for _ in ()).throw(ValueError("reserved flag"))
    assert host._session_action_import_session({"data": {"ida_args": ["-S"]}})["code"] == MCPError.INVALID_ARGS
    manager.validate_session = lambda _sid: None
    assert host._session_action_validate({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND
    manager.snapshot_session = lambda _sid: None
    assert host._session_action_snapshot({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_action_restore_snapshot({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    manager.restore_snapshot = lambda *_args: None
    assert host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "missing"})["code"] == MCPError.NOT_FOUND
    assert host._session_action_merge({"session_id": sid, "source_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_rate_skill({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_list_skills({"session_id": sid, "min_q": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_triage({"session_id": sid, "limit": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_analogy({"session_id": sid, "threshold_structural": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_analogy({"session_id": sid, "limit": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_apply_analogy({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_apply_analogy({"session_id": sid, "mappings": "bad"})["code"] == MCPError.INVALID_ARGS
    session.idb_path = None
    assert host._session_action_apply_analogy({"session_id": sid, "mappings": [{}]})["code"] == MCPError.INVALID_ARGS


def test_session_activity_macro_and_workflow_boundary_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    assert host._session_action_log_activity({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_log_activity({"session_id": sid, "tool": "code"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_track_hypothesis({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "confidence": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_confirm_hypothesis({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_refute_hypothesis({"session_id": sid, "hypothesis_id": "h"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_set({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_get({"name": "missing"})["code"] == MCPError.FILE_NOT_FOUND
    assert host._session_action_macro_delete({"name": "missing"})["code"] == MCPError.FILE_NOT_FOUND
    host._session_action_macro_set({"name": "flow", "data": {"calls": [{"action": "status"}, "bad", {"if": "$run", "then": {"action": "then"}, "else": {"action": "else"}}]}})
    host._execute_tool = lambda tool, args: {"ok": True, "tool": tool, **args}
    result = host._session_action_macro_run({"name": "flow", "run": False})
    assert result["step_count"] == 3
    assert result["steps"][2]["action"] == "else"
    host._session_action_macro_set({"name": "bad-run", "data": {"action": "macro_nested"}})
    assert host._session_action_macro_run({"name": "bad-run"})["code"] == MCPError.INVALID_ARGS
    host._session_action_macro_set({"name": "empty-run", "data": {"action": " "}})
    assert host._session_action_macro_run({"name": "empty-run"})["code"] == MCPError.INVALID_ARGS


def test_session_cleanup_and_bulk_ownership_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    assert host._session_action_bulk_delete({"session_ids": ["bad/id"]})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_bulk_tag({"session_ids": ["bad/id"], "tag": "x"})["code"] == MCPError.INVALID_ARGS
    manager.bulk_tag = lambda _sids, _tag: []
    assert host._session_action_bulk_tag({"session_ids": [sid], "tag": "   "})["code"] == MCPError.INVALID_ARGS
    manager.rows = [{"session_id": sid, "last_accessed": "bad", "binary_path": "/gone", "idb_path": "/gone"}]
    host._client_owns_session = lambda _sid: True
    host._session_is_busy = lambda _sid: False
    assert host._session_action_cleanup_stale({"max_age_days": "bad", "prune_orphans": False})["ok"] is True
    assert host._session_action_idle_purge({"idle_seconds": 1, "prune_orphans": False})["ok"] is True
    assert host._session_action_recent_workset({"session_id": "missing"})["code"] == MCPError.SESSION_NOT_FOUND
