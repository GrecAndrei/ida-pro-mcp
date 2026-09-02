"""Compose session metadata, maintenance, and investigation actions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from tests.host.test_session_action_modes_full import _error, _host


def test_session_metadata_import_and_investigation_actions(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    updated = host._session_action_update(
        {
            "session_id": sid,
            "tags": ["one", "two"],
            "notes": "note",
            "auto_name": " Display ",
            "phase": "triage",
        }
    )
    assert updated["session"]["session_id"] == sid
    assert manager.updated[-1][1]["tags"] == ["one", "two"]
    assert _error(host._session_action_update({"session_id": sid}), MCPError.INVALID_ARGS)
    manager.update_session = lambda *_args, **_kwargs: None
    assert _error(
        host._session_action_update({"session_id": sid, "name": "gone"}),
        MCPError.SESSION_NOT_FOUND,
    )

    manager.export_session = lambda value: {"session_id": value, "notes": "saved"}
    host._export_session_hypotheses_to_symbol_db = lambda _sid: 3
    exported = host._session_action_export_session({"session_id": sid})
    assert exported["exported_hypotheses"] == 3
    manager.export_session = lambda _value: None
    assert _error(host._session_action_export_session({"session_id": sid}), MCPError.SESSION_NOT_FOUND)

    imported = SimpleNamespace(to_dict=lambda: {"session_id": "IMPORTED1"})
    manager.import_session = lambda data: imported
    host._normalize_ida_args = lambda value: [str(value)]
    result = host._session_action_import_session(
        {"data": {"binary_path": "sample.bin", "ida_args": ["-c"]}}
    )
    assert result["session"]["session_id"] == "IMPORTED1"
    host._normalize_ida_args = lambda _value: (_ for _ in ()).throw(ValueError("reserved"))
    assert _error(
        host._session_action_import_session({"data": {"ida_args": ["-Sbad"]}}),
        MCPError.INVALID_ARGS,
    )

    manager.validate_session = lambda value: {"session_id": value, "valid": True}
    assert host._session_action_validate({"session_id": sid})["validation"]["valid"]
    manager.validate_session = lambda _value: None
    assert _error(host._session_action_validate({"session_id": sid}), MCPError.SESSION_NOT_FOUND)

    manager.snapshot_session = lambda value: {"snapshot_id": "s1", "message": "ok"}
    assert host._session_action_snapshot({"session_id": sid})["snapshot_id"] == "s1"
    manager.snapshot_session = lambda _value: None
    assert _error(host._session_action_snapshot({"session_id": sid}), MCPError.SESSION_NOT_FOUND)
    manager.snapshot_session = lambda value: {"snapshot_id": "s1"}
    manager.restore_snapshot = lambda *_args: session
    assert host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "s1"})["ok"]
    manager.restore_snapshot = lambda *_args: None
    assert _error(
        host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "missing"}),
        MCPError.NOT_FOUND,
    )

    manager.get_session = lambda value: session if value in {sid, "SOURCE01"} else None
    manager.merge_sessions = lambda *_args: session
    merged = host._session_action_merge({"target_id": sid, "source_id": "SOURCE01"})
    assert merged["session"]["session_id"] == sid
    manager.merge_sessions = lambda *_args: None
    assert _error(
        host._session_action_merge({"session_id": sid, "source_id": "SOURCE01"}),
        MCPError.SESSION_NOT_FOUND,
    )


def test_session_skill_analogy_and_activity_argument_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.rate_skill = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.list_skills = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.suggest_triage = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.suggest_strategy = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.get_phase = lambda value: {"sid": value, "phase": "triage"}
    manager.dashboard = lambda value: {"sid": value, "complete": 1}
    manager.suggest_analogy = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.log_activity = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.track_hypothesis = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.confirm_hypothesis = lambda value, **kwargs: {"sid": value, **kwargs}
    manager.refute_hypothesis = lambda value, **kwargs: {"sid": value, **kwargs}

    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "s", "reward": 0.5})["reward"] == 0.5
    assert host._session_action_list_skills({"session_id": sid})["global_skills"] is True
    assert host._session_action_suggest_triage({"session_id": sid})["limit"] == 5
    assert host._session_action_suggest_strategy({"session_id": sid, "context": 4})["context"] == "4"
    assert host._session_action_get_phase({"session_id": sid})["phase"] == "triage"
    assert host._session_action_dashboard({"session_id": sid})["complete"] == 1
    analogy = host._session_action_suggest_analogy({"session_id": sid})
    assert analogy["threshold_cosine"] == 0.85 and analogy["limit"] == 10
    assert host._session_action_log_activity({"session_id": sid, "tool": "code", "event": "read"})["action"] == "read"
    tracked = host._session_action_track_hypothesis(
        {"session_id": sid, "statement": "x", "evidence_against": "bad,weak"}
    )
    assert tracked["evidence_against"] == ["bad", "weak"]
    assert host._session_action_confirm_hypothesis({"session_id": sid, "id": "h", "evidence": "yes"})["evidence"] == ["yes"]
    assert host._session_action_refute_hypothesis({"session_id": sid, "id": "h", "reason": "no", "evidence": "r"})["evidence"] == ["r"]


def test_session_maintenance_prunes_only_owned_stale_rows(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    old = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    manager.rows = [
        {"session_id": sid, "last_accessed": old, "binary_path": "/gone/bin", "idb_path": "/gone/idb"},
        {"session_id": "OTHER001", "last_accessed": old, "binary_path": "/gone/bin", "idb_path": "/gone/idb"},
        {"session_id": "BAD/ID", "last_accessed": old, "binary_path": "", "idb_path": ""},
    ]
    host._client_owns_session = lambda value: value == sid
    host._session_is_busy = lambda _value: False
    host._require_owned_session_id = lambda value: None if value == sid else {"error": True}

    def delete_row(value):
        manager.rows = [row for row in manager.rows if row.get("session_id") != value]
        return value == sid

    manager.delete_session = delete_row
    deleted = host._session_action_cleanup_stale({"max_age_days": 1, "prune_orphans": True})
    assert deleted["deleted_sids"] == [sid]
    assert deleted["orphan_count"] == 0

    host, manager, session = _host(tmp_path / "idle")
    sid = session.session_id
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    manager.rows = [
        {"session_id": sid, "last_accessed": old, "binary_path": str(tmp_path / "missing"), "idb_path": str(tmp_path / "missing.i64")},
        {"session_id": "OTHER001", "last_accessed": "bad", "binary_path": "", "idb_path": ""},
    ]
    host._require_owned_session_id = lambda value: None if value == sid else {"error": True}
    host._runtime_record = lambda value: {"process": object()} if value == sid else None
    host._runtime_alive = lambda _runtime: True
    purged = host._session_action_idle_purge({"idle_seconds": 1, "prune_orphans": False})
    assert purged["closed_sids"] == [sid]
    assert "OTHER001" in purged["skipped_sids"]

    host, manager, session = _host(tmp_path / "errors")
    manager.rows = [{"session_id": session.session_id, "last_accessed": old, "binary_path": "", "idb_path": ""}]
    host._runtime_record = lambda _value: {"process": object()}
    host._cleanup_runtime = lambda _value: (_ for _ in ()).throw(RuntimeError("locked"))
    failed = host._session_action_idle_purge({"idle_seconds": 1, "prune_orphans": False})
    assert failed["error"] is True and failed["code"] == MCPError.IDA_ERROR
