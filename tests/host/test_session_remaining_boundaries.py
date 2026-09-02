"""Boundary coverage for session state, observability, and cleanup paths."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from tests.host.test_session_action_modes_full import _error, _host


def test_declarative_session_specs_cover_missing_none_list_and_raw_results(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    def passthrough(args):
        return args, None

    missing = host._run_session_spec(("dict", "missing_method", passthrough), {"session_id": sid})
    assert _error(missing, MCPError.NOT_IMPLEMENTED)

    manager.rename = lambda *_args, **_kwargs: None
    not_found = host._run_session_spec(("dict", "rename", passthrough), {"session_id": sid})
    assert _error(not_found, MCPError.SESSION_NOT_FOUND)

    manager.list_sessions = lambda **_kwargs: [session]
    listed = host._run_session_spec(("list", "list_sessions", passthrough), {})
    assert listed["count"] == 1 and listed["sessions"][0]["session_id"] == sid

    manager.raw_result = lambda *_args, **_kwargs: {"raw": True}
    assert host._run_session_spec(("raw", "raw_result", passthrough), {"session_id": sid}) == {"raw": True}


def test_state_payload_covers_firmware_fallback_blackboard_guidance_and_narrative(tmp_path):
    host, _manager, _session = _host(tmp_path)
    host._get_cached_coverage = lambda _sid: {"total_functions": 40, "pct_named": 10}
    host._execute_tool = lambda _tool, _args: {
        "meta": {
            "binary_path": "blob.bin",
            "processor": "arm",
            "file_type": "raw",
            "file_size": "bad",
            "import_count": "0",
        },
        "summary": {"imports": "bad"},
    }

    class Blackboard:
        def stats(self):
            return {"entries": 3}

        def next_target(self, limit):
            assert limit == 5
            return [{"addr": "0x1000", "title": "decode packet"}]

        def list(self, category, **_kwargs):
            if category == "hypothesis":
                return [{"title": "network path", "addr": "0x1000", "confidence": 0.8}]
            if category == "ioc":
                return [{"ioc_type": "domain", "ioc_value": "example.test", "addr": "0x2000"}]
            if category == "vuln":
                return [{"title": "unsafe copy", "addr": "0x3000", "confidence": 0.9}]
            return []

    def make_blackboard():
        return Blackboard()

    host._bb_store = make_blackboard
    state = host._build_state_payload()
    assert state["binary"]["is_firmware"] is True
    assert state["binary"]["imports"] == "bad"
    assert state["blackboard"]["stats"] == {"entries": 3}
    assert len(state["_next_actions"]) == 3

    class NarrativeBlackboard(Blackboard):
        def list(self, category, **kwargs):
            if category == "narrative":
                return [{"content": "A" * 60}]
            return super().list(category, **kwargs)

    def make_narrative_blackboard():
        return NarrativeBlackboard()

    host._bb_store = make_narrative_blackboard
    narrative = host._build_state_payload()
    assert isinstance(narrative, str) and narrative.startswith("<!-- state:")


def test_state_and_coverage_failures_are_explicit_and_cache_is_bounded(tmp_path):
    host, _manager, session = _host(tmp_path)
    host._arm_analysis_watcher_if_needed = lambda _sid: None
    host._session_ownership_report = lambda _sid: {"locked": False}
    host._safe_mode_active = lambda _sid: False
    host._analysis_is_complete = lambda _sid: False
    host._build_state_payload = lambda: (_ for _ in ()).throw(RuntimeError("state unavailable"))
    assert _error(host._session_action_state({}), MCPError.IDA_ERROR)
    host.current_session = None
    assert _error(host._session_action_state({}), MCPError.SESSION_NOT_FOUND)

    host.current_session = session
    host._session_state_cache_lock = object()
    host._execute_tool = lambda *_args, **_kwargs: {
        "functions": "0x1000 4 named\n0x2000 4 sub_2000\n"
    }
    first = host._get_cached_coverage(session.session_id)
    assert first == {
        "total_functions": 2,
        "named_functions": 1,
        "unnamed_functions": 1,
        "pct_named": 50.0,
    }
    assert host._get_cached_coverage(session.session_id) == first

    host._session_state_cache = {
        f"old-{i}": {"coverage": {}, "_ts": 0} for i in range(128)
    }
    host._execute_tool = lambda *_args, **_kwargs: {"items": []}
    host._get_cached_coverage("new")
    assert len(host._session_state_cache) == 128

    host._execute_tool = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("RPC failed"))
    assert host._get_cached_coverage("failed") == {}


def test_session_logs_and_status_report_runtime_and_watchdog_fallbacks(tmp_path):
    host, _manager, session = _host(tmp_path)
    process = SimpleNamespace(poll=lambda: None)
    host._runtime_record = lambda _sid: {
        "process": process,
        "ida_log": "/tmp/ida.log",
        "stdout_log": "/tmp/ida_stdout_worker.log",
        "stderr_log": None,
    }
    host._tail_text_file = lambda path, tail_lines=40: f"{path}:{tail_lines}"
    logs = host._session_action_logs({"lines": "not-a-number"})
    assert logs["lines_requested"] == 80
    assert logs["stderr_log"] == "/tmp/ida_stderr_worker.log"
    assert logs["ida_alive"] is True

    host._runtime_record = lambda _sid: None
    assert _error(host._session_action_logs({}), MCPError.IDA_ERROR)
    host.current_session = None
    assert _error(host._session_action_logs({}), MCPError.SESSION_REQUIRED)

    host.current_session = session
    session.metadata = {
        "analysis_is_ok": True,
        "analysis_state": "stalled",
        "analysis_stall_seconds": "invalid",
        "indexing_state": "warm",
        "indexing_mode": "background",
        "hot_indexed_count": "4",
        "last_apply_steps": ["processor"],
        "apply_progress": {"done": 1},
    }
    host._runtime_record = lambda _sid: {"process": process}
    host._safe_mode_active = lambda _sid: True
    host._analysis_is_complete = lambda _sid: False
    host._arm_analysis_watcher_if_needed = lambda _sid: None
    host._maybe_resolve_analysis_state = lambda _session: None
    host._query_ida_state = lambda _sid: {
        "analysis": {"is_ok": True, "active": False},
        "inventory": {"functions_qty": "invalid"},
    }
    status = host._session_action_status({})
    assert status["session"]["analysis_ready"] is True
    assert status["session"]["analysis_functions_qty"] is None
    assert status["session"]["analysis_stalled"] is True
    assert status["session"]["hot_indexed_count"] == 4
    assert status["session"]["steps_done"] == 1

    host._runtime_record = lambda _sid: {"process": SimpleNamespace(poll=lambda: 1)}
    fallback = host._session_action_status({})
    assert fallback["session"]["analysis_ready"] is True
    host.current_session = None
    assert host._session_action_status({})["session"] is None


def test_cleanup_stale_and_idle_purge_cover_age_orphan_and_runtime_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    old = (datetime.now() - timedelta(days=90)).isoformat()
    fresh = datetime.now().isoformat()
    age_rows = [
        {"session_id": session.session_id, "last_accessed": old, "binary_path": "/gone", "idb_path": "/gone.i64"},
        {"session_id": "NOMARK01", "last_accessed": None, "binary_path": "", "idb_path": ""},
        {"session_id": "BADDATE1", "last_accessed": "not-a-date", "binary_path": "", "idb_path": ""},
        {"session_id": "FRESH001", "last_accessed": fresh, "binary_path": "", "idb_path": ""},
        {"session_id": "BUSY001", "last_accessed": old, "binary_path": "", "idb_path": ""},
    ]
    orphan_rows = [
        {"session_id": "BAD/ID", "binary_path": "/gone", "idb_path": "/gone.i64"},
        {"session_id": "ORPHAN01", "binary_path": "/gone", "idb_path": "/gone.i64"},
    ]
    rows = iter([age_rows, orphan_rows])
    manager.list_sessions = lambda **_kwargs: {"sessions": next(rows)}
    manager.get_session = lambda sid: SimpleNamespace(session_id=sid)
    manager.delete_session = lambda _sid: True
    host._runtime_record = lambda sid: {"process": object()} if sid == "BUSY001" else None
    host._runtime_alive = lambda _runtime: True
    host._cleanup_runtime = lambda _sid: None
    host._drop_sid_from_groups = lambda _sid: None
    result = host._session_action_cleanup_stale({"max_age_days": 1, "prune_orphans": True})
    assert session.session_id in result["deleted_sids"]
    assert result["orphan_sids"] == ["ORPHAN01"]
    assert host.current_session is None

    host, manager, session = _host(tmp_path / "idle")
    stale = (datetime.now() - timedelta(seconds=1000)).isoformat()
    idle_rows = [
        {"session_id": session.session_id, "last_accessed": stale, "binary_path": "", "idb_path": ""},
        {"session_id": "UNKNOWN1", "last_accessed": None, "binary_path": "", "idb_path": ""},
        {"session_id": "INVALID1", "last_accessed": "bad", "binary_path": "", "idb_path": ""},
        {"session_id": "NORUN001", "last_accessed": stale, "binary_path": "", "idb_path": ""},
    ]
    manager.list_sessions = lambda **_kwargs: {"sessions": idle_rows}
    manager.get_session = lambda sid: SimpleNamespace(session_id=sid)
    manager.delete_session = lambda _sid: True
    host._runtime_record = lambda sid: {"process": object()} if sid == session.session_id else None
    host._cleanup_runtime = lambda _sid: None
    host._drop_sid_from_groups = lambda _sid: None
    purged = host._session_action_idle_purge({"idle_seconds": 10, "prune_orphans": False})
    assert purged["closed_sids"] == [session.session_id]
    assert purged["skipped_sids"]


def test_narrative_validation_stats_and_export_boundaries(tmp_path):
    host, manager, session = _host(tmp_path)
    host._activity_log = [
        {"tool": "code", "action": "decompile", "addresses": ["0x1000"], "topic": "entry", "target": "main", "ts": "now"},
        {"tool": "data", "action": "strings", "addresses": [], "ts": "later"},
    ]
    narrative = host._session_action_narrative({"limit": "999"})
    assert narrative["turn_count"] == 2
    assert narrative["turns"][0]["topic"] == "entry"
    host.current_session = None
    assert host._session_action_narrative({"limit": 0})["session"] == {}

    manager.validate_session = lambda _sid: None
    assert _error(host._session_action_validate({"session_id": session.session_id}), MCPError.SESSION_NOT_FOUND)
    manager.validate_session = lambda _sid: {"valid": True}
    assert host._session_action_validate({"session_id": session.session_id})["validation"]["valid"] is True
    assert host._session_action_stats({})["stats"] == {"sessions": 1}
