"""Exercise session dispatch and lifecycle actions through composed host paths."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_session import (
    ServerSessionMixin,
    _sess_coerce_none,
    _sess_coerce_note,
    _sess_coerce_query,
    _sess_coerce_rename,
    _sess_coerce_tag,
    _substitute_params,
)


class _Session:
    def __init__(self, sid="ABC12345", tmp_path=None):
        self.session_id = sid
        self.binary_path = str((tmp_path or Path("/tmp")) / "sample.bin")
        self.idb_path = str((tmp_path or Path("/tmp")) / "sample.i64")
        self.created_at = "2026-01-01T00:00:00"
        self.metadata = {}

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
            "metadata": self.metadata,
        }


class _Manager:
    def __init__(self, session):
        self.session = session
        self.deleted = []
        self.updated = []
        self.rows = []

    def get_session(self, sid):
        return self.session if sid == self.session.session_id else None

    def session_exists(self, sid):
        return sid == self.session.session_id

    def count(self):
        return 1

    def update_session(self, sid, **kwargs):
        if not self.session_exists(sid):
            return None
        self.updated.append((sid, kwargs))
        for key, value in kwargs.items():
            setattr(self.session, key, value)
        return self.session

    def list_sessions(self, **_kwargs):
        return {"sessions": list(self.rows)}

    def delete_session(self, sid):
        self.deleted.append(sid)
        return sid == self.session.session_id

    def bulk_delete(self, sids):
        return [{"session_id": sid, "deleted": True} for sid in sids]

    def get_stats(self):
        return {"sessions": 1}


class _Process:
    def __init__(self, alive=True):
        self.alive = alive

    def poll(self):
        return None if self.alive else 1


def _host(tmp_path=None):
    session = _Session(tmp_path=tmp_path)
    manager = _Manager(session)
    host = ServerSessionMixin.__new__(ServerSessionMixin)
    host.session_mgr = manager
    host.current_session = session
    host._ensure_client_owns_session = lambda _session: None
    host._session_macros = {}
    host._save_session_macros = lambda: None
    host._normalize_macro_name = lambda value: str(value).strip() if value else None
    host._drop_sid_from_groups = lambda _sid: None
    host._forget_analysis_state = lambda _sid: None
    host._cleanup_runtime = lambda _sid: None
    host._export_session_hypotheses_to_symbol_db = lambda _sid: 0
    host._runtime_record = lambda _sid: None
    host._runtime_alive = lambda _runtime: False
    def _tail(path, tail_lines=40):
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            return ""
        return "".join(lines[-tail_lines:])

    host._tail_text_file = _tail
    host._start_server = lambda _session: {"ok": True}
    return host, manager, session


def _error(result, code):
    assert result["error"] is True
    assert result["code"] == code
    return result


def test_coercers_dispatch_and_substitution_modes():
    assert _sess_coerce_none({}) == ({}, None)
    assert _sess_coerce_rename({})[1]["code"] == MCPError.INVALID_ARGS
    assert _sess_coerce_rename({"new_name": " x "})[0]["new_name"] == "x"
    assert _sess_coerce_tag({"tag": " x "})[0]["tag"] == "x"
    assert _sess_coerce_tag({"tag": "   "})[1]["code"] == MCPError.INVALID_ARGS
    assert _sess_coerce_note({})[1]["code"] == MCPError.INVALID_ARGS
    assert _sess_coerce_query({})[1]["code"] == MCPError.INVALID_ARGS
    assert _substitute_params({"a": ["$x", 2]}, {"x": "ok"}) == {"a": ["ok", 2]}

    host, manager, session = _host()
    assert host._resolve_session_id({"session_id": "ABC12345"}) == (session.session_id, None)
    assert host._resolve_session_id({"session_id": "simple"}) == ("SIMPLE", None)
    _error(host._resolve_session_id({"session_id": "bad/id"})[1], MCPError.INVALID_ARGS)
    _error(host._handle_session({"action": "missing"}), MCPError.ACTION_NOT_FOUND)
    assert host._handle_session({"action": "bootstrap_unknown"})["error"] is True

    result = host._run_session_spec(("dict", "missing_method", _sess_coerce_none), {"session_id": session.session_id})
    _error(result, MCPError.NOT_IMPLEMENTED)
    result = host._run_session_spec(("dict", "get_session", _sess_coerce_none), {"session_id": "NOPE"})
    _error(result, MCPError.SESSION_NOT_FOUND)
    manager.sessions = []
    host.session_mgr.list_sessions = lambda **_kwargs: []
    listed = host._run_session_spec(("list", "list_sessions", _sess_coerce_none), {})
    assert listed == {"ok": True, "sessions": [], "count": 0}
    manager.get_stats = lambda _sid=None: {"sessions": 1}
    raw = host._run_session_spec(("raw", "get_stats", _sess_coerce_none), {"session_id": session.session_id})
    assert raw == {"sessions": 1}


def test_logs_status_and_state_cover_empty_and_runtime_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    assert _error(host._session_action_logs({}), MCPError.IDA_ERROR)
    log = tmp_path / "ida.log"
    out = tmp_path / "ida_stdout_capture.log"
    log.write_text("one\ntwo\nthree\n", encoding="utf-8")
    out.write_text("stdout\n", encoding="utf-8")
    process = _Process()
    host._runtime_record = lambda _sid: {
        "ida_log": str(log),
        "stdout_log": str(out),
        "process": process,
    }
    logs = host._session_action_logs({"session_id": session.session_id, "lines": "2"})
    assert logs["ok"] is True
    assert logs["ida_log_tail"] == "two\nthree\n"
    assert logs["stderr_log"].endswith("ida_stderr_capture.log")
    assert logs["ida_alive"] is True
    assert _error(host._session_action_logs({"session_id": "ABC99999"}), MCPError.SESSION_NOT_FOUND)

    host._runtime_record = lambda _sid: {"process": process}
    host._safe_mode_active = lambda _sid: True
    host._analysis_is_complete = lambda _sid: False
    host._analysis_state_lock = lambda: SimpleNamespace(__enter__=lambda self: self, __exit__=lambda *args: False)
    host._arm_analysis_watcher_if_needed = lambda _sid: None
    host._maybe_resolve_analysis_state = lambda _session: None
    host._query_ida_state = lambda _sid: {
        "analysis": {"is_ok": True, "active": False},
        "inventory": {"functions_qty": "12"},
    }
    status = host._session_action_status({"session_id": session.session_id})
    assert status["session"]["analysis_ready"] is True
    assert status["session"]["analysis_functions_qty"] == 12
    assert status["total_sessions"] == 1

    host.current_session = None
    state = host._session_action_state({})
    _error(state, MCPError.SESSION_NOT_FOUND)


def test_update_rebuild_kill_and_bulk_error_modes(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    assert _error(host._session_action_update({}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_update({"session_id": sid, "bad": 1}), MCPError.INVALID_ARGS)
    updated = host._session_action_update({"session_id": sid, "tags": "a, b", "notes": "n", "name": "Demo", "phase": "triage"})
    assert updated["ok"] is True
    assert manager.updated[-1][1]["tags"] == ["a", "b"]
    assert _error(host._session_action_update({"session_id": sid}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_update({"session_id": "missing", "name": "x"}), MCPError.SESSION_NOT_FOUND)

    host.current_session = None
    assert _error(host._session_action_rebuild({}), MCPError.INVALID_ARGS)
    host.current_session = session
    assert _error(host._session_action_rebuild({"session_id": "missing"}), MCPError.SESSION_NOT_FOUND)
    (Path(session.idb_path)).write_text("idb", encoding="utf-8")
    host._start_server = lambda _session: {"ok": True, "current_options": {"processor": "x86"}}
    host._mark_analysis_pending = lambda _session: None
    rebuilt = host._session_action_rebuild({"session_id": sid, "processor": "x86"})
    assert rebuilt["ok"] is True
    assert not Path(session.idb_path).exists()
    assert sid not in getattr(host, "_reloading_sessions", set())

    host._start_server = lambda _session: {"error": True, "message": "spawn failed"}
    failed = host._session_action_rebuild({"session_id": sid})
    assert failed["error"] is True
    assert failed["safe_mode"] is True
    monkeypatch.setattr("os.path.exists", lambda _path: True)
    monkeypatch.setattr("os.remove", lambda _path: (_ for _ in ()).throw(OSError("locked")))
    assert host._session_action_rebuild({"session_id": sid})["code"] == MCPError.FILE_LOCKED

    host._runtime_record = lambda _sid: {"process": _Process()}
    host._kill_ida_process = lambda _runtime, grace_sec: {"terminated": True, "signaled": True, "grace_sec": grace_sec}
    host._collect_ida_state_snapshot = lambda **_kwargs: {"analysis": {}}
    killed = host._session_action_kill({"session_id": sid, "grace_sec": "99"})
    assert killed["ok"] is True
    assert killed["session_id"] == sid
    assert _error(host._session_action_kill({"session_id": "missing"}), MCPError.SESSION_NOT_FOUND)
    host._runtime_record = lambda _sid: {"process": _Process()}
    host._kill_ida_process = lambda *_args, **_kwargs: {"terminated": False}
    assert host._session_action_kill({"session_id": sid})["code"] == MCPError.IDA_ERROR

    assert _error(host._session_action_bulk_delete({}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_bulk_delete({"session_ids": "bad"}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_bulk_delete({"session_ids": ["bad/id"]}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_bulk_tag({}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_bulk_tag({"session_ids": [sid]}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_bulk_tag({"session_ids": "bad", "tag": "x"}), MCPError.INVALID_ARGS)


def test_cleanup_idle_and_workflow_boundaries(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.rows = [
        {"session_id": sid, "last_accessed": "2020-01-01T00:00:00+00:00", "binary_path": "/gone/bin", "idb_path": "/gone/idb"},
        {"session_id": "SIMPLE", "last_accessed": "not-a-date", "binary_path": "", "idb_path": ""},
    ]
    host._runtime_record = lambda _sid: None
    stale = host._session_action_cleanup_stale({"max_age_days": "1", "prune_orphans": False})
    assert stale["ok"] is True
    assert sid in stale["deleted_sids"]
    assert _error(host._session_action_idle_purge({}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_idle_purge({"idle_seconds": 0}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_idle_purge({"idle_seconds": "x"}), MCPError.INVALID_ARGS)

    host._execute_tool = lambda tool, args: {"ok": True, "tool": tool, **args}
    flow = host._run_workflow_sequence(
        "demo",
        [
            None,
            {"tool": "session", "action": "", "if": "$run"},
            {"tool": "session", "action": "status", "if": "$run", "then": {"action": "get"}, "else": {"action": "list"}},
            {"tool": "session", "action": "status", "if": "$missing", "then": "bad"},
        ],
        {"run": False},
    )
    assert flow["ok"] is True
    assert flow["step_count"] == 4
    assert flow["steps"][0]["result"]["code"] == MCPError.INVALID_ARGS
    assert flow["steps"][2]["skipped"] is False if "skipped" in flow["steps"][2] else True


def test_session_strategy_analogy_activity_hypothesis_and_macro_edges(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    manager.rate_skill = lambda *args, **kwargs: {"rated": True, **kwargs}
    manager.list_skills = lambda *args, **kwargs: {"skills": [], **kwargs}
    manager.suggest_triage = lambda *args, **kwargs: {"triage": True, **kwargs}
    manager.suggest_strategy = lambda *args, **kwargs: {"strategy": True, **kwargs}
    manager.get_phase = lambda *_args: {"phase": "triage"}
    manager.dashboard = lambda *_args: {"dashboard": True}
    manager.suggest_analogy = lambda *args, **kwargs: {"analogy": True, **kwargs}
    manager.log_activity = lambda *args, **kwargs: {"logged": True, **kwargs}
    manager.track_hypothesis = lambda *args, **kwargs: {"hypothesis": "H1", **kwargs}
    manager.confirm_hypothesis = lambda *args, **kwargs: {"confirmed": True, **kwargs}
    manager.refute_hypothesis = lambda *args, **kwargs: {"refuted": True, **kwargs}

    for action in (
        host._session_action_rate_skill,
        host._session_action_list_skills,
        host._session_action_suggest_triage,
        host._session_action_suggest_strategy,
        host._session_action_get_phase,
        host._session_action_dashboard,
    ):
        assert action({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS

    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "x", "reward": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "x", "reward": "0.75"})["rated"] is True
    assert host._session_action_list_skills({"session_id": sid, "min_q": "bad"})["code"] == MCPError.INVALID_ARGS
    skills = host._session_action_list_skills({"session_id": sid, "min_q": "0.4", "global_skills": "false"})
    assert skills["global_skills"] is False
    assert host._session_action_suggest_triage({"session_id": sid, "limit": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_triage({"session_id": sid, "context": 7})["limit"] == 5
    assert host._session_action_suggest_strategy({"session_id": sid, "context": 7})["context"] == "7"
    assert host._session_action_get_phase({"session_id": sid})["phase"] == "triage"
    assert host._session_action_dashboard({"session_id": sid})["dashboard"] is True

    assert host._session_action_suggest_analogy({"session_id": sid, "library_idbs": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_analogy({"session_id": sid, "threshold_cosine": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_analogy({"session_id": sid, "threshold_structural": "bad"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_suggest_analogy({"session_id": sid, "limit": "bad"})["code"] == MCPError.INVALID_ARGS
    analogy = host._session_action_suggest_analogy({"session_id": sid, "library_idbs": ["a.i64"], "limit": "2"})
    assert analogy["limit"] == 2

    applied = []
    host.call_tool = lambda *args, **kwargs: applied.append((args, kwargs)) or {"ok": True}
    result = host._session_action_apply_analogy({
        "session_id": sid,
        "mappings": ["bad", {}, {"name": "missing"}, {"addr": "0x1000", "name": "renamed", "comment": "note"}],
    })
    assert result["applied"] == 4
    assert len(applied) == 2

    assert host._session_action_log_activity({"session_id": sid, "tool": "x"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_log_activity({"session_id": sid, "tool": "x", "event": "done"})["logged"] is True
    assert host._session_action_track_hypothesis({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "confidence": "bad"})["code"] == MCPError.INVALID_ARGS
    tracked = host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "evidence_for": "a,b", "evidence_against": "c", "confidence": "0.8"})
    assert tracked["evidence_for"] == ["a", "b"]
    assert host._session_action_confirm_hypothesis({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_confirm_hypothesis({"session_id": sid, "id": "H1", "evidence": "yes"})["confirmed"] is True
    assert host._session_action_refute_hypothesis({"session_id": sid})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_refute_hypothesis({"session_id": sid, "id": "H1"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_refute_hypothesis({"session_id": sid, "id": "H1", "reason": "wrong", "evidence": "no"})["refuted"] is True

    assert host._session_action_macro_delete({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_run({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_run({"name": "missing"})["code"] == MCPError.FILE_NOT_FOUND
    host._session_macros["one"] = {"name": "one", "data": {"action": "status"}}
    host._execute_tool = lambda _tool, args: {"ok": True, **args}
    ran = host._session_action_macro_run({"name": "one", "run_action": "status"})
    assert ran["macro"] == "one"
    host._session_macros["workflow"] = {"name": "workflow", "data": {"calls": [{"tool": "session", "action": "status"}]}}
    assert host._session_action_macro_run({"name": "workflow"})["step_count"] == 1
    assert host._run_workflow_sequence("bad", ["not-a-dict"], {})["steps"][0]["result"]["code"] == MCPError.INVALID_ARGS

    host.current_session = None
    assert host._session_action_recent_workset({})["code"] == MCPError.INVALID_ARGS
