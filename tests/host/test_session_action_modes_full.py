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


def test_session_open_argument_result_and_analysis_state_boundaries(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    def normalize_ida_args(value):
        if any("\x00" in str(item) for item in (value or [])):
            raise ValueError("IDA args must not contain NUL")
        return [item for item in value if item != "-A"]

    host._normalize_ida_args = normalize_ida_args
    assert host._prepare_open_args({"idb_path": "/removed"})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": 7})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": "x", "analysis_options": []})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": "x", "architecture": []})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": "x", "analysis_options": {"processor": "arm"}, "processor": "mips"})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": "x", "architecture": {"arch": "arm"}, "processor": "mips"})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({"binary_path": "x", "ida_args": ["\x00"]})[-1]["code"] == MCPError.INVALID_ARGS
    assert host._prepare_open_args({})[-1]["code"] == MCPError.INVALID_ARGS

    binary = tmp_path / "payload.bin"
    binary.write_bytes(b"payload")
    prepared = host._prepare_open_args(
        {
            "binary_path": str(binary),
            "architecture": {"arch": "arm", "bits": 32, "endianness": "little"},
            "ida_args": ["-A", "-z"],
        }
    )
    assert prepared[-1] is None
    assert prepared[1]["processor"] == "arm"
    assert prepared[1]["bitness"] == 32
    assert prepared[4] == ["-z"]
    assert host._preloads_match(SimpleNamespace(analysis_options={"processor": "arm"}), {"processor": "arm"})
    assert not host._preloads_match(SimpleNamespace(analysis_options={"processor": "x86"}), {"processor": "arm"})

    host._runtime_record = lambda _sid: {"process": _Process(alive=True), "port": 1234}
    host._runtime_alive = lambda _runtime: True
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True, "functions": 9}
    assert host._open_analysis_state(session) == {"analysis_complete": True, "analysis_functions": 9}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": False}
    assert host._open_analysis_state(session) == {}
    host._send_rpc_raw = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("rpc"))
    assert host._open_analysis_state(session) == {}

    host._mark_analysis_complete = lambda current: setattr(current, "metadata", {"complete": True})
    host.safe_mode_poll_seconds = 0
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True, "functions": 9}
    assert host._wait_for_analysis_complete(session, timeout=0.1)["analysis_complete"] is True

    host._safe_mode_active = lambda _sid: False
    host._analysis_is_complete = lambda _sid: True
    host._checkpoint_staleness_warning = lambda _session: "stale checkpoint"
    opened = host._open_result(
        session,
        background=True,
        reused=True,
        note="reused",
        extra={"warning": "existing warning"},
    )
    assert opened["reused_existing_session"] is True
    assert opened["background"] is True
    assert opened["note"] == "reused"
    assert opened["warning"] == "existing warning stale checkpoint"


def test_session_discovery_reads_and_note_visibility_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    manager._load_orphaned_idbs = lambda: None
    manager.discover_sessions = lambda **_kwargs: [session]
    discovered = host._session_action_discover({"query": "sample", "binary_name": "sample.bin"})
    assert discovered["ok"] is True and discovered["count"] == 1

    host._session_ownership_report = lambda _sid: {"locked": False, "holder": None}
    host._safe_mode_active = lambda _sid: False
    host._analysis_is_complete = lambda _sid: True
    got = host._session_action_get({"session_id": session.session_id})
    assert got["ok"] is True and got["session"]["analysis_complete"] is True
    assert host._session_action_get({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_get({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_get({"session_id": "MISSING1"})["code"] == MCPError.SESSION_NOT_FOUND

    other = _Session("BBBB0002", tmp_path)
    manager.search_notes = lambda _query: [session, other, SimpleNamespace(to_dict=lambda: {"session_id": "none"})]
    host._client_owns_session = lambda sid: sid == session.session_id
    host._session_is_busy = lambda sid: sid == other.session_id
    assert host._session_action_search_notes({})["code"] == MCPError.INVALID_ARGS
    notes = host._session_action_search_notes({"query": "needle"})
    assert notes["count"] == 1 and notes["sessions"][0]["session_id"] == session.session_id

    host._session_ownership_report = lambda _sid: {"locked": False}
    host._runtime_record = lambda _sid: None
    assert host._session_action_switch({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_switch({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_switch({"session_id": "MISSING1"})["code"] == MCPError.SESSION_NOT_FOUND


def test_session_state_coverage_cache_supports_legacy_text_and_eviction(tmp_path):
    host, _manager, session = _host(tmp_path)
    calls = []
    host._execute_tool = lambda tool, args: calls.append((tool, args)) or {
        "functions": "0x1000 4 sub_first\n0x2000 8 named_function\n"
    }
    coverage = host._get_cached_coverage(session.session_id)
    assert coverage == {
        "total_functions": 2,
        "named_functions": 1,
        "unnamed_functions": 1,
        "pct_named": 50.0,
    }
    assert host._get_cached_coverage(session.session_id) == coverage
    assert len(calls) == 1

    host._session_state_cache = {f"old{i}": {"coverage": {}, "_ts": 0} for i in range(130)}
    host._execute_tool = lambda *_args: {"items": [{"name": "j_jump"}, {"name": "real"}]}
    fresh = host._get_cached_coverage("fresh")
    assert fresh["unnamed_functions"] == 1
    assert len(host._session_state_cache) <= 128


def test_session_admin_snapshot_merge_and_narrative_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    host._activity_log = [
        {"tool": "search", "action": "find", "addresses": ["0x10"], "topic": "entry", "target": "main", "ts": "t1"},
        {"tool": "code", "action": "decompile", "addresses": [], "topic": "", "target": "", "ts": "t2"},
    ]
    narrative = host._session_action_narrative({"limit": "1"})
    assert narrative["turn_count"] == 1
    assert narrative["turns"][0]["action"] == "decompile"
    assert "addresses" not in narrative["turns"][0]
    assert narrative["session"]["session_id"] == sid

    host.current_session = None
    empty_narrative = host._session_action_narrative({"limit": "0"})
    assert empty_narrative["turn_count"] == 1
    assert empty_narrative["session"] == {}
    host.current_session = session

    manager.validate_session = lambda value: {"session_id": value, "valid": True}
    assert host._session_action_validate({"session_id": "bad/id"})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_validate({"session_id": sid})["validation"]["valid"] is True
    manager.validate_session = lambda _value: None
    assert host._session_action_validate({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND

    manager.bulk_tag = lambda sids, tag: {"session_ids": sids, "tag": tag}
    tagged = host._session_action_bulk_tag({"session_ids": [sid], "tag": "  important  "})
    assert tagged["results"]["tag"] == "important"
    assert host._session_action_bulk_tag({"session_ids": [sid], "tag": " "})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_bulk_tag({"session_ids": ["bad/id"], "tag": "x"})["code"] == MCPError.INVALID_ARGS

    cleanup = []
    forgotten = []
    dropped = []

    def record_cleanup(value):
        cleanup.append(value)

    def record_forgotten(value):
        forgotten.append(value)

    def record_dropped(value):
        dropped.append(value)

    host._require_owned_session_id = lambda _sid: None
    host._cleanup_runtime = record_cleanup
    host._forget_analysis_state = record_forgotten
    host._drop_sid_from_groups = record_dropped
    deleted = host._session_action_bulk_delete({"session_ids": [sid]})
    assert deleted["ok"] is True and deleted["results"][0]["session_id"] == sid
    assert host.current_session is None
    assert cleanup == forgotten == dropped == [sid]
    host.current_session = session

    manager.snapshot_session = lambda value: {"snapshot_id": "snap-1", "message": "saved"}
    snapshot = host._session_action_snapshot({"session_id": sid})
    assert snapshot == {"ok": True, "session_id": sid, "snapshot_id": "snap-1", "message": "saved"}
    manager.snapshot_session = lambda _value: None
    assert host._session_action_snapshot({"session_id": sid})["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_action_restore_snapshot({"session_id": sid})["code"] == MCPError.INVALID_ARGS

    manager.snapshot_session = lambda _value: {"snapshot_id": "snap-1", "message": "saved"}
    manager.restore_snapshot = lambda _sid, _snapshot: session
    restored = host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "snap-1"})
    assert restored["ok"] is True and restored["session"]["session_id"] == sid
    manager.restore_snapshot = lambda _sid, _snapshot: None
    assert host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "missing"})["code"] == MCPError.NOT_FOUND

    source_sid = "SOURCE99"
    manager.get_session = lambda value: session if value in (sid, source_sid) else None
    manager.merge_sessions = lambda _target, _source: session
    assert host._session_action_merge({"session_id": sid, "source_id": sid})["code"] == MCPError.INVALID_ARGS
    merged = host._session_action_merge({"target_id": sid, "source_id": source_sid})
    assert merged["ok"] is True and merged["session"]["session_id"] == sid
    manager.merge_sessions = lambda _target, _source: None
    assert host._session_action_merge({"session_id": sid, "source_id": source_sid})["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_action_merge({"session_id": sid})["code"] == MCPError.INVALID_ARGS


def test_session_macro_registry_and_workflow_branch_modes(tmp_path):
    host, _manager, session = _host(tmp_path)
    saved = []
    host._save_session_macros = lambda: saved.append(True)
    assert host._session_action_macro_set({})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_set({"name": "bad", "data": []})["code"] == MCPError.INVALID_ARGS

    configured = host._session_action_macro_set({"macro": " Inspect ", "data": {"_tool": "code", "action": "summary", "value": "$needle"}})
    assert configured["name"] == "Inspect" and saved == [True]
    assert host._session_action_macro_get({"macro": "inspect"})["data"]["action"] == "summary"
    assert host._session_action_macro_get({"name": "missing"})["code"] == MCPError.FILE_NOT_FOUND
    host._session_macros["malformed"] = "not-a-dict"
    assert host._session_action_macro_list({})["count"] == 1
    assert host._session_action_macro_delete({"name": "missing"})["code"] == MCPError.FILE_NOT_FOUND

    calls = []
    host._execute_tool = lambda tool, args: calls.append((tool, args)) or {"ok": True, "value": args.get("value", "done")}
    ran = host._session_action_macro_run({"name": "inspect", "needle": "found"})
    assert ran["macro"] == "inspect" and ran["value"] == "found"
    assert calls[-1] == ("code", {"_tool": "code", "action": "summary", "value": "found", "needle": "found"})
    host._session_macros["bad-run"] = {"name": "bad-run", "data": {}}
    assert host._session_action_macro_run({"name": "bad-run", "run_action": 7})["code"] == MCPError.INVALID_ARGS
    assert host._session_action_macro_run({"name": "bad-run", "run_action": "macro_list"})["code"] == MCPError.INVALID_ARGS
    host._execute_tool = lambda *_args: {"error": True, "code": "IDA_ERROR"}
    assert host._session_action_macro_run({"name": "bad-run", "run_action": "status"})["code"] == "IDA_ERROR"

    host._session_macros["flow"] = {
        "name": "flow",
        "data": {
            "calls": [
                {"tool": "$tool", "action": "$action", "if": "$run", "then": {"tool": "$tool", "action": "$action", "value": "$value"}, "else": {"action": "fallback"}},
                {"action": "", "if": "$run", "then": "not-a-step"},
                {"action": "status", "value": "$step0_value"},
            ]
        },
    }
    host._execute_tool = lambda tool, args: {"ok": True, "tool": tool, "value": args.get("value", "result")}
    flow = host._session_action_macro_run({"name": "flow", "tool": "session", "action": "status", "run": True, "value": "x"})
    assert flow["step_count"] == 3
    assert flow["steps"][0]["tool"] == "session"
    assert flow["steps"][1]["skipped"] is True
    assert flow["steps"][2]["result"]["value"] == "x"
    fallback = host._run_workflow_sequence("flow", [{"action": "status", "if": "$run", "else": {"action": "list"}}], {"run": False})
    assert fallback["steps"][0]["action"] == "list"

    host._session_macros["inspect"] = {"name": "Inspect", "data": {"action": "status"}}
    assert host._session_action_macro_delete({"name": "inspect"})["ok"] is True
    assert saved[-1] is True

    host._build_recent_workset = lambda sid, **kwargs: {"ok": True, "session_id": sid, **kwargs}
    recent = host._session_action_recent_workset({"session_id": session.session_id, "n": "3", "include_bookmarks": "false", "include_items": "true"})
    assert recent["n"] == 3 and recent["include_bookmarks"] is False and recent["include_items"] is True
