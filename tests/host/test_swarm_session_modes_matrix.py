"""Exercise session modes that are not part of the socket/IDA lifecycle tests."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.server.server_session import ServerSessionMixin


class _Session:
    def __init__(self, sid="SID12345"):
        self.session_id = sid
        self.binary_path = "/samples/demo.bin"
        self.idb_path = "/samples/demo.i64"
        self.created_at = "2026-09-01T00:00:00"

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
        }


class _Manager:
    def __init__(self, session):
        self.session = session
        self.calls = []

    def get_session(self, sid):
        return self.session if sid == self.session.session_id else None

    def session_exists(self, sid):
        return sid == self.session.session_id

    def get_stats(self):
        return {"sessions": 1, "active": 1}

    def validate_session(self, sid):
        return {"session_id": sid, "valid": True}

    def rate_skill(self, sid, **kwargs):
        return {"ok": True, "sid": sid, **kwargs}

    def list_skills(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "skills": [], **kwargs}

    def suggest_triage(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "triage": kwargs}

    def suggest_strategy(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "strategy": kwargs}

    def get_phase(self, sid):
        return {"ok": True, "sid": sid, "phase": "triage"}

    def dashboard(self, sid):
        return {"ok": True, "sid": sid, "dashboard": {}}

    def suggest_analogy(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "analogy": kwargs}

    def log_activity(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "activity": kwargs}

    def track_hypothesis(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "hypothesis": kwargs}

    def confirm_hypothesis(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "confirmed": kwargs}

    def refute_hypothesis(self, sid, **kwargs):
        return {"ok": True, "sid": sid, "refuted": kwargs}

    def snapshot_session(self, sid):
        return {"snapshot_id": "snap-1", "message": "saved"}

    def restore_snapshot(self, sid, snapshot_id):
        return self.session

    def merge_sessions(self, sid1, sid2):
        return self.session

    def bulk_delete(self, sids):
        return [{"session_id": sid, "deleted": True} for sid in sids]

    def bulk_tag(self, sids, tag):
        return [{"session_id": sid, "tag": tag} for sid in sids]

    def export_session(self, sid):
        return {"session_id": sid, "format": "json"}

    def import_session(self, data):
        return self.session


def _host():
    session = _Session()
    manager = _Manager(session)
    host = ServerSessionMixin.__new__(ServerSessionMixin)
    host.session_mgr = manager
    host.current_session = session
    host._require_owned_session_id = lambda _sid: None
    host._session_macros = {}
    host._save_session_macros = lambda: None
    host._normalize_macro_name = lambda value: str(value).strip()[:80] if value else None
    host._execute_tool = lambda tool, args: {"ok": True, "tool": tool, "action": args["action"]}
    host.call_tool = lambda *args, **kwargs: {"ok": True, "tool": args[0], "action": kwargs.get("action")}
    host._activity_log = [
        {"tool": "code", "action": "decompile", "addresses": ["0x1000"], "topic": "entry", "target": "main", "ts": "now"},
        {"tool": "data", "action": "strings", "addresses": [], "ts": "later"},
    ]
    host._drop_sid_from_groups = lambda _sid: None
    host._forget_analysis_state = lambda _sid: None
    host._cleanup_runtime = lambda _sid: None
    host._export_session_hypotheses_to_symbol_db = lambda _sid: 0
    return host


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_session_strategy_knowledge_and_bulk_modes():
    host = _host()
    sid = host.current_session.session_id
    assert _ok(host._session_action_stats({}))['stats']['sessions'] == 1
    narrative = _ok(host._session_action_narrative({"limit": 10}))
    assert narrative["turn_count"] == 2
    assert _ok(host._session_action_validate({"session_id": sid}))["validation"]["valid"] is True

    assert _ok(host._session_action_rate_skill({"session_id": sid, "skill_id": "cfg", "reward": "0.8"}))['reward'] == 0.8
    assert _ok(host._session_action_list_skills({"session_id": sid, "min_q": "0.2", "global_skills": "false"}))['global_skills'] is False
    assert _ok(host._session_action_suggest_triage({"session_id": sid, "context": 7, "limit": "3"}))['triage']['limit'] == 3
    assert _ok(host._session_action_suggest_strategy({"session_id": sid}))['strategy'] == {"context": None}
    assert _ok(host._session_action_get_phase({"session_id": sid}))['phase'] == "triage"
    assert _ok(host._session_action_dashboard({"session_id": sid}))['dashboard'] == {}
    analogy = _ok(host._session_action_suggest_analogy({"session_id": sid, "library_idbs": ["a.i64"], "limit": "2"}))
    assert analogy['analogy']['limit'] == 2
    applied = _ok(host._session_action_apply_analogy({"session_id": sid, "mappings": [{"addr": "0x1000", "name": "entry", "comment": "root"}, None, {"name": "missing"}]}))
    assert applied["applied"] == 3
    assert _ok(host._session_action_log_activity({"session_id": sid, "tool": "code", "activity_action": "decompile", "result": "ok"}))['activity']['action'] == "decompile"
    tracked = _ok(host._session_action_track_hypothesis({"session_id": sid, "statement": "is loader", "evidence_for": "a,b", "evidence_against": ["c"], "confidence": "0.7"}))
    assert tracked['hypothesis']['evidence_for'] == ["a", "b"]
    assert _ok(host._session_action_confirm_hypothesis({"session_id": sid, "id": "h1", "evidence": "x,y"}))['confirmed']['evidence'] == ["x", "y"]
    assert _ok(host._session_action_refute_hypothesis({"session_id": sid, "hypothesis_id": "h1", "reason": "no", "evidence": ["z"]}))['refuted']['reason'] == "no"
    assert _ok(host._session_action_bulk_tag({"session_ids": [sid], "tag": "review"}))['results'][0]['tag'] == "review"
    assert _ok(host._session_action_bulk_delete({"session_ids": [sid]}))['results'][0]['deleted'] is True


def test_session_snapshot_merge_import_and_macro_modes():
    host = _host()
    sid = host.current_session.session_id
    assert _ok(host._session_action_snapshot({"session_id": sid}))['snapshot_id'] == "snap-1"
    assert _ok(host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "snap-1"}))['session']['session_id'] == sid
    assert _ok(host._session_action_merge({"session_id": sid, "source_id": "SID67890"}))['session']['session_id'] == sid
    assert _ok(host._session_action_export_session({"session_id": sid}))['exported']['session_id'] == sid
    assert _ok(host._session_action_import_session({"data": {"binary_path": "demo.bin"}}))['session']['session_id'] == sid

    macro = _ok(host._session_action_macro_set({"name": "Open", "data": {"_tool": "session", "action": "status", "label": "$label"}}))
    assert macro['name'] == "Open"
    assert _ok(host._session_action_macro_get({"name": "open"}))['data']['label'] == "$label"
    assert _ok(host._session_action_macro_run({"name": "open", "$label": "demo"}))['macro'] == "open"
    host._session_action_macro_set({"name": "Flow", "data": {"calls": [
        {"tool": "session", "action": "status", "if": "$run", "then": {"action": "get"}, "else": {"action": "list"}},
        None,
        {"tool": "session", "action": ""},
    ]}})
    workflow = _ok(host._session_action_macro_run({"name": "Flow", "run": False}))
    assert workflow['step_count'] == 3
    assert _ok(host._session_action_macro_list({}))['count'] == 2
    assert _ok(host._session_action_macro_delete({"name": "open"}))['name'] == "open"
    assert host._session_action_macro_get({"name": "open"})['error'] is True
