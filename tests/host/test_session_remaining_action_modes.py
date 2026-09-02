"""Cover the less frequently used session actions through one shared host."""

from __future__ import annotations

from tests.host.test_session_action_modes_full import _host


def test_session_metadata_and_knowledge_action_wrappers(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    calls = []

    def record(name, result=None, **kwargs):
        calls.append((name, kwargs))
        return result if result is not None else {"ok": True, "action": name, **kwargs}

    manager._load_orphaned_idbs = lambda: None
    manager.discover_sessions = lambda **_kwargs: [session]
    manager.search_notes = lambda _query: [session]
    assert host._session_action_discover({"query": "sample"})["count"] == 1
    host._client_owns_session = lambda _sid: True
    host._session_is_busy = lambda _sid: False
    assert host._session_action_search_notes({"query": "note"})["count"] == 1

    manager.export_session = lambda sid: record("export", {"sid": sid})
    host._export_session_hypotheses_to_symbol_db = lambda _sid: 2
    exported = host._session_action_export_session({"session_id": session.session_id})
    assert exported["exported_hypotheses"] == 2

    manager.import_session = lambda data: record("import", session)
    imported = host._session_action_import_session({"data": {"binary_path": session.binary_path}})
    assert imported["session"]["session_id"] == session.session_id
    manager.validate_session = lambda sid: record("validate", {"session_id": sid})
    assert host._session_action_validate({"session_id": session.session_id})["validation"]

    manager.snapshot_session = lambda sid: {"snapshot_id": "snap-1", "message": "saved"}
    snap = host._session_action_snapshot({"session_id": session.session_id})
    assert snap["snapshot_id"] == "snap-1"
    manager.restore_snapshot = lambda _sid, _snapshot: session
    restored = host._session_action_restore_snapshot({"session_id": session.session_id, "snapshot_id": "snap-1"})
    assert restored["session"]["session_id"] == session.session_id
    manager.merge_sessions = lambda _target, _source: session
    manager.get_session = lambda sid: session if sid in {session.session_id, "SOURCE01"} else None
    merged = host._session_action_merge({"session_id": session.session_id, "source_id": "SOURCE01"})
    assert merged["session"]["session_id"] == session.session_id

    manager.rate_skill = lambda sid, **kwargs: record("rate", {"sid": sid, **kwargs})
    manager.list_skills = lambda sid, **kwargs: record("skills", {"sid": sid, **kwargs})
    manager.suggest_triage = lambda sid, **kwargs: record("triage", {"sid": sid, **kwargs})
    manager.suggest_strategy = lambda sid, **kwargs: record("strategy", {"sid": sid, **kwargs})
    manager.get_phase = lambda sid: record("phase", {"sid": sid})
    manager.dashboard = lambda sid: record("dashboard", {"sid": sid})
    assert host._session_action_rate_skill({"session_id": session.session_id, "skill_id": "s", "reward": "0.8"})["sid"] == session.session_id
    assert host._session_action_list_skills({"session_id": session.session_id, "min_q": "0.2", "global_skills": False})["sid"] == session.session_id
    assert host._session_action_suggest_triage({"session_id": session.session_id, "context": 7, "limit": "3"})["sid"] == session.session_id
    assert host._session_action_suggest_strategy({"session_id": session.session_id})["sid"] == session.session_id
    assert host._session_action_get_phase({"session_id": session.session_id})["sid"] == session.session_id
    assert host._session_action_dashboard({"session_id": session.session_id})["sid"] == session.session_id


def test_session_activity_hypothesis_macro_and_bulk_modes(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.log_activity = lambda value, **kwargs: {"ok": True, "sid": value, **kwargs}
    manager.track_hypothesis = lambda value, **kwargs: {"ok": True, "sid": value, **kwargs}
    manager.confirm_hypothesis = lambda value, **kwargs: {"ok": True, "sid": value, **kwargs}
    manager.refute_hypothesis = lambda value, **kwargs: {"ok": True, "sid": value, **kwargs}
    assert host._session_action_log_activity({"session_id": sid, "tool": "code", "activity": "decompile"})["action"] == "decompile"
    tracked = host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "evidence_for": "a,b", "confidence": "0.7"})
    assert tracked["evidence_for"] == ["a", "b"]
    assert host._session_action_confirm_hypothesis({"session_id": sid, "id": "h1", "evidence": "ok"})["sid"] == sid
    assert host._session_action_refute_hypothesis({"session_id": sid, "id": "h1", "reason": "no"})["sid"] == sid

    saved = []
    host._save_session_macros = lambda: saved.append(True)
    host._session_action_macro_set({"name": "Demo", "data": {"action": "status"}})
    assert host._session_action_macro_get({"name": "demo"})["data"]["action"] == "status"
    assert host._session_action_macro_list({})["count"] == 1
    host._execute_tool = lambda tool, args: {"ok": True, "tool": tool, **args}
    ran = host._session_action_macro_run({"name": "demo", "value": "x"})
    assert ran["macro"] == "demo"
    assert host._session_action_macro_delete({"name": "demo"})["ok"] is True
    assert saved

    host._activity_log = [{"tool": "code", "action": "decompile", "addresses": ["0x10"], "topic": "x"}]
    narrative = host._session_action_narrative({"limit": "1"})
    assert narrative["turn_count"] == 1 and narrative["turns"][0]["addresses"] == ["0x10"]

    manager.bulk_tag = lambda sids, tag: [{"sid": sid, "tag": tag} for sid in sids]
    assert host._session_action_bulk_tag({"session_ids": [sid], "tag": "x"})["results"]
    manager.bulk_delete = lambda sids: [{"sid": value, "deleted": True} for value in sids]
    host._session_action_bulk_delete({"session_ids": [sid]})
    assert host.current_session is None


def test_session_analogy_and_restore_validation_errors(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.suggest_analogy = lambda value, **kwargs: {"ok": True, "sid": value, **kwargs}
    host.call_tool = lambda tool, ip, **kwargs: {"ok": True, "tool": tool, "ip": ip, **kwargs}
    analogy = host._session_action_suggest_analogy({"session_id": sid, "library_idbs": [1], "threshold_cosine": "0.8", "limit": "2"})
    assert analogy["library_idbs"] == ["1"]
    applied = host._session_action_apply_analogy(
        {"session_id": sid, "mappings": [{"addr": "0x10", "name": "renamed", "comment": "note"}, {}, "bad"]}
    )
    assert applied["applied"] == 3 and applied["results"][1]["ok"] is False

    assert host._session_action_macro_get({})["error"] is True
    assert host._session_action_macro_set({"name": "bad", "data": []})["error"] is True
    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "s", "reward": "bad"})["error"] is True
    assert host._session_action_suggest_analogy({"session_id": sid, "library_idbs": "bad"})["error"] is True
    assert host._session_action_suggest_analogy({"session_id": sid, "threshold_cosine": "bad"})["error"] is True
    assert host._session_action_restore_snapshot({"session_id": sid})["error"] is True
