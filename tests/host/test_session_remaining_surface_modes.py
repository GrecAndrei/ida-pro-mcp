"""Cover the less frequently used session actions through stable envelopes."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from tests.host.test_session_action_modes_full import _error, _host


def test_session_bulk_snapshot_restore_merge_and_skill_boundaries(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    deleted = host._session_action_bulk_delete({"session_ids": [sid]})
    assert deleted["ok"] is True
    assert deleted["results"][0]["deleted"] is True
    assert host.current_session is None

    host, manager, session = _host(tmp_path / "tag")
    sid = session.session_id
    def bulk_tag(sids, tag):
        return dict.fromkeys(sids, tag)

    manager.bulk_tag = bulk_tag
    tagged = host._session_action_bulk_tag({"session_ids": [sid], "tag": "  review  "})
    assert tagged["results"] == {sid: "review"}
    assert _error(host._session_action_bulk_tag({"session_ids": [sid], "tag": "   "}), MCPError.INVALID_ARGS)

    manager.snapshot_session = lambda value: {"snapshot_id": "snap-1", "message": value}
    snap = host._session_action_snapshot({"session_id": sid})
    assert snap["snapshot_id"] == "snap-1"
    manager.snapshot_session = lambda _value: None
    assert _error(host._session_action_snapshot({"session_id": sid}), MCPError.SESSION_NOT_FOUND)

    manager.restore_snapshot = lambda *_args: session
    restored = host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "snap-1"})
    assert restored["session"]["session_id"] == sid
    assert _error(host._session_action_restore_snapshot({"session_id": sid}), MCPError.INVALID_ARGS)
    manager.session_exists = lambda _value: False
    assert _error(
        host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "snap-1"}),
        MCPError.SESSION_NOT_FOUND,
    )

    host, manager, session = _host(tmp_path / "merge")
    sid = session.session_id
    manager.get_session = lambda value: session if value in {sid, "OTHER123"} else None
    manager.merge_sessions = lambda *_args: session
    assert _error(host._session_action_merge({"session_id": sid, "source_id": sid}), MCPError.INVALID_ARGS)
    assert host._session_action_merge({"target_id": sid, "source_id": "OTHER123"})["session"]["session_id"] == sid
    manager.merge_sessions = lambda *_args: None
    assert _error(
        host._session_action_merge({"target_id": sid, "source_id": "OTHER123"}),
        MCPError.SESSION_NOT_FOUND,
    )


def test_session_skill_analogy_and_hypothesis_validation_paths(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.rate_skill = lambda *_args, **kwargs: {"reward": kwargs["reward"]}
    manager.list_skills = lambda *_args, **kwargs: {"min_q": kwargs["min_q"], "global": kwargs["global_skills"]}
    manager.suggest_triage = lambda *_args, **kwargs: {"limit": kwargs["limit"], "context": kwargs["context"]}
    manager.suggest_strategy = lambda *_args, **kwargs: {"context": kwargs["context"]}
    manager.get_phase = lambda *_args: {"phase": "prove"}
    manager.dashboard = lambda *_args: {"dashboard": True}
    manager.suggest_analogy = lambda *_args, **kwargs: kwargs
    manager.log_activity = lambda *_args, **kwargs: kwargs
    manager.track_hypothesis = lambda *_args, **kwargs: kwargs
    manager.confirm_hypothesis = lambda *_args, **kwargs: kwargs
    manager.refute_hypothesis = lambda *_args, **kwargs: kwargs

    assert _error(host._session_action_rate_skill({"session_id": sid}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_rate_skill({"session_id": sid, "skill_id": "s", "reward": "bad"}), MCPError.INVALID_ARGS)
    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "s", "reward": "0.4"})["reward"] == 0.4
    assert _error(host._session_action_list_skills({"session_id": sid, "min_q": "bad"}), MCPError.INVALID_ARGS)
    assert host._session_action_list_skills({"session_id": sid, "min_q": "0.2", "global_skills": "false"}) == {"min_q": 0.2, "global": False}
    assert _error(host._session_action_suggest_triage({"session_id": sid, "limit": "bad"}), MCPError.INVALID_ARGS)
    assert host._session_action_suggest_triage({"session_id": sid, "context": 4}) == {"limit": 5, "context": "4"}
    assert host._session_action_suggest_strategy({"session_id": sid, "context": 4}) == {"context": "4"}
    assert host._session_action_get_phase({"session_id": sid})["phase"] == "prove"
    assert host._session_action_dashboard({"session_id": sid})["dashboard"] is True

    assert _error(host._session_action_suggest_analogy({"session_id": sid, "library_idbs": "bad"}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_suggest_analogy({"session_id": sid, "threshold_cosine": "bad"}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_suggest_analogy({"session_id": sid, "threshold_structural": "bad"}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_suggest_analogy({"session_id": sid, "limit": "bad"}), MCPError.INVALID_ARGS)
    analogy = host._session_action_suggest_analogy({"session_id": sid, "library_idbs": [1], "limit": "2"})
    assert analogy["library_idbs"] == ["1"] and analogy["limit"] == 2

    assert _error(host._session_action_track_hypothesis({"session_id": sid}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "confidence": "bad"}), MCPError.INVALID_ARGS)
    tracked = host._session_action_track_hypothesis({"session_id": sid, "statement": "x", "evidence_for": "a,b"})
    assert tracked["evidence_for"] == ["a", "b"]
    assert _error(host._session_action_confirm_hypothesis({"session_id": sid}), MCPError.INVALID_ARGS)
    assert host._session_action_confirm_hypothesis({"session_id": sid, "id": "h", "evidence": "yes"})["evidence"] == ["yes"]
    assert _error(host._session_action_refute_hypothesis({"session_id": sid, "id": "h"}), MCPError.INVALID_ARGS)
    assert host._session_action_refute_hypothesis({"session_id": sid, "id": "h", "reason": "no"})["reason"] == "no"


def test_session_apply_analogy_activity_and_recent_workset_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    host.call_tool = lambda tool, idb, **kwargs: {"tool": tool, "idb": idb, **kwargs}

    assert _error(host._session_action_apply_analogy({"session_id": sid}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_apply_analogy({"session_id": sid, "mappings": "bad"}), MCPError.INVALID_ARGS)
    applied = host._session_action_apply_analogy({
        "session_id": sid,
        "mappings": [None, {}, {"addr": "0x1000", "name": "entry", "comment": "start"}],
    })
    assert applied["applied"] == 3
    assert applied["results"][0]["ok"] is False
    assert applied["results"][2]["rename"]["action"] == "rename"

    assert _error(host._session_action_log_activity({"session_id": sid}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_log_activity({"session_id": sid, "tool": "code"}), MCPError.INVALID_ARGS)
    manager.log_activity = lambda *_args, **kwargs: kwargs
    assert host._session_action_log_activity({"session_id": sid, "tool": "code", "action_name": "read"})["action"] == "read"
    assert host._session_action_log_activity({"session_id": sid, "tool": "code", "log_action": "write"})["action"] == "write"

    host._build_recent_workset = lambda value, **kwargs: {"sid": value, **kwargs}
    assert _error(host._session_action_recent_workset({"session_id": "bad/id"}), MCPError.INVALID_ARGS)
    recent = host._session_action_recent_workset({"session_id": sid, "n": "2", "include_bookmarks": "false", "include_items": "true"})
    assert recent == {"sid": sid, "n": 2, "include_bookmarks": False, "include_items": True}


def test_session_macros_and_workflow_condition_modes(tmp_path):
    host, _manager, _session = _host(tmp_path)
    saved = []
    host._save_session_macros = lambda: saved.append(True)
    host._execute_tool = lambda tool, args: {"tool": tool, **args, "answer": "ok"}

    assert _error(host._session_action_macro_set({}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_macro_set({"name": "bad", "data": []}), MCPError.INVALID_ARGS)
    created = host._session_action_macro_set({"name": "Inspect", "query": "$needle"})
    assert created["name"] == "Inspect"
    assert host._session_action_macro_get({"name": "inspect"})["data"]["query"] == "$needle"
    assert host._session_action_macro_list({})["count"] == 1
    run = host._session_action_macro_run({"name": "Inspect", "needle": "packet"})
    assert run["macro"] == "Inspect" and run["query"] == "packet"
    assert _error(host._session_action_macro_run({"name": "inspect", "run_action": "macro_get"}), MCPError.INVALID_ARGS)
    assert _error(host._session_action_macro_delete({"name": "missing"}), MCPError.FILE_NOT_FOUND)
    assert host._session_action_macro_delete({"name": "inspect"})["ok"] is True
    assert len(saved) == 2

    host._session_macros["flow"] = {"name": "flow", "data": {"calls": [
        None,
        {"action": "status", "if": "$run", "then": {"action": "get"}},
        {"action": "status", "if": "$skip", "else": {"action": "list"}},
        {"action": "status", "if": "$missing"},
        {"action": "status", "if": "$run", "then": "bad"},
        {"tool": "session"},
    ]}}
    workflow = host._session_action_macro_run({"name": "flow", "run": True})
    assert workflow["ok"] is True
    assert workflow["step_count"] == 6
    assert workflow["steps"][1]["action"] == "get"
    assert workflow["steps"][2]["action"] == "list"
    assert workflow["steps"][3]["skipped"] is True
    assert workflow["steps"][4]["skipped"] is True
    assert workflow["steps"][5]["result"]["code"] == MCPError.INVALID_ARGS
