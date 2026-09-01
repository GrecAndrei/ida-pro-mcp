"""Offline behavioral coverage for session skills and bootstrap state."""

from __future__ import annotations

import math

from ida_pro_mcp.host.server.session import SessionManager
from ida_pro_mcp.host.server.session_skills import SessionSkillsMixin


def test_skills_state_normalization_is_safe_for_malformed_persisted_data():
    normalized = SessionSkillsMixin._normalize_skills_state(
        {
            "skills": {
                "good": {
                    "q_value": "nan",
                    "description": 42,
                    "tags": "network",
                    "success_count": "bad",
                    "failure_count": -2,
                },
                "bad": "not-an-object",
            },
            "q_table": {"good": float("inf"), "other": "0.75"},
            "activity_log": [{"tool": "code"}, "bad"],
            "hypotheses": [{"id": "h1"}, None],
            "bootstrap": {
                "policies": {"p1": {"name": "one"}, "bad": "skip"},
                "history": [{"rounds": 1}, "bad"],
                "tournament_runs": "bad",
                "decay_lambda": "nan",
            },
        }
    )
    assert set(normalized["skills"]) == {"good"}
    assert normalized["skills"]["good"]["q_value"] == 0.5
    assert normalized["skills"]["good"]["description"] == "42"
    assert normalized["skills"]["good"]["tags"] == ["network"]
    assert normalized["skills"]["good"]["success_count"] == 0
    assert normalized["skills"]["good"]["failure_count"] == 0
    assert normalized["q_table"] == {"good": 0.5, "other": 0.75}
    assert len(normalized["activity_log"]) == 1
    assert len(normalized["hypotheses"]) == 1
    assert set(normalized["bootstrap"]["policies"]) == {"p1"}
    assert normalized["bootstrap"]["tournament_runs"] == 0
    assert math.isclose(normalized["bootstrap"]["decay_lambda"], 0.03)


def test_skill_rating_listing_and_strategy_suggestion_follow_q_values(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    sid = session.session_id
    data = manager._load_skills(sid)
    data["skills"] = {
        "decode": {"q_value": 0.6, "description": "decode network packets", "tags": ["network"]},
        "noise": {"q_value": 0.2, "description": "inspect entropy", "tags": ["static"]},
    }
    data["q_table"]["decode"] = 0.6
    manager._save_skills(sid, data)
    rated = manager.rate_skill(sid, "decode", 1.0)
    assert rated["ok"] is True
    assert rated["q_value"] > 0.6
    assert manager.rate_skill(sid, "missing", 1.0)["error"] is True
    listed = manager.list_skills(sid, min_q=0.5, global_skills=False)
    assert listed["local_count"] == 1
    assert list(listed["local_skills"]) == ["decode"]
    suggestions = manager.suggest_strategy(sid)
    assert suggestions["ok"] is True
    assert suggestions["suggestions"][0]["skill_id"] == "decode"


def test_activity_log_dead_end_detection_and_dashboard_counts(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    sid = session.session_id
    for _ in range(5):
        manager.log_activity(sid, "code", "decompile", "fixture_leaf")
    for _ in range(5):
        manager.log_activity(sid, "search", "find", "fixture_leaf")
    activity = manager.get_activity_log(sid, limit=4)
    assert activity["ok"] is True and activity["total"] == 10
    dead_end = manager._detect_dead_end(manager._load_skills(sid)["activity_log"])
    assert dead_end["type"] == "repeated_decompile"
    dashboard = manager.dashboard(sid)
    assert dashboard["activity"]["functions_decompiled"] == 5
    assert dashboard["activity"]["searches_performed"] == 5
    assert manager.get_phase(sid)["phase"] == "triage"
    assert manager.get_activity_log("missing")["error"] is True


def test_bootstrap_init_tournament_blend_and_status_are_persisted(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    sid = session.session_id
    initialized = manager.bootstrap_init(sid, decay_lambda=0.05, min_bootstrap_weight=0.2)
    assert initialized["ok"] is True and initialized["policies"] == 12
    again = manager.bootstrap_init(sid)
    assert again["initialized"] is False
    tournament = manager.bootstrap_run_tournament(sid, rounds=3, seed=7)
    assert tournament["ok"] is True and tournament["rounds"] == 3
    status = manager.bootstrap_status(sid)
    assert status["initialized"] is True
    assert status["total_rounds"] == 3
    blend = manager.bootstrap_compute_blend(sid, session_samples=100)
    assert blend["weights"]["bootstrap"] >= 0.2
    assert blend["weights"]["bootstrap"] + blend["weights"]["session"] == 1.0
    plan = manager.bootstrap_plan_status(sid)
    assert plan["ok"] is True and plan["overall"]["items"] > 0


def test_bootstrap_readiness_history_trend_and_dry_run_mitigation(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/target.bin")
    sid = session.session_id
    first = manager.bootstrap_record_readiness(sid, tag="cold")
    second = manager.bootstrap_record_readiness(sid, tag="second")
    assert first["ok"] is True and second["history_count"] == 2
    history = manager.bootstrap_readiness_history(sid, limit=1)
    assert history["count"] == 1 and history["total"] == 2
    trend = manager.bootstrap_readiness_trend(sid, window=2)
    assert trend["enough_data"] is True and trend["status"] == "stable"
    guard = manager.bootstrap_readiness_regression_guard(sid, window=2, auto_snapshot=False)
    assert guard["ok"] is True and guard["triggered"] is False
    plan = manager.bootstrap_mitigation_plan(sid, window=2)
    assert plan["ok"] is True and plan["enough_data"] is False
    dry_run = manager.bootstrap_apply_mitigation(sid, window=2, dry_run=True)
    assert dry_run["ok"] is True and dry_run["dry_run"] is True
    assert manager.bootstrap_readiness_history("missing")["error"] is True
