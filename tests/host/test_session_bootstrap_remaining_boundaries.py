"""Offline coverage for the remaining bootstrap lifecycle branches."""

from __future__ import annotations

from datetime import datetime

from ida_pro_mcp.host.errors import MCPError, make_error
from tests.host.test_swarm_f08_skills import _make_manager, _write_skills


def _error():
    return make_error(MCPError.IDA_ERROR, "forced test error")


def test_bootstrap_actions_return_session_errors_before_loading_state(tmp_path):
    manager, _session = _make_manager(tmp_path)
    calls = [
        lambda: manager.bootstrap_init("MISSING"),
        lambda: manager.bootstrap_run_tournament("MISSING", rounds=1),
        lambda: manager.bootstrap_compute_blend("MISSING", 1),
        lambda: manager.bootstrap_status("MISSING"),
        lambda: manager.bootstrap_mitigation_plan("MISSING"),
        lambda: manager.bootstrap_apply_mitigation("MISSING"),
        lambda: manager.bootstrap_mitigation_history("MISSING"),
        lambda: manager.bootstrap_mitigation_effectiveness("MISSING"),
        lambda: manager.bootstrap_policy_reweight("MISSING"),
        lambda: manager.bootstrap_set_autopilot_policy("MISSING"),
        lambda: manager.bootstrap_get_autopilot_policy("MISSING"),
        lambda: manager.bootstrap_rollback_last_reweight("MISSING"),
        lambda: manager.bootstrap_policy_reweight_history("MISSING"),
        lambda: manager.bootstrap_autopilot("MISSING"),
        lambda: manager.bootstrap_simulate_batch("MISSING", n=1),
        lambda: manager.bootstrap_prune_data("MISSING"),
        lambda: manager.bootstrap_export_metrics("MISSING"),
        lambda: manager.bootstrap_calibration_report("MISSING"),
        lambda: manager.bootstrap_ingest_outcome("MISSING", 0.5, 1),
        lambda: manager.bootstrap_open_dispute("MISSING", "c", 0.5, "r"),
        lambda: manager.bootstrap_list_disputes("MISSING"),
        lambda: manager.bootstrap_resolve_dispute("MISSING", "d", 1),
    ]
    assert all(result()["error"] for result in calls)


def test_tournament_initializes_cold_session_and_handles_empty_policies(tmp_path):
    manager, _session = _make_manager(tmp_path)
    result = manager.bootstrap_run_tournament("SID_TEST", rounds=1, seed=3)
    assert result["ok"] is True and result["rounds"] == 1

    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["policies"] = {}
    manager._save_skills("SID_TEST", data)
    empty = manager.bootstrap_run_tournament("SID_TEST", rounds=1)
    assert empty["error"] is True and empty["code"] == MCPError.INVALID_ARGS

    status = manager.bootstrap_status("SID_TEST")
    assert status["policy_count"] == 0
    blend = manager.bootstrap_compute_blend("SID_TEST", session_samples=-10)
    assert blend["session_samples"] == 0


def test_mitigation_plan_covers_evaluation_errors_and_severity_matrix(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: _error())
    assert manager.bootstrap_mitigation_plan("SID_TEST")["error"] is True

    monkeypatch.setattr(
        manager,
        "bootstrap_evaluate_alerts",
        lambda *_a, **_k: {"ok": True, "enough_data": False},
    )
    assert manager.bootstrap_mitigation_plan("SID_TEST")["actions"] == []

    medium = {
        "ok": True,
        "enough_data": True,
        "severity": "medium",
        "alerts": [{"type": "ece_regression"}, {"type": "confidence_drop"}],
    }
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: medium)
    medium_plan = manager.bootstrap_mitigation_plan("SID_TEST")
    assert [a["action"] for a in medium_plan["actions"]] == [
        "bootstrap_run_tournament",
        "bootstrap_simulate_batch",
    ]

    high = {**medium, "severity": "high"}
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: high)
    high_plan = manager.bootstrap_mitigation_plan("SID_TEST", window=2)
    assert len(high_plan["actions"]) == 4

    steady = {"ok": True, "enough_data": True, "severity": "low", "alerts": []}
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: steady)
    assert manager.bootstrap_mitigation_plan("SID_TEST")["actions"][0]["action"] == "bootstrap_snapshot"


def test_apply_mitigation_executes_every_persisted_action_and_handles_final_error(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    actions = [
        {"action": "bootstrap_run_tournament", "params": {"rounds": 1, "seed": 2}},
        {"action": "bootstrap_simulate_batch", "params": {"n": 1, "positive_rate": 0.5}},
        {"action": "bootstrap_snapshot", "params": {"name": "x"}},
        {"action": "bootstrap_update_baseline", "params": {"window": 2, "percentile": 90}},
        {"action": "not-a-real-action", "params": {}},
    ]
    monkeypatch.setattr(
        manager,
        "bootstrap_mitigation_plan",
        lambda *_a, **_k: {"ok": True, "severity": "high", "alerts": [], "actions": actions},
    )
    monkeypatch.setattr(manager, "bootstrap_run_tournament", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(manager, "bootstrap_simulate_batch", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(manager, "bootstrap_snapshot", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(manager, "bootstrap_update_baseline", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: {"ok": True, "severity": "none", "alerts": []})

    result = manager.bootstrap_apply_mitigation("SID_TEST", max_actions=10)
    assert result["ok"] is True
    assert len(result["executed"]) == 5
    assert result["executed"][-1]["result"]["error"] is True

    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: _error())
    assert manager.bootstrap_apply_mitigation("SID_TEST")["error"] is True


def test_effectiveness_counts_improved_worsened_and_same_rows(tmp_path):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["mitigation_history"] = [
        {"plan_severity": "high", "post_severity": "none", "pre_alerts": 3, "post_alerts": 0, "executed_total": 2, "executed_ok": 2},
        {"plan_severity": "none", "post_severity": "high", "pre_alerts": 0, "post_alerts": 2, "executed_total": 2, "executed_ok": 0},
        {"plan_severity": "medium", "post_severity": "medium", "pre_alerts": 1, "post_alerts": 1, "executed_total": 2, "executed_ok": 1},
    ]
    manager._save_skills("SID_TEST", data)
    result = manager.bootstrap_mitigation_effectiveness("SID_TEST")
    assert result["counts"] == {"improved": 1, "same": 1, "worsened": 1}


def test_policy_reweight_tiers_bad_weights_and_rollback_outcomes(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["policies"] = {"p": {"weights": [0.1, 0.2, 0.3]}}
    manager._save_skills("SID_TEST", data)

    empty = manager.bootstrap_policy_reweight("SID_TEST")
    assert empty["enough_data"] is False

    monkeypatch.setattr(
        manager,
        "bootstrap_mitigation_effectiveness",
        lambda *_a, **_k: {"ok": True, "enough_data": True, "effectiveness_score": 0.9, "tier": "strong"},
    )
    strong = manager.bootstrap_policy_reweight("SID_TEST", dry_run=True)
    assert strong["tier"] == "strong" and len(strong["updates"]) == 1

    monkeypatch.setattr(
        manager,
        "bootstrap_mitigation_effectiveness",
        lambda *_a, **_k: {"ok": True, "enough_data": True, "effectiveness_score": 0.6, "tier": "moderate"},
    )
    moderate = manager.bootstrap_policy_reweight("SID_TEST")
    assert moderate["tier"] == "moderate"

    assert manager.bootstrap_rollback_last_reweight("SID_TEST")["rolled_back"] is True
    history = manager.bootstrap_policy_reweight_history("SID_TEST", limit=1)
    assert history["count"] == 1

    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["policy_reweight_history"] = [{"prior_weights": {}}]
    manager._save_skills("SID_TEST", data)
    assert manager.bootstrap_rollback_last_reweight("SID_TEST")["rolled_back"] is False
    data["bootstrap"]["policy_reweight_history"] = [{"prior_weights": {"missing": [1, 0, 0, 0]}}]
    manager._save_skills("SID_TEST", data)
    assert manager.bootstrap_rollback_last_reweight("SID_TEST")["rolled_back"] is False


def test_autopilot_cooldown_budget_errors_and_regression_rollback(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    now = datetime.now().isoformat()
    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["autopilot_policy"] = {"daily_budget": 1, "cooldown_seconds": 300, "max_live_actions": 2, "rollback_on_regression": True}
    data["bootstrap"]["autopilot_runs"] = [{"day": now[:10], "timestamp": now}]
    manager._save_skills("SID_TEST", data)
    blocked = manager.bootstrap_autopilot("SID_TEST")
    assert blocked["blocked"] is True and blocked["reason"] == "daily_budget_exceeded"

    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["autopilot_policy"]["daily_budget"] = 10
    data["bootstrap"]["autopilot_runs"] = [{"day": "yesterday", "timestamp": "bad"}]
    manager._save_skills("SID_TEST", data)
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: {"ok": True, "severity": "none", "alerts": []})
    monkeypatch.setattr(manager, "bootstrap_mitigation_plan", lambda *_a, **_k: {"ok": True, "severity": "none", "actions": []})
    monkeypatch.setattr(manager, "bootstrap_apply_mitigation", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(manager, "bootstrap_policy_reweight", lambda *_a, **_k: {"ok": True})
    assert manager.bootstrap_autopilot("SID_TEST", dry_run=True)["ok"] is True

    monkeypatch.setattr(manager, "bootstrap_rollback_last_reweight", lambda *_a, **_k: {"ok": True, "rolled_back": True})
    evaluations = iter([
        {"ok": True, "severity": "none", "alerts": []},
        {"ok": True, "severity": "high", "alerts": [{"type": "x"}]},
    ])
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: next(evaluations))
    result = manager.bootstrap_autopilot("SID_TEST")
    assert result["ok"] is True and result["rollback"]["rolled_back"] is True


def test_autopilot_propagates_each_control_loop_error(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    success = {"ok": True, "severity": "none", "alerts": []}
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: _error())
    assert manager.bootstrap_autopilot("SID_TEST")["error"] is True
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: success)
    monkeypatch.setattr(manager, "bootstrap_mitigation_plan", lambda *_a, **_k: _error())
    assert manager.bootstrap_autopilot("SID_TEST")["error"] is True
    monkeypatch.setattr(manager, "bootstrap_mitigation_plan", lambda *_a, **_k: success | {"actions": []})
    monkeypatch.setattr(manager, "bootstrap_apply_mitigation", lambda *_a, **_k: _error())
    assert manager.bootstrap_autopilot("SID_TEST")["error"] is True
    monkeypatch.setattr(manager, "bootstrap_apply_mitigation", lambda *_a, **_k: success)
    monkeypatch.setattr(manager, "bootstrap_policy_reweight", lambda *_a, **_k: _error())
    assert manager.bootstrap_autopilot("SID_TEST")["error"] is True
    monkeypatch.setattr(manager, "bootstrap_policy_reweight", lambda *_a, **_k: success)
    evaluations = iter([success, _error()])
    monkeypatch.setattr(manager, "bootstrap_evaluate_alerts", lambda *_a, **_k: next(evaluations))
    assert manager.bootstrap_autopilot("SID_TEST")["error"] is True


def test_batch_export_calibration_and_outcome_error_paths(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    manager.bootstrap_init("SID_TEST")
    monkeypatch.setattr(manager, "_bootstrap_apply_outcome_in_memory", lambda *_a, **_k: _error())
    assert manager.bootstrap_simulate_batch("SID_TEST", n=1)["error"] is True
    assert manager.bootstrap_ingest_outcome("SID_TEST", 0.5, 1)["error"] is True

    data = manager._load_skills("SID_TEST")
    data["bootstrap"]["metric_snapshots"] = [{"timestamp": None}, {"timestamp": "not-a-date"}, {"timestamp": "2020-01-01T00:00:00"}]
    data["bootstrap"]["disputes"] = [{"opened_at": "not-a-date", "status": "open"}]
    data["bootstrap"]["outcomes"] = [{"timestamp": "not-a-date"}]
    policy = next(iter(data["bootstrap"]["policies"].values()))
    policy["calibration_bins"]["0"] = {"n": 2, "sum_pred": 0.4, "sum_obs": 1.0}
    manager._save_skills("SID_TEST", data)
    exported = manager.bootstrap_export_metrics("SID_TEST", since="2021-01-01T00:00:00")
    assert exported["ok"] is True and exported["counts"]["snapshots"] == 0
    report = manager.bootstrap_calibration_report("SID_TEST", min_bin_n=1)
    assert report["used_bins"] == 1


def test_in_memory_outcomes_and_disputes_cover_initialization_and_resolution_edges(tmp_path, monkeypatch):
    manager, _session = _make_manager(tmp_path)
    data = {"skills": {"s": {"q_value": 0.5, "success_count": 0, "failure_count": 0}}, "q_table": {}}
    monkeypatch.setattr(manager, "bootstrap_init", lambda *_a, **_k: _error())
    assert manager._bootstrap_apply_outcome_in_memory("SID_TEST", data, 0.5, 1)["error"] is True

    active, _session = _make_manager(tmp_path / "active")
    active.bootstrap_init("SID_TEST")
    data = active._load_skills("SID_TEST")
    data["skills"] = {"s": {"q_value": 0.5, "success_count": 0, "failure_count": 0}}
    active._bootstrap_apply_outcome_in_memory("SID_TEST", data, 1.5, 1, skill_id="s", delay_seconds=-1)
    active._bootstrap_apply_outcome_in_memory("SID_TEST", data, -1.0, 0, skill_id="s")
    assert data["skills"]["s"]["success_count"] == 1
    assert data["skills"]["s"]["failure_count"] == 1

    fresh, _session = _make_manager(tmp_path / "fresh")
    opened = fresh.bootstrap_open_dispute("SID_TEST", "claim", 1.5, " uncertain ", "s")
    assert opened["ok"] is True and opened["dispute"]["reason"] == "uncertain"
    dispute_id = opened["dispute"]["dispute_id"]
    assert fresh.bootstrap_list_disputes("SID_TEST", status="open")["count"] == 1
    assert fresh.bootstrap_resolve_dispute("SID_TEST", "missing", 1)["error"] is True
    resolved = fresh.bootstrap_resolve_dispute("SID_TEST", dispute_id, 1, delay_seconds=-2)
    assert resolved["ok"] is True and resolved["dispute"]["status"] == "resolved"
    assert fresh.bootstrap_resolve_dispute("SID_TEST", dispute_id, 0)["message"] == "Dispute already resolved"

    manager2, _session = _make_manager(tmp_path / "resolve-error")
    opened = manager2.bootstrap_open_dispute("SID_TEST", "claim", 0.5, "reason")
    monkeypatch.setattr(manager2, "_bootstrap_apply_outcome_in_memory", lambda *_a, **_k: _error())
    assert manager2.bootstrap_resolve_dispute("SID_TEST", opened["dispute"]["dispute_id"], 1)["error"] is True


def test_snapshot_export_and_policy_defaults_remain_safe_for_uninitialized_state(tmp_path):
    manager, _session = _make_manager(tmp_path)
    assert manager.bootstrap_get_autopilot_policy("SID_TEST")["policy"]["daily_budget"] == 100
    assert manager.bootstrap_mitigation_effectiveness("SID_TEST")["enough_data"] is False
    assert manager.bootstrap_policy_reweight_history("SID_TEST")["count"] == 0
    assert manager.bootstrap_export_metrics("SID_TEST")["counts"] == {"snapshots": 0, "disputes": 0, "outcomes": 0}
