"""Behavioral coverage for bootstrap monitoring and outcome controls."""

from __future__ import annotations

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import SessionManager


def _manager(tmp_path):
    manager = SessionManager(str(tmp_path))
    session = manager.create_session("/samples/bootstrap.bin")
    return manager, session.session_id


def test_bootstrap_uninitialized_contracts_and_outcome_lifecycle(tmp_path):
    manager, sid = _manager(tmp_path)

    assert manager.bootstrap_summary(sid)["initialized"] is False
    assert manager.bootstrap_status(sid)["initialized"] is False
    assert manager.bootstrap_snapshot(sid)["initialized"] is False
    assert manager.bootstrap_drift_report(sid)["enough_data"] is False
    assert manager.bootstrap_update_baseline(sid)["enough_data"] is False
    assert manager.bootstrap_calibration_report(sid)["used_bins"] == 0
    assert manager.bootstrap_mitigation_effectiveness(sid)["enough_data"] is False
    assert manager.bootstrap_policy_reweight(sid)["error"] is True
    assert manager.bootstrap_summary("missing")["code"] == MCPError.SESSION_NOT_FOUND

    assert manager.bootstrap_init(sid)["initialized"] is True
    state = manager._load_skills(sid)
    state["skills"]["triage"] = {
        "q_value": 0.5,
        "description": "bootstrap triage",
        "tags": ["bootstrap"],
    }
    manager._save_skills(sid, state)
    ingested = manager.bootstrap_ingest_outcome(
        sid, predicted=1.5, observed=1, skill_id="triage", delay_seconds=-2
    )
    assert ingested["ok"] is True
    assert ingested["predicted"] == 0.999
    assert ingested["session_update"]["skill_id"] == "triage"
    simulated = manager.bootstrap_simulate_batch(sid, n=4, seed=12, positive_rate=0.75)
    assert simulated["n"] == 4
    assert simulated["positive_rate_target"] == 0.75

    dispute = manager.bootstrap_open_dispute(
        sid, claim_id="claim-1", predicted=-1.0, reason="review disagreement", skill_id="triage"
    )
    dispute_id = dispute["dispute"]["dispute_id"]
    assert manager.bootstrap_list_disputes(sid, status="OPEN")["count"] == 1
    resolved = manager.bootstrap_resolve_dispute(sid, dispute_id, observed=0, delay_seconds=4)
    assert resolved["dispute"]["status"] == "resolved"
    assert manager.bootstrap_resolve_dispute(sid, dispute_id, observed=1)["message"] == "Dispute already resolved"
    assert manager.bootstrap_resolve_dispute(sid, "missing", observed=1)["code"] == MCPError.NOT_FOUND
    assert manager.bootstrap_list_disputes(sid)["resolved"] == 1


def test_bootstrap_snapshots_drift_baseline_exports_and_calibration(tmp_path):
    manager, sid = _manager(tmp_path)
    manager.bootstrap_init(sid)
    manager.bootstrap_run_tournament(sid, rounds=2, seed=5)
    manager.bootstrap_simulate_batch(sid, n=3, seed=8, positive_rate=0.5)

    for i in range(5):
        snap = manager.bootstrap_snapshot(sid, name=f"checkpoint-{i}")
        assert snap["snapshot"]["name"] == f"checkpoint-{i}"
    listed = manager.bootstrap_list_snapshots(sid, limit=2, offset=1)
    assert listed["total"] == 5 and listed["count"] == 2
    drift = manager.bootstrap_drift_report(sid, window=99)
    assert drift["enough_data"] is True and drift["window"] == 5
    baseline = manager.bootstrap_update_baseline(sid, window=99, percentile=120)
    assert baseline["enough_data"] is True
    assert baseline["baseline"]["percentile"] == 99.9
    alerts = manager.bootstrap_evaluate_alerts(sid, window=1)
    assert alerts["enough_data"] is True
    report = manager.bootstrap_calibration_report(sid, min_bin_n=1)
    assert report["used_bins"] >= 1 and report["ece"] >= 0
    detailed = manager.bootstrap_summary_detailed(sid, top_policies=2)
    assert detailed["total_policies"] == 12
    assert len(detailed["policy_diagnostics"]) == 2

    exported = manager.bootstrap_export_metrics(
        sid,
        status="resolved",
        since="2000-01-01T00:00:00",
        until="2100-01-01T00:00:00",
        limit=2,
    )
    assert exported["ok"] is True
    assert exported["filters"]["status"] == "resolved"
    assert exported["counts"]["snapshots"] == 2

    data = manager._load_skills(sid)
    snapshots = data["bootstrap"]["metric_snapshots"]
    snapshots[0]["ece"] = 0.01
    snapshots[-1]["ece"] = 0.20
    snapshots[-1]["prior_confidence"] = 0.30
    manager._save_skills(sid, data)
    assert manager.bootstrap_drift_report(sid)["risk"] == "degrading"
    assert manager.bootstrap_evaluate_alerts(sid)["severity"] in {"low", "medium", "high", "none"}


def test_bootstrap_mitigation_policy_and_autopilot_controls(tmp_path):
    manager, sid = _manager(tmp_path)
    manager.bootstrap_init(sid)
    for i in range(5):
        manager.bootstrap_snapshot(sid, name=f"mitigation-{i}")
    manager.bootstrap_update_baseline(sid)

    plan = manager.bootstrap_mitigation_plan(sid)
    assert plan["ok"] is True and plan["enough_data"] is True
    dry = manager.bootstrap_apply_mitigation(sid, dry_run=True)
    assert dry["dry_run"] is True and dry["executed"] == []
    applied = manager.bootstrap_apply_mitigation(sid, max_actions=1)
    assert applied["ok"] is True and applied["actions_requested"] == 1
    history = manager.bootstrap_mitigation_history(sid)
    assert history["count"] == 1
    effectiveness = manager.bootstrap_mitigation_effectiveness(sid)
    assert effectiveness["enough_data"] is True

    preview = manager.bootstrap_policy_reweight(sid, max_shift=0.3, dry_run=True)
    assert preview["dry_run"] is True and preview["updates"]
    changed = manager.bootstrap_policy_reweight(sid, max_shift=0.3)
    assert changed["ok"] is True
    assert manager.bootstrap_policy_reweight_history(sid)["count"] == 1
    rollback = manager.bootstrap_rollback_last_reweight(sid)
    assert rollback["rolled_back"] is True
    assert manager.bootstrap_rollback_last_reweight(sid)["rolled_back"] is True

    set_policy = manager.bootstrap_set_autopilot_policy(
        sid, cooldown_seconds=-1, daily_budget=0, max_live_actions=99, rollback_on_regression=False
    )
    assert set_policy["policy"]["cooldown_seconds"] == 0
    assert set_policy["policy"]["daily_budget"] == 1
    assert set_policy["policy"]["max_live_actions"] == 10
    assert manager.bootstrap_get_autopilot_policy(sid)["policy"]["rollback_on_regression"] is False
    autopilot = manager.bootstrap_autopilot(sid, window=2, dry_run=True)
    assert autopilot["ok"] is True and autopilot["dry_run"] is True
    assert manager.bootstrap_prune_data(sid, max_outcomes=1, max_disputes=1, max_snapshots=2)["ok"] is True
