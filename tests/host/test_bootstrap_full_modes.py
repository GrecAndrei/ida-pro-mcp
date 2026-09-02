"""End-to-end coverage for the persisted bootstrap control loop.

The bootstrap API is host-side, but it is consumed by both the public session
surface and the legacy session action dispatcher.  Keep this test on a real
``SessionManager`` and let each operation read/write the same skills file so
the assertions cover the interaction between modes, not just individual
return values.
"""

from __future__ import annotations

import os

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import Session, SessionManager


def _manager(tmp_path):
    manager = SessionManager(str(tmp_path))
    manager.sessions["SID_MATRIX"] = Session(
        "SID_MATRIX", idb_path=str(tmp_path / "sample.i64"), binary_path=str(tmp_path / "sample.bin")
    )
    os.makedirs(os.path.dirname(manager._get_skills_path("SID_MATRIX")), exist_ok=True)
    return manager


def _skills(manager):
    return manager._load_skills("SID_MATRIX")


def _save(manager, data):
    manager._save_skills("SID_MATRIX", data)


def test_bootstrap_cold_start_outcome_dispute_and_reports(tmp_path):
    manager = _manager(tmp_path)
    sid = "SID_MATRIX"

    assert manager.bootstrap_status("missing") ["error"] is True
    assert manager.bootstrap_status(sid)["initialized"] is False

    initialized = manager.bootstrap_init(sid, decay_lambda=0.05, min_bootstrap_weight=0.2)
    assert initialized == {"ok": True, "initialized": True, "policies": 12}
    assert manager.bootstrap_init(sid)["initialized"] is False
    assert manager.bootstrap_compute_blend(sid, -4)["session_samples"] == 0
    assert manager.bootstrap_compute_blend(sid, 10_000)["weights"]["bootstrap"] == 0.2

    tournament = manager.bootstrap_run_tournament(sid, rounds=4, seed=19)
    assert tournament["ok"] is True
    assert tournament["rounds"] == 4
    assert len(tournament["top_policies"]) == 5
    status = manager.bootstrap_status(sid)
    assert status["total_rounds"] == 4
    assert status["leaderboard"]

    data = _skills(manager)
    data["skills"] = {
        "skill-a": {
            "q_value": 0.4,
            "success_count": 0,
            "failure_count": 0,
            "description": "find imports",
            "tags": ["imports"],
        }
    }
    _save(manager, data)
    ingested = manager.bootstrap_ingest_outcome(
        sid, predicted=1.5, observed=2, skill_id="skill-a", delay_seconds=-9
    )
    assert ingested["ok"] is True
    assert ingested["predicted"] == 0.999
    assert ingested["observed"] == 1
    assert ingested["session_update"]["skill_id"] == "skill-a"
    assert _skills(manager)["skills"]["skill-a"]["success_count"] == 1

    dispute = manager.bootstrap_open_dispute(sid, "claim-1", -2, "  review  ", "skill-a")
    dispute_id = dispute["dispute"]["dispute_id"]
    assert dispute["dispute"]["predicted"] == 0.001
    assert dispute["dispute"]["reason"] == "review"
    assert manager.bootstrap_list_disputes(sid, "OPEN")["count"] == 1
    resolved = manager.bootstrap_resolve_dispute(sid, dispute_id, 0, -7)
    assert resolved["ok"] is True
    assert resolved["dispute"]["status"] == "resolved"
    assert manager.bootstrap_resolve_dispute(sid, dispute_id, 1)["message"] == "Dispute already resolved"
    assert manager.bootstrap_resolve_dispute(sid, "no-such", 0)["code"] == MCPError.NOT_FOUND

    snapshot = manager.bootstrap_snapshot(sid, "  after-outcome ")
    assert snapshot["snapshot"]["name"] == "after-outcome"
    assert manager.bootstrap_list_snapshots(sid, limit=1, offset=-2)["count"] == 1
    assert manager.bootstrap_calibration_report(sid, min_bin_n=1)["used_bins"] >= 1
    summary = manager.bootstrap_summary(sid)
    detailed = manager.bootstrap_summary_detailed(sid, top_policies=1)
    assert summary["initialized"] is True
    assert summary["disputes"]["resolved"] == 1
    assert len(detailed["policy_diagnostics"]) == 1

    exported = manager.bootstrap_export_metrics(
        sid,
        status="resolved",
        since="2000-01-01T00:00:00",
        until="2999-01-01T00:00:00",
        limit=2,
    )
    assert exported["ok"] is True
    assert exported["counts"]["disputes"] == 1
    assert manager.bootstrap_export_metrics(sid, status="open")["counts"]["disputes"] == 0


def test_bootstrap_drift_mitigation_reweight_and_autopilot_modes(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SID_MATRIX"
    manager.bootstrap_init(sid)

    # Seed the real persistence format with enough history to take every
    # observability branch while keeping the test fast and deterministic.
    data = _skills(manager)
    bootstrap = data["bootstrap"]
    bootstrap["metric_snapshots"] = [
        {
            "snapshot_id": f"s{i}",
            "timestamp": f"2026-01-{i + 1:02d}T00:00:00",
            "prior_confidence": 0.9 - i * 0.03,
            "ece": 0.05 + i * 0.02,
            "outcomes": 100 + i,
            "open_disputes": i % 3,
        }
        for i in range(8)
    ]
    bootstrap["outcomes"] = [
        {"timestamp": f"2026-01-01T00:{i:02d}:00", "predicted": 0.5, "observed": i % 2, "brier": 0.25}
        for i in range(8)
    ]
    bootstrap["disputes"] = []
    _save(manager, data)

    drift = manager.bootstrap_drift_report(sid, window=4)
    assert drift["ok"] is True
    assert drift["enough_data"] is True
    baseline = manager.bootstrap_update_baseline(sid, window=4, percentile=90)
    assert baseline["ok"] is True
    assert baseline["baseline"]["window"] == 5
    alerts = manager.bootstrap_evaluate_alerts(sid, window=4)
    assert alerts["ok"] is True
    plan = manager.bootstrap_mitigation_plan(sid, window=4)
    assert plan["ok"] is True
    assert plan["actions"]
    dry = manager.bootstrap_apply_mitigation(sid, window=4, max_actions=1, dry_run=True)
    assert dry["dry_run"] is True

    # Drive all mitigation action kinds through the real executor.  The
    # replacement plan is still passed through the actual method and state
    # persistence, while avoiding a large synthetic tournament.
    monkeypatch.setattr(
        manager,
        "bootstrap_mitigation_plan",
        lambda _sid, window=20: {
            "ok": True,
            "severity": "high",
            "alerts": [{"type": "confidence_drop"}],
            "actions": [
                {"action": "bootstrap_run_tournament", "params": {"rounds": 2, "seed": 3}},
                {"action": "bootstrap_simulate_batch", "params": {"n": 2, "seed": 4, "positive_rate": 0.75}},
                {"action": "bootstrap_snapshot", "params": {"name": "mitigation"}},
                {"action": "bootstrap_update_baseline", "params": {"window": 3, "percentile": 95}},
                {"action": "not-a-real-action", "params": {}},
            ],
        },
    )
    applied = manager.bootstrap_apply_mitigation(sid, window=4, max_actions=10)
    assert applied["ok"] is True
    assert len(applied["executed"]) == 5
    assert applied["executed"][-1]["ok"] is False
    assert manager.bootstrap_mitigation_history(sid)["count"] >= 1
    effectiveness = manager.bootstrap_mitigation_effectiveness(sid, window=1)
    assert effectiveness["enough_data"] is True
    assert effectiveness["tier"] in {"poor", "moderate", "strong"}

    # Reweight both dry-run and persisted paths, then rollback the persisted
    # update and inspect its history.
    dry_reweight = manager.bootstrap_policy_reweight(sid, dry_run=True, max_shift=0.2)
    assert dry_reweight["ok"] is True
    applied_reweight = manager.bootstrap_policy_reweight(sid, max_shift=0.2)
    assert applied_reweight["ok"] is True
    assert manager.bootstrap_policy_reweight_history(sid)["count"] == 1
    rollback = manager.bootstrap_rollback_last_reweight(sid)
    assert rollback["rolled_back"] is True
    assert manager.bootstrap_rollback_last_reweight(sid)["rolled_back"] is True

    policy = manager.bootstrap_set_autopilot_policy(
        sid, cooldown_seconds=-1, daily_budget=0, max_live_actions=99, rollback_on_regression=False
    )
    assert policy["policy"]["cooldown_seconds"] == 0
    assert policy["policy"]["daily_budget"] == 1
    assert policy["policy"]["max_live_actions"] == 10
    assert manager.bootstrap_get_autopilot_policy(sid)["policy"] == policy["policy"]

    # A dry-run autopilot traverses planning, mitigation, reweighting and the
    # post-evaluation report without consuming the daily budget.
    autopilot = manager.bootstrap_autopilot(sid, window=4, dry_run=True)
    assert autopilot["ok"] is True
    assert autopilot["dry_run"] is True


def test_bootstrap_readiness_history_trend_guard_and_pruning(tmp_path):
    manager = _manager(tmp_path)
    sid = "SID_MATRIX"
    manager.bootstrap_init(sid)
    data = _skills(manager)
    bootstrap = data["bootstrap"]
    bootstrap["outcomes"] = [{"timestamp": "2026-01-01T00:00:00", "brier": 0.1}]
    bootstrap["disputes"] = [{"dispute_id": "d1", "status": "open"}]
    bootstrap["metric_snapshots"] = [{"timestamp": "2026-01-01T00:00:00"}]
    _save(manager, data)

    not_ready = manager.bootstrap_readiness_gate(
        sid, min_tournament_rounds=100, min_snapshots=2, min_outcomes=2, max_open_disputes=0
    )
    assert not_ready["readiness"] is False
    assert "outcome_depth" in not_ready["failed"]
    recorded = manager.bootstrap_record_readiness(sid, "first")
    assert recorded["history_count"] == 1

    data = _skills(manager)
    data["bootstrap"]["readiness_history"] = [
        {"readiness": True, "coverage": 100.0},
        {"readiness": False, "coverage": 80.0},
        {"readiness": False, "coverage": 70.0},
    ]
    _save(manager, data)
    history = manager.bootstrap_readiness_history(sid, limit=2, offset=-4)
    assert history["count"] == 2
    trend = manager.bootstrap_readiness_trend(sid, window=3)
    assert trend["status"] == "regressing"
    guard = manager.bootstrap_readiness_regression_guard(sid, auto_snapshot=False)
    assert guard["triggered"] is True
    assert len(guard["actions"]) == 2
    assert manager.bootstrap_readiness_trend(sid, window=1)["enough_data"] is True

    report = manager.bootstrap_finalize_report(sid, trend_window=3, effectiveness_window=1)
    assert report["ok"] is True
    assert report["stage"] == "needs_attention"
    pruned = manager.bootstrap_prune_data(sid, max_outcomes=1, max_disputes=1, max_snapshots=1)
    assert pruned["ok"] is True
    assert pruned["after"] == {"outcomes": 1, "disputes": 1, "metric_snapshots": 1}


def test_bootstrap_error_and_internal_prediction_modes(tmp_path):
    manager = _manager(tmp_path)
    sid = "SID_MATRIX"
    assert manager.bootstrap_init("missing")["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.bootstrap_run_tournament("missing", rounds=1)["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.bootstrap_policy_reweight(sid)["code"] == MCPError.INVALID_ARGS

    # Exercise prediction defaults and both clipping directions without a
    # second persistence round-trip.
    import random

    low = manager._policy_predict({"bias": -9, "noise": 0}, [1, 1, 1, 1], random.Random(1))
    high = manager._policy_predict({"bias": 9, "noise": 0}, [1, 1, 1, 1], random.Random(1))
    default = manager._policy_predict({}, [0, 0, 0, 0], random.Random(1))
    assert low == 0.001
    assert high == 0.999
    assert default == 0.001
