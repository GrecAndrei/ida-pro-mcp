"""Contract coverage for the host bootstrap-session adapter."""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.server.server_session_bootstrap import (
    ServerSessionBootstrapMixin,
    _coerce_observed01,
    _coerce_predicted01,
)


class _Manager:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if not name.startswith("bootstrap_"):
            raise AttributeError(name)

        def call(sid, **kwargs):
            self.calls.append((name, sid, kwargs))
            return {"ok": True, "method": name, "sid": sid, "kwargs": kwargs}

        return call


class _Host(ServerSessionBootstrapMixin):
    def __init__(self):
        self.session_mgr = _Manager()
        self.owned_error = None

    def _require_session_sid(self, args):
        sid = str(args.get("session_id") or "").strip().upper()
        return (sid, None) if sid else (None, {"error": True, "message": "session_id required"})

    def _require_owned_session_id(self, _sid):
        return self.owned_error


_CASES = [
    ("bootstrap_init", {"overwrite": True, "decay_lambda": "0.2", "min_bootstrap_weight": "0.4"}, "bootstrap_init", {"overwrite": True, "decay_lambda": 0.2, "min_bootstrap_weight": 0.4}),
    ("bootstrap_run_tournament", {"rounds": 99999, "seed": -4}, "bootstrap_run_tournament", {"rounds": 5000, "seed": 0}),
    ("bootstrap_compute_blend", {"session_samples": 12}, "bootstrap_compute_blend", {"session_samples": 12}),
    ("bootstrap_status", {}, "bootstrap_status", {}),
    ("bootstrap_ingest_outcome", {"predicted": "0.75", "observed": 1, "skill_id": " skill ", "delay_seconds": 999999999}, "bootstrap_ingest_outcome", {"predicted": 0.75, "observed": 1, "skill_id": "skill", "delay_seconds": 31536000}),
    ("bootstrap_open_dispute", {"claim_id": "c1", "reason": "incorrect", "predicted": 0, "skill_id": "s1"}, "bootstrap_open_dispute", {"claim_id": "c1", "predicted": 0.0, "reason": "incorrect", "skill_id": "s1"}),
    ("bootstrap_list_disputes", {"status": "open"}, "bootstrap_list_disputes", {"status": "open"}),
    ("bootstrap_resolve_dispute", {"dispute_id": "d1", "observed": 0, "delay_seconds": 2}, "bootstrap_resolve_dispute", {"dispute_id": "d1", "observed": 0, "delay_seconds": 2}),
    ("bootstrap_summary", {}, "bootstrap_summary", {}),
    ("bootstrap_snapshot", {"name": "before-change"}, "bootstrap_snapshot", {"name": "before-change"}),
    ("bootstrap_list_snapshots", {"limit": 9999, "offset": -3}, "bootstrap_list_snapshots", {"limit": 1000, "offset": 0}),
    ("bootstrap_drift_report", {"window": 1}, "bootstrap_drift_report", {"window": 2}),
    ("bootstrap_simulate_batch", {"n": 99999, "seed": -1, "positive_rate": "0.25"}, "bootstrap_simulate_batch", {"n": 20000, "seed": 0, "positive_rate": 0.25}),
    ("bootstrap_prune_data", {"max_outcomes": 0, "max_disputes": 999999, "max_snapshots": 0}, "bootstrap_prune_data", {"max_outcomes": 1, "max_disputes": 50000, "max_snapshots": 1}),
    ("bootstrap_export_metrics", {"status": " OPEN ", "since": "s", "until": "u", "limit": 999999}, "bootstrap_export_metrics", {"status": "open", "since": "s", "until": "u", "limit": 200000}),
    ("bootstrap_summary_detailed", {"top_policies": 999}, "bootstrap_summary_detailed", {"top_policies": 50}),
    ("bootstrap_calibration_report", {"min_bin_n": 0}, "bootstrap_calibration_report", {"min_bin_n": 1}),
    ("bootstrap_update_baseline", {"window": 1, "percentile": "90.5"}, "bootstrap_update_baseline", {"window": 5, "percentile": 90.5}),
    ("bootstrap_evaluate_alerts", {"window": 1}, "bootstrap_evaluate_alerts", {"window": 2}),
    ("bootstrap_mitigation_plan", {"window": 1}, "bootstrap_mitigation_plan", {"window": 2}),
    ("bootstrap_apply_mitigation", {"window": 1, "max_actions": 99, "dry_run": "yes"}, "bootstrap_apply_mitigation", {"window": 2, "max_actions": 10, "dry_run": True}),
    ("bootstrap_mitigation_history", {"limit": 99999, "offset": -1}, "bootstrap_mitigation_history", {"limit": 5000, "offset": 0}),
    ("bootstrap_mitigation_effectiveness", {"window": 1}, "bootstrap_mitigation_effectiveness", {"window": 1}),
    ("bootstrap_policy_reweight", {"window": 1, "max_shift": "0.3", "dry_run": 1}, "bootstrap_policy_reweight", {"window": 2, "max_shift": 0.3, "dry_run": True}),
    ("bootstrap_policy_reweight_history", {"limit": 99999, "offset": -1}, "bootstrap_policy_reweight_history", {"limit": 5000, "offset": 0}),
    ("bootstrap_autopilot", {"window": 1, "dry_run": True}, "bootstrap_autopilot", {"window": 2, "dry_run": True}),
    ("bootstrap_set_autopilot_policy", {"cooldown_seconds": 999999, "daily_budget": 0, "max_live_actions": 99, "rollback_on_regression": "no"}, "bootstrap_set_autopilot_policy", {"cooldown_seconds": 86400, "daily_budget": 1, "max_live_actions": 10, "rollback_on_regression": False}),
    ("bootstrap_get_autopilot_policy", {}, "bootstrap_get_autopilot_policy", {}),
    ("bootstrap_rollback_last_reweight", {}, "bootstrap_rollback_last_reweight", {}),
    ("bootstrap_plan_status", {}, "bootstrap_plan_status", {}),
    ("bootstrap_readiness_gate", {"min_tournament_rounds": 0, "min_snapshots": 0, "min_outcomes": 0, "max_ece": "0.1", "max_open_disputes": -1}, "bootstrap_readiness_gate", {"min_tournament_rounds": 1, "min_snapshots": 1, "min_outcomes": 1, "max_ece": 0.1, "max_open_disputes": 0}),
    ("bootstrap_record_readiness", {"tag": " ready "}, "bootstrap_record_readiness", {"tag": "ready"}),
    ("bootstrap_readiness_history", {"limit": 99999, "offset": -1}, "bootstrap_readiness_history", {"limit": 5000, "offset": 0}),
    ("bootstrap_readiness_trend", {"window": 1}, "bootstrap_readiness_trend", {"window": 2}),
    ("bootstrap_readiness_regression_guard", {"window": 1, "auto_snapshot": "no"}, "bootstrap_readiness_regression_guard", {"window": 2, "auto_snapshot": False}),
    ("bootstrap_finalize_report", {"trend_window": 1, "effectiveness_window": 0}, "bootstrap_finalize_report", {"trend_window": 2, "effectiveness_window": 1}),
]


@pytest.mark.parametrize("action,args,method,expected", _CASES)
def test_bootstrap_actions_route_and_bound_arguments(action, args, method, expected):
    host = _Host()
    args = {"session_id": "abc12345", **args}

    result = host._handle_session_bootstrap(action, args)

    assert result["ok"] is True
    assert result["method"] == method
    assert result["sid"] == "ABC12345"
    assert result["kwargs"] == expected


def test_bootstrap_validation_rejects_bad_inputs_without_calling_manager():
    host = _Host()
    cases = [
        ({"session_id": "abc12345", "predicted": 1.2, "observed": 1}, "bootstrap_ingest_outcome"),
        ({"session_id": "abc12345", "predicted": 0.5, "observed": 0.5}, "bootstrap_ingest_outcome"),
        ({"session_id": "abc12345", "claim_id": "c", "reason": "r", "predicted": "bad"}, "bootstrap_open_dispute"),
        ({"session_id": "abc12345", "dispute_id": "d", "observed": 2}, "bootstrap_resolve_dispute"),
        ({"session_id": "abc12345", "positive_rate": "bad"}, "bootstrap_simulate_batch"),
        ({"session_id": "abc12345", "percentile": "bad"}, "bootstrap_update_baseline"),
        ({"session_id": "abc12345", "max_shift": "bad"}, "bootstrap_policy_reweight"),
        ({"session_id": "abc12345", "max_ece": "bad"}, "bootstrap_readiness_gate"),
        ({"session_id": "abc12345"}, "bootstrap_compute_blend"),
    ]

    for args, action in cases:
        result = host._handle_session_bootstrap(action, args)
        assert result["error"] is True, (action, result)
    assert host.session_mgr.calls == []


def test_bootstrap_mutators_require_ownership_and_missing_manager_is_classifiable():
    host = _Host()
    host.owned_error = {"error": True, "code": "FILE_LOCKED"}
    result = host._handle_session_bootstrap("bootstrap_init", {"session_id": "abc12345"})
    assert result == host.owned_error
    assert host.session_mgr.calls == []

    host = _Host()
    host.session_mgr = object()
    result = host._handle_session_bootstrap("bootstrap_status", {"session_id": "abc12345"})
    assert result["error"] is True
    assert result["code"] == "NOT_IMPLEMENTED"
    assert result["details"]["method"] == "bootstrap_status"


def test_bootstrap_sid_errors_and_unknown_actions_are_non_destructive():
    host = _Host()
    missing = host._handle_session_bootstrap("bootstrap_status", {})
    assert missing["error"] is True
    assert host._handle_session_bootstrap("bootstrap_not_real", {"session_id": "abc12345"}) is None


def test_bootstrap_scalar_coercers_reject_non_integral_values():
    assert _coerce_observed01(0) == (0, None)
    assert _coerce_observed01("1") == (1, None)
    assert _coerce_observed01(True)[0] is None
    assert _coerce_observed01(0.2)[0] is None
    assert _coerce_predicted01(0.0) == (0.0, None)
    assert _coerce_predicted01("1") == (1.0, None)
    assert _coerce_predicted01(-0.1)[0] is None
    assert _coerce_predicted01("not-a-number")[0] is None
