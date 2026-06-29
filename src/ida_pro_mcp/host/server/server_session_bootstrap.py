#!/usr/bin/env python3
"""Bootstrap action routing extracted from session tool dispatch."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Dict, Optional, Tuple

from ..config import _bounded_int, _coerce_bool
from ..errors import MCPError, make_error


class ServerSessionBootstrapMixin:
    def _handle_session_bootstrap(
        self,
        action: str,
        args: Dict[str, Any],
        sid_arg: Callable[..., Tuple[Optional[str], Optional[dict]]],
    ) -> Optional[dict]:
        if action == "bootstrap_init":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            overwrite = _coerce_bool(args.get("overwrite"), False)
            decay_lambda = args.get("decay_lambda", 0.03)
            min_bootstrap_weight = args.get("min_bootstrap_weight", 0.1)
            try:
                decay_lambda = float(decay_lambda)
                min_bootstrap_weight = float(min_bootstrap_weight)
            except (TypeError, ValueError):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "decay_lambda and min_bootstrap_weight must be numeric",
                )
            return self.session_mgr.bootstrap_init(
                sid,
                overwrite=overwrite,
                decay_lambda=decay_lambda,
                min_bootstrap_weight=min_bootstrap_weight,
            )
        if action == "bootstrap_run_tournament":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            rounds = _bounded_int(args.get("rounds", 200), 200, min_value=1, max_value=50000)
            seed = _bounded_int(args.get("seed", 1337), 1337, min_value=0, max_value=2_147_483_647)
            return self.session_mgr.bootstrap_run_tournament(
                sid,
                rounds=rounds,
                seed=seed,
            )
        if action == "bootstrap_compute_blend":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            if "session_samples" not in args:
                return make_error(MCPError.INVALID_ARGS, "session_samples required")
            session_samples = _bounded_int(
                args.get("session_samples"),
                0,
                min_value=0,
                max_value=100_000_000,
            )
            return self.session_mgr.bootstrap_compute_blend(
                sid,
                session_samples=session_samples,
            )
        if action == "bootstrap_status":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.bootstrap_status(sid)
        if action == "bootstrap_ingest_outcome":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            if "predicted" not in args:
                return make_error(MCPError.INVALID_ARGS, "predicted required")
            if "observed" not in args:
                return make_error(MCPError.INVALID_ARGS, "observed required")
            try:
                predicted = float(args.get("predicted"))
                observed = int(args.get("observed"))
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "predicted must be float and observed must be int")
            skill_id = str(args.get("skill_id") or "").strip() or None
            delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
            return self.session_mgr.bootstrap_ingest_outcome(
                sid,
                predicted=predicted,
                observed=observed,
                skill_id=skill_id,
                delay_seconds=delay_seconds,
            )
        if action == "bootstrap_open_dispute":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            claim_id = str(args.get("claim_id") or "").strip()
            reason = str(args.get("reason") or "").strip()
            if not claim_id:
                return make_error(MCPError.INVALID_ARGS, "claim_id required")
            if not reason:
                return make_error(MCPError.INVALID_ARGS, "reason required")
            if "predicted" not in args:
                return make_error(MCPError.INVALID_ARGS, "predicted required")
            try:
                predicted = float(args.get("predicted"))
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "predicted must be float")
            skill_id = str(args.get("skill_id") or "").strip() or None
            return self.session_mgr.bootstrap_open_dispute(
                sid,
                claim_id=claim_id,
                predicted=predicted,
                reason=reason,
                skill_id=skill_id,
            )
        if action == "bootstrap_list_disputes":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            status = str(args.get("status") or "").strip() or None
            return self.session_mgr.bootstrap_list_disputes(sid, status=status)
        if action == "bootstrap_resolve_dispute":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            dispute_id = str(args.get("dispute_id") or "").strip()
            if not dispute_id:
                return make_error(MCPError.INVALID_ARGS, "dispute_id required")
            if "observed" not in args:
                return make_error(MCPError.INVALID_ARGS, "observed required")
            try:
                observed = int(args.get("observed"))
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "observed must be int")
            delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
            return self.session_mgr.bootstrap_resolve_dispute(
                sid,
                dispute_id=dispute_id,
                observed=observed,
                delay_seconds=delay_seconds,
            )
        if action == "bootstrap_summary":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.bootstrap_summary(sid)
        if action == "bootstrap_snapshot":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            name = str(args.get("name") or "").strip()
            return self.session_mgr.bootstrap_snapshot(sid, name=name)
        if action == "bootstrap_list_snapshots":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            limit = _bounded_int(args.get("limit", 50), 50, min_value=1, max_value=1000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self.session_mgr.bootstrap_list_snapshots(
                sid,
                limit=limit,
                offset=offset,
            )
        if action == "bootstrap_drift_report":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=1000)
            return self.session_mgr.bootstrap_drift_report(sid, window=window)
        if action == "bootstrap_simulate_batch":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            n = _bounded_int(args.get("n", 500), 500, min_value=1, max_value=200000)
            seed = _bounded_int(args.get("seed", 2026), 2026, min_value=0, max_value=2_147_483_647)
            positive_rate = args.get("positive_rate", 0.5)
            try:
                positive_rate = float(positive_rate)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "positive_rate must be numeric")
            return self.session_mgr.bootstrap_simulate_batch(
                sid,
                n=n,
                seed=seed,
                positive_rate=positive_rate,
            )
        if action == "bootstrap_prune_data":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            max_outcomes = _bounded_int(args.get("max_outcomes", 1000), 1000, min_value=1, max_value=200000)
            max_disputes = _bounded_int(args.get("max_disputes", 500), 500, min_value=1, max_value=50000)
            max_snapshots = _bounded_int(args.get("max_snapshots", 2000), 2000, min_value=1, max_value=100000)
            return self.session_mgr.bootstrap_prune_data(
                sid,
                max_outcomes=max_outcomes,
                max_disputes=max_disputes,
                max_snapshots=max_snapshots,
            )
        if action == "bootstrap_export_metrics":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            status = str(args.get("status") or "all").strip().lower()
            since = str(args.get("since") or "").strip()
            until = str(args.get("until") or "").strip()
            limit = _bounded_int(args.get("limit", 5000), 5000, min_value=1, max_value=200000)
            return self.session_mgr.bootstrap_export_metrics(
                sid,
                status=status,
                since=since,
                until=until,
                limit=limit,
            )
        if action == "bootstrap_summary_detailed":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            top_policies = _bounded_int(args.get("top_policies", 10), 10, min_value=1, max_value=50)
            return self.session_mgr.bootstrap_summary_detailed(sid, top_policies=top_policies)
        if action == "bootstrap_calibration_report":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            min_bin_n = _bounded_int(args.get("min_bin_n", 20), 20, min_value=1, max_value=1000000)
            return self.session_mgr.bootstrap_calibration_report(sid, min_bin_n=min_bin_n)
        if action == "bootstrap_update_baseline":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 50), 50, min_value=5, max_value=10000)
            percentile = args.get("percentile", 95.0)
            try:
                percentile = float(percentile)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "percentile must be numeric")
            return self.session_mgr.bootstrap_update_baseline(
                sid,
                window=window,
                percentile=percentile,
            )
        if action == "bootstrap_evaluate_alerts":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            return self.session_mgr.bootstrap_evaluate_alerts(sid, window=window)
        if action == "bootstrap_mitigation_plan":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            return self.session_mgr.bootstrap_mitigation_plan(sid, window=window)
        if action == "bootstrap_apply_mitigation":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            max_actions = _bounded_int(args.get("max_actions", 4), 4, min_value=1, max_value=10)
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self.session_mgr.bootstrap_apply_mitigation(
                sid,
                window=window,
                max_actions=max_actions,
                dry_run=dry_run,
            )
        if action == "bootstrap_mitigation_history":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self.session_mgr.bootstrap_mitigation_history(sid, limit=limit, offset=offset)
        if action == "bootstrap_mitigation_effectiveness":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 50), 50, min_value=1, max_value=10000)
            return self.session_mgr.bootstrap_mitigation_effectiveness(sid, window=window)
        if action == "bootstrap_policy_reweight":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            max_shift = args.get("max_shift", 0.08)
            try:
                max_shift = float(max_shift)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "max_shift must be numeric")
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self.session_mgr.bootstrap_policy_reweight(
                sid,
                window=window,
                max_shift=max_shift,
                dry_run=dry_run,
            )
        if action == "bootstrap_policy_reweight_history":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self.session_mgr.bootstrap_policy_reweight_history(sid, limit=limit, offset=offset)
        if action == "bootstrap_autopilot":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self.session_mgr.bootstrap_autopilot(sid, window=window, dry_run=dry_run)
        if action == "bootstrap_set_autopilot_policy":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            cooldown_seconds = _bounded_int(args.get("cooldown_seconds", 300), 300, min_value=0, max_value=86400)
            daily_budget = _bounded_int(args.get("daily_budget", 100), 100, min_value=1, max_value=100000)
            max_live_actions = _bounded_int(args.get("max_live_actions", 4), 4, min_value=1, max_value=10)
            rollback_on_regression = _coerce_bool(args.get("rollback_on_regression"), True)
            return self.session_mgr.bootstrap_set_autopilot_policy(
                sid,
                cooldown_seconds=cooldown_seconds,
                daily_budget=daily_budget,
                max_live_actions=max_live_actions,
                rollback_on_regression=rollback_on_regression,
            )
        if action == "bootstrap_get_autopilot_policy":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.bootstrap_get_autopilot_policy(sid)
        if action == "bootstrap_rollback_last_reweight":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.bootstrap_rollback_last_reweight(sid)
        if action == "bootstrap_plan_status":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.bootstrap_plan_status(sid)
        if action == "bootstrap_readiness_gate":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            min_tournament_rounds = _bounded_int(args.get("min_tournament_rounds", 1000), 1000, min_value=1, max_value=1_000_000)
            min_snapshots = _bounded_int(args.get("min_snapshots", 10), 10, min_value=1, max_value=100_000)
            min_outcomes = _bounded_int(args.get("min_outcomes", 200), 200, min_value=1, max_value=1_000_000)
            max_open_disputes = _bounded_int(args.get("max_open_disputes", 25), 25, min_value=0, max_value=100_000)
            max_ece = args.get("max_ece", 0.2)
            try:
                max_ece = float(max_ece)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "max_ece must be numeric")
            return self.session_mgr.bootstrap_readiness_gate(
                sid,
                min_tournament_rounds=min_tournament_rounds,
                min_snapshots=min_snapshots,
                min_outcomes=min_outcomes,
                max_ece=max_ece,
                max_open_disputes=max_open_disputes,
            )
        if action == "bootstrap_record_readiness":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            tag = str(args.get("tag") or "").strip()
            return self.session_mgr.bootstrap_record_readiness(sid, tag=tag)
        if action == "bootstrap_readiness_history":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self.session_mgr.bootstrap_readiness_history(sid, limit=limit, offset=offset)
        if action == "bootstrap_readiness_trend":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            return self.session_mgr.bootstrap_readiness_trend(sid, window=window)
        if action == "bootstrap_readiness_regression_guard":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            auto_snapshot = _coerce_bool(args.get("auto_snapshot"), True)
            return self.session_mgr.bootstrap_readiness_regression_guard(
                sid,
                window=window,
                auto_snapshot=auto_snapshot,
            )
        if action == "bootstrap_finalize_report":
            sid, sid_err = sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            trend_window = _bounded_int(args.get("trend_window", 50), 50, min_value=2, max_value=10000)
            effectiveness_window = _bounded_int(args.get("effectiveness_window", 50), 50, min_value=1, max_value=10000)
            return self.session_mgr.bootstrap_finalize_report(
                sid,
                trend_window=trend_window,
                effectiveness_window=effectiveness_window,
            )

        return None
