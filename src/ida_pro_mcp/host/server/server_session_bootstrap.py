#!/usr/bin/env python3
"""Hidden orchestrator-only bootstrap dispatch for the session tool.

The ``bootstrap_*`` session actions are the host-side control surface for the
local-skills bootstrap lab (policy tournaments, outcome ingestion, disputes,
snapshots, drift/readiness, mitigation and autopilot). They are deliberately
NOT advertised: none of them appear in ``TOOL_ACTIONS['session']`` (see
schemas_data.py), so a client that enumerates valid actions never sees them,
and they are not registered in tool_registry/schemas. They are reachable only
through the raw dispatch path in ``ServerSessionMixin._handle_session``
(server_session.py), which routes any ``action`` starting with ``bootstrap_``
here. This is an intentional contract for the orchestrator plan matrix
(``session_skills.py`` ``_bootstrap_plan_matrix``), not a schema oversight —
do not advertise these actions without an explicit product decision.

Ownership: every branch resolves the target session through
``self._require_session_sid`` and, for actions that persist bootstrap state,
through ``self._require_owned_session_id``, so a multiplexed connection can
never mutate another client's live session (FILE_LOCKED envelope). Read-only
branches (status/summary/list_*/history/drift/export/plan_status/readiness
reads) only resolve the sid and need no ownership guard.

Manager availability: each branch calls the SessionManager through
``_bootstrap_mgr_call``, which resolves ``bootstrap_<suffix>`` via getattr and
returns a classifiable NOT_IMPLEMENTED envelope (mirroring ``_run_session_spec``)
when the method is missing or renamed, instead of a -32000 internal
AttributeError that callers cannot classify.

Argument bounds are kept in lockstep with the manager's own clamps so the
advertised range matches what actually executes (tournament rounds <= 5000,
simulate_batch n <= 20000), and outcome/probability inputs are validated
strictly instead of silently coerced by the manager.
"""

from __future__ import annotations

from typing import Any

from ..config import _bounded_int, _coerce_bool
from ..errors import MCPError, make_error


def _coerce_observed01(raw: Any) -> tuple[int | None, dict | None]:
    """Coerce an outcome observation to 0/1, rejecting anything else.

    The manager collapses any truthy observed to 1 (``obs = 1 if int(observed)
    else 0``), so a float like 0.9 would silently become 0. Reject non-integral
    values and anything outside {0, 1} up front instead of letting ``int()``
    truncate.
    """
    if isinstance(raw, bool):
        return None, make_error(MCPError.INVALID_ARGS, "observed must be an integer 0/1")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None, make_error(MCPError.INVALID_ARGS, "observed must be an integer 0/1")
    if value not in (0.0, 1.0):
        return None, make_error(MCPError.INVALID_ARGS, "observed must be an integer 0/1")
    return int(value), None


def _coerce_predicted01(raw: Any) -> tuple[float | None, dict | None]:
    """Coerce a prediction probability to [0.0, 1.0], rejecting out-of-range.

    The manager clamps predicted to [0.001, 0.999] silently; reject a caller
    value outside [0.0, 1.0] here so a bad request surfaces as INVALID_ARGS
    instead of being silently clamped into a different probability.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None, make_error(
            MCPError.INVALID_ARGS, "predicted must be a number between 0.0 and 1.0"
        )
    if not (0.0 <= value <= 1.0):
        return None, make_error(
            MCPError.INVALID_ARGS, "predicted must be between 0.0 and 1.0"
        )
    return value, None


class ServerSessionBootstrapMixin:
    def _bootstrap_mgr_call(self, suffix: str, sid: str, **kwargs: Any) -> dict:
        """Call ``session_mgr.bootstrap_<suffix>`` with a NOT_IMPLEMENTED fallback.

        Mirrors ``_run_session_spec`` (server_session.py): a missing or renamed
        manager method surfaces as a classifiable NOT_IMPLEMENTED envelope
        instead of a raw AttributeError. ``suffix`` is the action name without
        the ``bootstrap_`` prefix.
        """
        method = f"bootstrap_{suffix}"
        mgr_call = getattr(self.session_mgr, method, None)
        if mgr_call is None:
            return make_error(
                MCPError.NOT_IMPLEMENTED,
                f"Session action {method!r} is not implemented in this build",
                hint="Check the package version; this action may have been removed or is gated on a feature flag.",
                details={"method": method, "kind": "bootstrap"},
            )
        return mgr_call(sid, **kwargs)

    def _handle_session_bootstrap(
        self,
        action: str,
        args: dict[str, Any],
    ) -> dict | None:
        if action == "bootstrap_init":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
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
            return self._bootstrap_mgr_call(
                "init",
                sid,
                overwrite=overwrite,
                decay_lambda=decay_lambda,
                min_bootstrap_weight=min_bootstrap_weight,
            )
        if action == "bootstrap_run_tournament":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            # Manager clamps rounds at 5000 (session_skills_bootstrap.py);
            # advertise the same upper bound so a caller sees the real cap.
            rounds = _bounded_int(args.get("rounds", 200), 200, min_value=1, max_value=5000)
            seed = _bounded_int(args.get("seed", 1337), 1337, min_value=0, max_value=2_147_483_647)
            return self._bootstrap_mgr_call(
                "run_tournament",
                sid,
                rounds=rounds,
                seed=seed,
            )
        if action == "bootstrap_compute_blend":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            if "session_samples" not in args:
                return make_error(MCPError.INVALID_ARGS, "session_samples required")
            session_samples = _bounded_int(
                args.get("session_samples"),
                0,
                min_value=0,
                max_value=100_000_000,
            )
            return self._bootstrap_mgr_call(
                "compute_blend",
                sid,
                session_samples=session_samples,
            )
        if action == "bootstrap_status":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            return self._bootstrap_mgr_call("status", sid)
        if action == "bootstrap_ingest_outcome":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            if "predicted" not in args:
                return make_error(MCPError.INVALID_ARGS, "predicted required")
            if "observed" not in args:
                return make_error(MCPError.INVALID_ARGS, "observed required")
            predicted, perr = _coerce_predicted01(args.get("predicted"))
            if perr:
                return perr
            observed, oerr = _coerce_observed01(args.get("observed"))
            if oerr:
                return oerr
            skill_id = str(args.get("skill_id") or "").strip() or None
            delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
            return self._bootstrap_mgr_call(
                "ingest_outcome",
                sid,
                predicted=predicted,
                observed=observed,
                skill_id=skill_id,
                delay_seconds=delay_seconds,
            )
        if action == "bootstrap_open_dispute":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            claim_id = str(args.get("claim_id") or "").strip()
            reason = str(args.get("reason") or "").strip()
            if not claim_id:
                return make_error(MCPError.INVALID_ARGS, "claim_id required")
            if not reason:
                return make_error(MCPError.INVALID_ARGS, "reason required")
            if "predicted" not in args:
                return make_error(MCPError.INVALID_ARGS, "predicted required")
            predicted, perr = _coerce_predicted01(args.get("predicted"))
            if perr:
                return perr
            skill_id = str(args.get("skill_id") or "").strip() or None
            return self._bootstrap_mgr_call(
                "open_dispute",
                sid,
                claim_id=claim_id,
                predicted=predicted,
                reason=reason,
                skill_id=skill_id,
            )
        if action == "bootstrap_list_disputes":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            status = str(args.get("status") or "").strip() or None
            return self._bootstrap_mgr_call("list_disputes", sid, status=status)
        if action == "bootstrap_resolve_dispute":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            dispute_id = str(args.get("dispute_id") or "").strip()
            if not dispute_id:
                return make_error(MCPError.INVALID_ARGS, "dispute_id required")
            if "observed" not in args:
                return make_error(MCPError.INVALID_ARGS, "observed required")
            observed, oerr = _coerce_observed01(args.get("observed"))
            if oerr:
                return oerr
            delay_seconds = _bounded_int(args.get("delay_seconds", 0), 0, min_value=0, max_value=31_536_000)
            return self._bootstrap_mgr_call(
                "resolve_dispute",
                sid,
                dispute_id=dispute_id,
                observed=observed,
                delay_seconds=delay_seconds,
            )
        if action == "bootstrap_summary":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            return self._bootstrap_mgr_call("summary", sid)
        if action == "bootstrap_snapshot":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            name = str(args.get("name") or "").strip()
            return self._bootstrap_mgr_call("snapshot", sid, name=name)
        if action == "bootstrap_list_snapshots":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            limit = _bounded_int(args.get("limit", 50), 50, min_value=1, max_value=1000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self._bootstrap_mgr_call(
                "list_snapshots",
                sid,
                limit=limit,
                offset=offset,
            )
        if action == "bootstrap_drift_report":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=1000)
            return self._bootstrap_mgr_call("drift_report", sid, window=window)
        if action == "bootstrap_simulate_batch":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            # Simulated outcomes are persisted to the bootstrap lab, so this is
            # a mutating action on the target session and needs the ownership
            # guard just like bootstrap_ingest_outcome.
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            # Manager clamps n at 20000 (session_skills_bootstrap.py);
            # advertise the same upper bound so a caller sees the real cap.
            n = _bounded_int(args.get("n", 500), 500, min_value=1, max_value=20000)
            seed = _bounded_int(args.get("seed", 2026), 2026, min_value=0, max_value=2_147_483_647)
            positive_rate = args.get("positive_rate", 0.5)
            try:
                positive_rate = float(positive_rate)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "positive_rate must be numeric")
            return self._bootstrap_mgr_call(
                "simulate_batch",
                sid,
                n=n,
                seed=seed,
                positive_rate=positive_rate,
            )
        if action == "bootstrap_prune_data":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            max_outcomes = _bounded_int(args.get("max_outcomes", 1000), 1000, min_value=1, max_value=200000)
            max_disputes = _bounded_int(args.get("max_disputes", 500), 500, min_value=1, max_value=50000)
            max_snapshots = _bounded_int(args.get("max_snapshots", 2000), 2000, min_value=1, max_value=100000)
            return self._bootstrap_mgr_call(
                "prune_data",
                sid,
                max_outcomes=max_outcomes,
                max_disputes=max_disputes,
                max_snapshots=max_snapshots,
            )
        if action == "bootstrap_export_metrics":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            status = str(args.get("status") or "all").strip().lower()
            since = str(args.get("since") or "").strip()
            until = str(args.get("until") or "").strip()
            limit = _bounded_int(args.get("limit", 5000), 5000, min_value=1, max_value=200000)
            return self._bootstrap_mgr_call(
                "export_metrics",
                sid,
                status=status,
                since=since,
                until=until,
                limit=limit,
            )
        if action == "bootstrap_summary_detailed":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            top_policies = _bounded_int(args.get("top_policies", 10), 10, min_value=1, max_value=50)
            return self._bootstrap_mgr_call("summary_detailed", sid, top_policies=top_policies)
        if action == "bootstrap_calibration_report":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            min_bin_n = _bounded_int(args.get("min_bin_n", 20), 20, min_value=1, max_value=1000000)
            return self._bootstrap_mgr_call("calibration_report", sid, min_bin_n=min_bin_n)
        if action == "bootstrap_update_baseline":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            window = _bounded_int(args.get("window", 50), 50, min_value=5, max_value=10000)
            percentile = args.get("percentile", 95.0)
            try:
                percentile = float(percentile)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "percentile must be numeric")
            return self._bootstrap_mgr_call(
                "update_baseline",
                sid,
                window=window,
                percentile=percentile,
            )
        if action == "bootstrap_evaluate_alerts":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            return self._bootstrap_mgr_call("evaluate_alerts", sid, window=window)
        if action == "bootstrap_mitigation_plan":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            return self._bootstrap_mgr_call("mitigation_plan", sid, window=window)
        if action == "bootstrap_apply_mitigation":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            max_actions = _bounded_int(args.get("max_actions", 4), 4, min_value=1, max_value=10)
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self._bootstrap_mgr_call(
                "apply_mitigation",
                sid,
                window=window,
                max_actions=max_actions,
                dry_run=dry_run,
            )
        if action == "bootstrap_mitigation_history":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self._bootstrap_mgr_call(
                "mitigation_history",
                sid,
                limit=limit,
                offset=offset,
            )
        if action == "bootstrap_mitigation_effectiveness":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 50), 50, min_value=1, max_value=10000)
            return self._bootstrap_mgr_call("mitigation_effectiveness", sid, window=window)
        if action == "bootstrap_policy_reweight":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            # Rewrites policy weights (and persists when dry_run=False), so it
            # needs the ownership guard like every other mutating bootstrap
            # action even though it also supports a dry-run read.
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            max_shift = args.get("max_shift", 0.08)
            try:
                max_shift = float(max_shift)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "max_shift must be numeric")
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self._bootstrap_mgr_call(
                "policy_reweight",
                sid,
                window=window,
                max_shift=max_shift,
                dry_run=dry_run,
            )
        if action == "bootstrap_policy_reweight_history":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self._bootstrap_mgr_call(
                "policy_reweight_history",
                sid,
                limit=limit,
                offset=offset,
            )
        if action == "bootstrap_autopilot":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            window = _bounded_int(args.get("window", 20), 20, min_value=2, max_value=10000)
            dry_run = _coerce_bool(args.get("dry_run"), False)
            return self._bootstrap_mgr_call("autopilot", sid, window=window, dry_run=dry_run)
        if action == "bootstrap_set_autopilot_policy":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            cooldown_seconds = _bounded_int(args.get("cooldown_seconds", 300), 300, min_value=0, max_value=86400)
            daily_budget = _bounded_int(args.get("daily_budget", 100), 100, min_value=1, max_value=100000)
            max_live_actions = _bounded_int(args.get("max_live_actions", 4), 4, min_value=1, max_value=10)
            rollback_on_regression = _coerce_bool(args.get("rollback_on_regression"), True)
            return self._bootstrap_mgr_call(
                "set_autopilot_policy",
                sid,
                cooldown_seconds=cooldown_seconds,
                daily_budget=daily_budget,
                max_live_actions=max_live_actions,
                rollback_on_regression=rollback_on_regression,
            )
        if action == "bootstrap_get_autopilot_policy":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            return self._bootstrap_mgr_call("get_autopilot_policy", sid)
        if action == "bootstrap_rollback_last_reweight":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            return self._bootstrap_mgr_call("rollback_last_reweight", sid)
        if action == "bootstrap_plan_status":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            return self._bootstrap_mgr_call("plan_status", sid)
        if action == "bootstrap_readiness_gate":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            min_tournament_rounds = _bounded_int(args.get("min_tournament_rounds", 1000), 1000, min_value=1, max_value=1_000_000)
            min_snapshots = _bounded_int(args.get("min_snapshots", 10), 10, min_value=1, max_value=100_000)
            min_outcomes = _bounded_int(args.get("min_outcomes", 200), 200, min_value=1, max_value=1_000_000)
            max_open_disputes = _bounded_int(args.get("max_open_disputes", 25), 25, min_value=0, max_value=100_000)
            max_ece = args.get("max_ece", 0.2)
            try:
                max_ece = float(max_ece)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "max_ece must be numeric")
            return self._bootstrap_mgr_call(
                "readiness_gate",
                sid,
                min_tournament_rounds=min_tournament_rounds,
                min_snapshots=min_snapshots,
                min_outcomes=min_outcomes,
                max_ece=max_ece,
                max_open_disputes=max_open_disputes,
            )
        if action == "bootstrap_record_readiness":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            tag = str(args.get("tag") or "").strip()
            return self._bootstrap_mgr_call("record_readiness", sid, tag=tag)
        if action == "bootstrap_readiness_history":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=5000)
            offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=1_000_000)
            return self._bootstrap_mgr_call(
                "readiness_history",
                sid,
                limit=limit,
                offset=offset,
            )
        if action == "bootstrap_readiness_trend":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            return self._bootstrap_mgr_call("readiness_trend", sid, window=window)
        if action == "bootstrap_readiness_regression_guard":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            window = _bounded_int(args.get("window", 50), 50, min_value=2, max_value=10000)
            auto_snapshot = _coerce_bool(args.get("auto_snapshot"), True)
            return self._bootstrap_mgr_call(
                "readiness_regression_guard",
                sid,
                window=window,
                auto_snapshot=auto_snapshot,
            )
        if action == "bootstrap_finalize_report":
            sid, sid_err = self._require_session_sid(args)
            if sid_err:
                return sid_err
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            trend_window = _bounded_int(args.get("trend_window", 50), 50, min_value=2, max_value=10000)
            effectiveness_window = _bounded_int(args.get("effectiveness_window", 50), 50, min_value=1, max_value=10000)
            return self._bootstrap_mgr_call(
                "finalize_report",
                sid,
                trend_window=trend_window,
                effectiveness_window=effectiveness_window,
            )

        return None
