# Bootstrap Implementation Status

This document maps the Evidence Physics Engine bootstrap plan to concrete implementation artifacts.

## Phase 1: Bootstrap Lab Core

- `session.bootstrap_init`
- `session.bootstrap_run_tournament`
- `session.bootstrap_compute_blend`
- `session.bootstrap_status`

## Phase 2: Integration into Scoring Paths

- `session.suggest_strategy` uses `blended_score`
- `predictor.suggest_next_tool` exposes `bootstrap_prior` and blended confidence

## Phase 3: Outcome and Dispute Lifecycle

- `session.bootstrap_ingest_outcome`
- `session.bootstrap_open_dispute`
- `session.bootstrap_list_disputes`
- `session.bootstrap_resolve_dispute`

## Phase 4: Observability and Drift Detection

- `session.bootstrap_summary`
- `session.bootstrap_summary_detailed`
- `session.bootstrap_calibration_report`
- `session.bootstrap_snapshot`
- `session.bootstrap_list_snapshots`
- `session.bootstrap_drift_report`
- `session.bootstrap_update_baseline`
- `session.bootstrap_evaluate_alerts`

## Phase 5: Mitigation and Control Loop

- `session.bootstrap_mitigation_plan`
- `session.bootstrap_apply_mitigation`
- `session.bootstrap_mitigation_history`
- `session.bootstrap_mitigation_effectiveness`

## Phase 6: Adaptation and Safeguards

- `session.bootstrap_policy_reweight`
- `session.bootstrap_policy_reweight_history`
- `session.bootstrap_autopilot`
- `session.bootstrap_set_autopilot_policy`
- `session.bootstrap_get_autopilot_policy`
- `session.bootstrap_rollback_last_reweight`

## Phase 7: Operations and Data Hygiene

- `session.bootstrap_export_metrics`
- `session.bootstrap_prune_data`
- `session.bootstrap_simulate_batch`

## Phase 8: Plan Governance and Auditability

- `session.bootstrap_plan_status`
- `docs/BOOTSTRAP_IMPLEMENTATION_STATUS.md`

## Validation Artifacts

- Tests: `tests/test_evidence_bootstrap.py`
- Benchmarks: `tests/benchmark_evidence_bootstrap.py`
