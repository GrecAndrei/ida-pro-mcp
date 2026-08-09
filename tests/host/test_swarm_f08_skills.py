"""Regression tests for the f08_skills swarm finding wave.

Covers:
- The bootstrap plan matrix lists only implemented methods, so the readiness
  gate / finalize report can reach a positive outcome (phantom-matrix fix).
- _save_skills pid-scopes its temp file like every sibling durable writer.
- log_activity respects the metadata persist throttle and no longer runs the
  discarded dead-end detector on the hot path.
- suggest_triage bounds a caller-controlled limit before it is multiplied
  into an embedding-index top_k query.
- bootstrap_run_tournament / bootstrap_simulate_batch bound their work so a
  single session action cannot hold the SessionManager-wide lock for seconds.
- bootstrap_export_metrics rejects malformed since/until instead of silently
  dropping the filter.
- bootstrap_apply_mitigation returns an error envelope on non-numeric stored
  params instead of raising.
- bootstrap_snapshot returns a graceful uninitialized dict instead of the
  semantically-wrong NOT_IMPLEMENTED.
"""

import copy
import json
import os

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import Session, SessionManager


def _make_manager(tmp_path):
    mgr = SessionManager(str(tmp_path))
    session = Session("SID_TEST", idb_path="/tmp/test.i64", binary_path="/tmp/test")
    mgr.sessions["SID_TEST"] = session
    path = mgr._get_skills_path("SID_TEST")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return mgr, session


def _write_skills(mgr, data):
    with open(mgr._get_skills_path("SID_TEST"), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _ready_bootstrap() -> dict:
    """A fully-populated bootstrap lab that satisfies every readiness gate."""
    bins = {str(i): {"n": 10, "sum_pred": 5.0, "sum_obs": 5.0} for i in range(10)}
    policies = {}
    for i in range(1, 13):
        policies[f"p{i:02d}"] = {
            "name": f"Policy {i}",
            "weights": [0.25, 0.25, 0.25, 0.25],
            "bias": 0.0,
            "noise": 0.03,
            "rating": 1500.0,
            "samples": 100,
            "brier_sum": 5.0,
            "calibration_bins": copy.deepcopy(bins),
        }
    snapshots = [
        {
            "snapshot_id": f"bsnap_{i + 1:02d}",
            "name": None,
            "timestamp": f"2026-01-{i + 1:02d}T00:00:00",
            "prior_confidence": 0.8,
            "ece": 0.05,
            "outcomes": 300,
            "open_disputes": 0,
            "resolved_disputes": 0,
            "tournament_runs": 2,
            "total_rounds": 1500,
        }
        for i in range(12)
    ]
    outcomes = [
        {
            "timestamp": f"2026-01-01T00:{i % 60:02d}:00",
            "predicted": 0.5,
            "observed": 1,
            "brier": 0.25,
            "skill_id": None,
            "delay_seconds": 0,
        }
        for i in range(300)
    ]
    # A single mitigation row where severity improved: effectiveness = strong.
    mitigation_history = [
        {
            "timestamp": "2026-01-02T00:00:00",
            "window": 50,
            "plan_severity": "high",
            "post_severity": "none",
            "actions_requested": 2,
            "executed_ok": 2,
            "executed_total": 2,
            "pre_alerts": 3,
            "post_alerts": 0,
        }
    ]
    return {
        "version": 1,
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-02T00:00:00",
        "decay_lambda": 0.03,
        "min_bootstrap_weight": 0.1,
        "tournament_runs": 2,
        "total_rounds": 1500,
        "policies": policies,
        "history": [],
        "metric_snapshots": snapshots,
        "outcomes": outcomes,
        "disputes": [],
        "mitigation_history": mitigation_history,
    }


def _write_ready_skills(mgr):
    _write_skills(
        mgr,
        {"skills": {}, "q_table": {}, "activity_log": [], "hypotheses": [], "bootstrap": _ready_bootstrap()},
    )


# ---------------------------------------------------------------------------
# Phantom plan matrix / readiness gate reaching a positive outcome
# ---------------------------------------------------------------------------


def test_plan_matrix_lists_only_implemented_methods(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    plan = mgr.bootstrap_plan_status("SID_TEST")
    assert plan["ok"] is True
    assert plan["overall"]["coverage"] == 100.0
    for phase in plan["phases"]:
        assert phase["missing"] == []


def test_readiness_gate_reaches_production_ready(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_ready_skills(mgr)
    gate = mgr.bootstrap_readiness_gate("SID_TEST")
    assert gate["ok"] is True
    assert gate["readiness"] is True
    assert gate["stage"] == "production_ready"
    assert gate["gates"]["phase_coverage_100"] is True
    assert gate["failed"] == []


def test_finalize_report_can_reach_stage_ready(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_ready_skills(mgr)
    report = mgr.bootstrap_finalize_report("SID_TEST")
    assert report["ok"] is True
    assert report["release_ready"] is True
    assert report["stage"] == "ready"
    assert report["risk_flags"] == []


# ---------------------------------------------------------------------------
# _save_skills temp-file atomicity / pid scoping
# ---------------------------------------------------------------------------


def test_save_skills_uses_pid_scoped_tmp(tmp_path, monkeypatch):
    mgr, _ = _make_manager(tmp_path)
    real_replace = os.replace
    replaced = []

    def _spy(src, dst):
        replaced.append((src, dst))
        return real_replace(src, dst)

    data = {"skills": {}, "q_table": {}, "activity_log": [], "hypotheses": []}
    # Confine the os.replace spy to the _save_skills call only — a global
    # patch breaks sqlite3 (used by SessionManager.__init__).
    with monkeypatch.context() as m:
        m.setattr(os, "replace", _spy)
        mgr._save_skills("SID_TEST", data)
    path = mgr._get_skills_path("SID_TEST")
    assert replaced
    src, dst = replaced[-1]
    assert src == f"{path}.{os.getpid()}.tmp"
    assert dst == path
    # No non-pid tmp is ever created, and no stale tmp survives the write.
    assert not os.path.exists(path + ".tmp")
    with open(path, encoding="utf-8") as f:
        assert json.load(f) == data


# ---------------------------------------------------------------------------
# log_activity hot-path behavior
# ---------------------------------------------------------------------------


def test_log_activity_respects_metadata_throttle(tmp_path, monkeypatch):
    mgr, _ = _make_manager(tmp_path)
    real = mgr._save_metadata
    calls = []
    monkeypatch.setattr(mgr, "_save_metadata", lambda s: (calls.append(s), real(s))[1])
    mgr.log_activity("SID_TEST", tool="data", action="list_functions", result='{"target": "all"}')
    mgr.log_activity("SID_TEST", tool="data", action="list_functions", result='{"target": "all"}')
    # Second call lands inside the 60s _maybe_persist_access throttle window.
    assert len(calls) == 1


def test_log_activity_no_longer_emits_discarded_dead_end_warning(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    result = json.dumps({"addresses": ["0x401000"], "target": "0x401000"})
    for _ in range(13):
        mgr.log_activity("SID_TEST", tool="code", action="decompile", result=result)
    out = mgr.log_activity("SID_TEST", tool="code", action="decompile", result=result)
    assert out == {"ok": True}
    assert "dead_end_warning" not in out
    # The detector utility itself still works (it has its own tests).
    stored = mgr._load_skills("SID_TEST")["activity_log"]
    assert mgr._detect_dead_end(stored) is not None


# ---------------------------------------------------------------------------
# suggest_triage limit bounding
# ---------------------------------------------------------------------------


def test_suggest_triage_clamps_caller_limit(tmp_path, monkeypatch):
    import ida_pro_mcp.host.intelligence.context as ctx

    captured = {}

    class _FakeAsm:
        def suggest_next_targets(self, idb_path, limit=5):
            captured["limit"] = limit
            return []

    monkeypatch.setattr(ctx, "get_assembler", _FakeAsm)
    mgr, _ = _make_manager(tmp_path)
    res = mgr.suggest_triage("SID_TEST", context="find crypto", limit=100000)
    assert res.get("ok") is True
    assert res.get("limit") == 50
    assert captured["limit"] == 50


# ---------------------------------------------------------------------------
# Lock-hold bounding for tournament / simulate_batch
# ---------------------------------------------------------------------------


def test_bootstrap_run_tournament_bounds_lock_hold_rounds(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    mgr.bootstrap_init("SID_TEST")
    res = mgr.bootstrap_run_tournament("SID_TEST", rounds=50000, seed=42)
    assert res.get("ok") is True
    assert res["rounds"] == 5000


def test_bootstrap_simulate_batch_bounds_lock_hold_n(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    mgr.bootstrap_init("SID_TEST")
    res = mgr.bootstrap_simulate_batch("SID_TEST", n=200000, seed=42, positive_rate=0.5)
    assert res.get("ok") is True
    assert res["n"] == 20000


# ---------------------------------------------------------------------------
# bootstrap_export_metrics timestamp validation
# ---------------------------------------------------------------------------


def test_bootstrap_export_metrics_rejects_malformed_since(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    res = mgr.bootstrap_export_metrics("SID_TEST", since="2026-13-40")
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


def test_bootstrap_export_metrics_rejects_malformed_until(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    res = mgr.bootstrap_export_metrics("SID_TEST", until="not-a-date")
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# bootstrap_apply_mitigation defensive param coercion
# ---------------------------------------------------------------------------


def test_bootstrap_apply_mitigation_rejects_non_numeric_params(tmp_path, monkeypatch):
    mgr, _ = _make_manager(tmp_path)
    mgr.bootstrap_init("SID_TEST")

    def _bad_plan(sid, window=20):
        return {
            "ok": True,
            "enough_data": True,
            "severity": "high",
            "alerts": [],
            "actions": [
                {
                    "priority": 1,
                    "action": "bootstrap_run_tournament",
                    "params": {"rounds": "many"},
                    "reason": "x",
                }
            ],
        }

    monkeypatch.setattr(mgr, "bootstrap_mitigation_plan", _bad_plan)
    res = mgr.bootstrap_apply_mitigation("SID_TEST")
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# bootstrap_snapshot uninitialized handling
# ---------------------------------------------------------------------------


def test_bootstrap_snapshot_returns_graceful_uninitialized(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    res = mgr.bootstrap_snapshot("SID_TEST")
    assert res.get("ok") is True
    assert res.get("initialized") is False
    assert res.get("snapshot") is None
    assert res.get("error") is not True
    assert "bootstrap_init" in (res.get("hint") or "")
