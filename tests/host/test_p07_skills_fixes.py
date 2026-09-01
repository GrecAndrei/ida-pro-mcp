"""Regression tests for p07_skills audit fixes.

Covers:
- bootstrap_plan_status no longer counts non-existent blended-strategy methods
  as implemented (inflating coverage and the readiness gate).
- rate_skill no longer raises KeyError on skills lacking success/failure
  counters (loaded from arbitrary on-disk skills.json / session merges).
- _detect_dead_end reduces persisted JSON result blobs to scalar function /
  query identities instead of comparing and returning whole serialized dicts.
- bootstrap_evaluate_alerts honors the auto-baseline-update result instead of
  reporting enough_data on default thresholds when no real baseline exists.
- bootstrap_simulate_batch preserves bounded-history semantics while skipping
  per-outcome list slicing / timestamps.
- bootstrap_snapshot error hint references a reachable action, not a
  non-existent 'skills' tool.
"""

import json
import os

from ida_pro_mcp.host.server.session import Session, SessionManager
from ida_pro_mcp.host.server.session_skills import _activity_result_scalar

_PHANTOM_PLAN_ITEMS = ("suggest_strategy_blended", "predictor_suggest_next_tool_blended")


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


def _filler_entries(n):
    return [
        {"action": "list_functions", "result": json.dumps({"addresses": [], "target": "all"}), "tool": "data"}
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# F1: bootstrap_plan_status must not count phantom methods as implemented
# ---------------------------------------------------------------------------


def test_bootstrap_plan_status_omits_phantom_methods(tmp_path):
    """The plan matrix lists only implemented methods: the two never-built
    blended-strategy names are gone, so coverage reflects real methods only
    and the readiness gate can reach 100% (see f08 phantom-matrix fix)."""
    mgr, _ = _make_manager(tmp_path)
    plan = mgr.bootstrap_plan_status("SID_TEST")
    assert plan["ok"] is True
    overall = plan["overall"]
    # All listed plan items have a backing method -> 100% coverage.
    assert overall["items"] == 30
    assert overall["done"] == 30
    assert overall["coverage"] == 100.0

    phase2 = next(r for r in plan["phases"] if r["phase"] == "phase2_scoring_integration")
    assert phase2["done"] == 1
    # The dead names are no longer tracked (removed, not marked missing).
    assert not any(p in phase2["missing"] for p in _PHANTOM_PLAN_ITEMS)
    gate = mgr.bootstrap_readiness_gate("SID_TEST")
    assert gate["gates"]["phase_coverage_100"] is True


# ---------------------------------------------------------------------------
# F3: rate_skill must tolerate skills missing success/failure counters
# ---------------------------------------------------------------------------


def test_rate_skill_tolerates_missing_counters(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(
        mgr,
        {
            "skills": {"sk1": {"q_value": 0.3, "description": "x", "tags": []}},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    res = mgr.rate_skill("SID_TEST", "sk1", 0.8)
    assert res.get("ok") is True
    stored = mgr._load_skills("SID_TEST")["skills"]["sk1"]
    assert stored.get("success_count") == 1


def test_rate_skill_tolerates_missing_counters_negative_reward(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(
        mgr,
        {
            "skills": {"sk2": {"q_value": 0.3}},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    res = mgr.rate_skill("SID_TEST", "sk2", 0.0)
    assert res.get("ok") is True
    stored = mgr._load_skills("SID_TEST")["skills"]["sk2"]
    assert stored.get("failure_count") == 1


def test_load_skills_normalizes_valid_but_malformed_json(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(
        mgr,
        {
            "skills": {
                "good": {
                    "q_value": "nan",
                    "description": 123,
                    "tags": "firmware",
                    "success_count": "bad",
                },
                "discarded": ["not a skill"],
            },
            "q_table": {"good": "inf", "other": "0.8"},
            "activity_log": [{"action": "find"}, "not an entry"],
            "hypotheses": "not a list",
            "bootstrap": {"disputes": "not a list"},
        },
    )

    state = mgr._load_skills("SID_TEST")
    assert set(state["skills"]) == {"good"}
    assert state["skills"]["good"]["q_value"] == 0.5
    assert state["skills"]["good"]["description"] == "123"
    assert state["skills"]["good"]["tags"] == ["firmware"]
    assert state["skills"]["good"]["success_count"] == 0
    assert state["q_table"] == {"good": 0.5, "other": 0.8}
    assert state["activity_log"] == [{"action": "find"}]
    assert state["hypotheses"] == []
    assert state["bootstrap"]["disputes"] == []


def test_load_skills_rejects_non_object_root(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(mgr, ["valid json, wrong root type"])
    assert mgr._load_skills("SID_TEST") == {
        "skills": {}, "q_table": {}, "activity_log": [], "hypotheses": [],
    }


def test_load_skills_recovers_from_invalid_utf8(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    with open(mgr._get_skills_path("SID_TEST"), "wb") as handle:
        handle.write(b"\xff")
    assert mgr._load_skills("SID_TEST") == {
        "skills": {}, "q_table": {}, "activity_log": [], "hypotheses": [],
    }


# ---------------------------------------------------------------------------
# F4: _detect_dead_end reduces JSON result blobs to scalar identities
# ---------------------------------------------------------------------------


def test_activity_result_scalar_extracts_target_over_addresses():
    assert (
        _activity_result_scalar('{"addresses": ["0x401000"], "topic": "parse", "target": "0x401000"}')
        == "0x401000"
    )
    assert _activity_result_scalar('{"addresses": ["0x401000"], "target": "recv("}') == "recv("
    # Plain (non-JSON) results pass through unchanged.
    assert _activity_result_scalar("0x401000") == "0x401000"


def test_detect_dead_end_matches_same_function_across_different_addresses(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    log = _filler_entries(10) + [
        # Same target function, but a different result address per call — the
        # raw JSON blobs differ, so pre-fix matching escaped detection.
        {"action": "decompile", "result": json.dumps({"addresses": [hex(0x401000 + i)], "target": "0x401000"}), "tool": "code"}
        for i in range(6)
    ]
    warning = mgr._detect_dead_end(log)
    assert warning is not None
    assert warning["type"] == "repeated_decompile"
    # The returned identity is the scalar function name, not a JSON blob.
    assert warning["function"] == "0x401000"
    assert not warning["function"].startswith("{")


def test_detect_dead_end_matches_same_query_across_different_addresses(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    log = _filler_entries(10) + [
        {"action": "find", "result": json.dumps({"addresses": [hex(0x500000 + i)], "target": "recv("}), "tool": "data"}
        for i in range(4)
    ]
    warning = mgr._detect_dead_end(log)
    assert warning is not None
    assert warning["type"] == "repeated_search"
    assert warning["query"] == "recv("
    assert not warning["query"].startswith("{")


# ---------------------------------------------------------------------------
# F5: bootstrap_evaluate_alerts must not report enough_data on default baselines
# ---------------------------------------------------------------------------


def test_evaluate_alerts_reports_not_enough_data_when_no_real_baseline(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(
        mgr,
        {
            "bootstrap": {"metric_snapshots": [{"ece": 0.1} for _ in range(3)]},
            "skills": {},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    res = mgr.bootstrap_evaluate_alerts("SID_TEST", window=20)
    assert res.get("ok") is True
    assert res.get("enough_data") is False
    assert res.get("alerts") == []
    assert "5 snapshots" in res.get("message", "")

    # Downstream mitigation must therefore also decline to act.
    plan = mgr.bootstrap_mitigation_plan("SID_TEST", window=20)
    assert plan.get("enough_data") is False
    assert plan.get("actions") == []


def test_evaluate_alerts_still_works_with_real_baseline(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    snaps = [{"ece": 0.05, "prior_confidence": 0.7} for _ in range(6)]
    snaps.append({"ece": 0.3, "prior_confidence": 0.1})  # regression trigger
    _write_skills(
        mgr,
        {
            "bootstrap": {"metric_snapshots": snaps},
            "skills": {},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    res = mgr.bootstrap_evaluate_alerts("SID_TEST", window=20)
    assert res.get("enough_data") is True
    assert res.get("baseline")  # auto-baseline was established
    assert any(a["type"] == "ece_regression" for a in res.get("alerts", []))


# ---------------------------------------------------------------------------
# F7: bootstrap_simulate_batch keeps bounded-history semantics
# ---------------------------------------------------------------------------


def test_simulate_batch_bounds_outcomes_and_sets_timestamp(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    mgr.bootstrap_init("SID_TEST")
    res = mgr.bootstrap_simulate_batch("SID_TEST", n=1200, seed=7, positive_rate=0.5)
    assert res.get("ok") is True
    assert res.get("n") == 1200
    stored = mgr._load_skills("SID_TEST")
    outcomes = stored["bootstrap"]["outcomes"]
    assert len(outcomes) == 1000  # bounded, not grown to 1200
    assert stored["bootstrap"].get("updated_at")  # updated once after the loop
    assert all(o.get("skill_id") is None for o in outcomes)


# ---------------------------------------------------------------------------
# F9: bootstrap_snapshot hint references a reachable action
# ---------------------------------------------------------------------------


def test_snapshot_hint_references_reachable_action(tmp_path):
    mgr, _ = _make_manager(tmp_path)
    _write_skills(
        mgr,
        {"skills": {}, "q_table": {}, "activity_log": [], "hypotheses": []},
    )
    res = mgr.bootstrap_snapshot("SID_TEST")
    # Graceful uninitialized dict (matches bootstrap_status/summary), with a
    # hint that references a reachable action, not a non-existent tool.
    assert res.get("error") is not True
    assert res.get("initialized") is False
    hint = res.get("hint", "")
    assert "bootstrap_init" in hint
    assert "skills/session bootstrap tool" not in hint
