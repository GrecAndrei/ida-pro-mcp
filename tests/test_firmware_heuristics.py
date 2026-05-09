import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools"))

from firmware_heuristics import (
    ascii_run_stats,
    build_campaign_execution_plan,
    build_carve_plan,
    cluster_pointer_hits,
    rank_region_plans,
    region_priority_score,
    shannon_entropy,
    summarize_campaign_regions,
)


def test_entropy_low_for_uniform_data():
    hist = [0] * 256
    hist[0x41] = 100
    ent = shannon_entropy(hist, 100)
    assert ent < 0.1


def test_ascii_run_stats_detects_multiple_runs():
    data = b"AAAAAA\x00BBBBBBB\x00\x01\x02"
    st = ascii_run_stats(data, min_len=6)
    assert st["runs"] == 2
    assert st["longest"] >= 6


def test_cluster_pointer_hits_groups_contiguous_entries():
    hits = [
        {"ea": 0x1000, "value": 0x5000, "score": 0.9},
        {"ea": 0x1004, "value": 0x5004, "score": 0.85},
        {"ea": 0x1010, "value": 0x5010, "score": 0.8},
        {"ea": 0x2000, "value": 0x6000, "score": 0.7},
    ]
    clusters = cluster_pointer_hits(hits, ptr_size=4, max_gap_entries=3)
    assert clusters
    assert clusters[0]["entries"] >= 3


def test_build_carve_plan_reflects_signal_and_risk():
    plan = build_carve_plan(
        {"unknown_ratio": 0.6, "entropy": 7.4, "ascii_runs": 0},
        ptr_count=5,
        table_count=2,
    )
    assert plan["risk"] == "high"
    assert plan["phases"]
    assert any(p["phase"] == "pointer-first" for p in plan["phases"])


def test_region_priority_score_increases_with_risk_and_signal():
    low = region_priority_score(
        {"unknown_ratio": 0.1, "entropy": 4.2, "pointer_density": 0.05, "ascii_runs": 0},
        {"risk": "low"},
        cluster_count=0,
    )
    high = region_priority_score(
        {"unknown_ratio": 0.6, "entropy": 7.6, "pointer_density": 0.45, "ascii_runs": 3},
        {"risk": "high"},
        cluster_count=8,
    )
    assert high > low


def test_rank_region_plans_orders_by_priority_score():
    items = [
        {"priority_score": 0.4, "plan": {"entropy": 6.0}, "profile": {"unknown_ratio": 0.4}},
        {"priority_score": 1.1, "plan": {"entropy": 5.0}, "profile": {"unknown_ratio": 0.2}},
        {"priority_score": 0.8, "plan": {"entropy": 7.0}, "profile": {"unknown_ratio": 0.6}},
    ]
    out = rank_region_plans(items, limit=2)
    assert len(out) == 2
    assert out[0]["priority_score"] >= out[1]["priority_score"]


def test_summarize_campaign_regions_counts_risk_and_priority():
    rows = [
        {"priority_score": 1.2, "plan": {"risk": "high"}},
        {"priority_score": 0.6, "plan": {"risk": "medium"}},
        {"priority_score": 0.2, "plan": {"risk": "low"}},
    ]
    s = summarize_campaign_regions(rows)
    assert s["count"] == 3
    assert s["risk_counts"]["high"] == 1
    assert s["avg_priority"] > 0


def test_build_campaign_execution_plan_generates_staged_steps():
    rows = [
        {"segment": "TEXT", "start": "0x1000", "end": "0x1800", "priority_score": 1.1},
        {"segment": "DATA", "start": "0x2000", "end": "0x2800", "priority_score": 0.8},
    ]
    steps = build_campaign_execution_plan(rows, max_steps=5)
    assert steps
    assert steps[0]["action"] == "campaign"
    assert any(s.get("action") == "smart_carve" for s in steps)
