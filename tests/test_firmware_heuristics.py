import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools"))

from firmware_heuristics import (
    ascii_run_stats,
    build_carve_plan,
    cluster_pointer_hits,
    shannon_entropy,
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
