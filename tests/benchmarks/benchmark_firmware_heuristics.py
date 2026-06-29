#!/usr/bin/env python3
"""Microbenchmarks for firmware heuristic primitives."""

import os
import random
import statistics
import time

from tests._isolated_repo_loader import load_support_module

_fw_heuristics = load_support_module("firmware_heuristics")
aggregate_fingerprint_scores = _fw_heuristics.aggregate_fingerprint_scores
apply_fingerprint_boost = _fw_heuristics.apply_fingerprint_boost
ascii_run_stats = _fw_heuristics.ascii_run_stats
build_campaign_execution_plan = _fw_heuristics.build_campaign_execution_plan
build_carve_plan = _fw_heuristics.build_carve_plan
cluster_pointer_hits = _fw_heuristics.cluster_pointer_hits
dedup_regions_by_fingerprint = _fw_heuristics.dedup_regions_by_fingerprint
rank_region_plans = _fw_heuristics.rank_region_plans
region_fingerprint = _fw_heuristics.region_fingerprint
region_priority_score = _fw_heuristics.region_priority_score
shannon_entropy = _fw_heuristics.shannon_entropy
summarize_campaign_regions = _fw_heuristics.summarize_campaign_regions


def _summ(name, samples):
    ms = [x * 1000 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(f"{name:<34} mean={statistics.mean(ms):8.3f} ms median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms")


def bench_entropy(rounds=1000):
    data = bytes(i % 251 for i in range(1 << 16))
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        shannon_entropy(hist, len(data))
        samples.append(time.perf_counter() - t0)
    _summ("entropy", samples)


def bench_ascii(rounds=1000):
    data = (b"A" * 32 + b"\x00" + b"B" * 48 + b"\x01\x02") * 200
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        ascii_run_stats(data, min_len=6)
        samples.append(time.perf_counter() - t0)
    _summ("ascii_run_stats", samples)


def bench_clusters(rounds=800):
    rng = random.Random(1337)
    hits = []
    ea = 0x1000
    for _ in range(4000):
        ea += rng.randint(4, 16)
        hits.append({"ea": ea, "value": 0x400000 + rng.randint(0, 0xFFFF), "score": rng.random()})
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        cluster_pointer_hits(hits, ptr_size=4, max_gap_entries=2)
        samples.append(time.perf_counter() - t0)
    _summ("cluster_pointer_hits", samples)


def bench_plan(rounds=20000):
    samples = []
    for i in range(rounds):
        t0 = time.perf_counter()
        build_carve_plan({"unknown_ratio": 0.4, "entropy": 6.8, "ascii_runs": i % 5}, ptr_count=10, table_count=3)
        samples.append(time.perf_counter() - t0)
    _summ("build_carve_plan", samples)


def bench_region_ranking(rounds=12000):
    items = []
    for i in range(256):
        profile = {
            "unknown_ratio": (i % 100) / 100.0,
            "entropy": 4.0 + ((i % 40) / 10.0),
            "pointer_density": (i % 25) / 50.0,
            "ascii_runs": i % 14,
        }
        plan = {"risk": "high" if i % 9 == 0 else ("medium" if i % 4 == 0 else "low")}
        items.append({
            "profile": profile,
            "plan": plan,
            "priority_score": region_priority_score(profile, plan, cluster_count=i % 12),
        })
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        rank_region_plans(items, limit=24)
        samples.append(time.perf_counter() - t0)
    _summ("rank_region_plans", samples)


def bench_campaign_summary_and_plan(rounds=12000):
    rows = []
    for i in range(64):
        rows.append(
            {
                "segment": f"seg{i}",
                "start": hex(0x1000 + i * 0x100),
                "end": hex(0x1000 + i * 0x100 + 0x80),
                "priority_score": 1.5 - (i / 100.0),
                "plan": {"risk": "high" if i % 7 == 0 else ("medium" if i % 3 == 0 else "low")},
            }
        )
    s_samples = []
    p_samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        summarize_campaign_regions(rows)
        s_samples.append(time.perf_counter() - t0)
        t1 = time.perf_counter()
        build_campaign_execution_plan(rows, max_steps=20)
        p_samples.append(time.perf_counter() - t1)
    _summ("summarize_campaign", s_samples)
    _summ("build_execution_plan", p_samples)


def bench_region_fingerprint_dedup(rounds=12000):
    rows = []
    for i in range(180):
        profile = {
            "entropy": 5.5 + (i % 20) * 0.1,
            "unknown_ratio": (i % 50) / 100.0,
            "pointer_density": (i % 12) / 20.0,
            "ascii_runs": i % 6,
        }
        plan = {"risk": "high" if i % 8 == 0 else "medium", "phases": [{"phase": "pointer-first"}]}
        rows.append({"segment": f"s{i%20}", "profile": profile, "plan": plan, "priority_score": 1.2 - i / 500.0})
        rows.append({"segment": f"s{i%20}", "profile": profile, "plan": plan, "priority_score": 1.0 - i / 500.0})
    f_samples = []
    d_samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        for r in rows[:32]:
            region_fingerprint(r)
        f_samples.append(time.perf_counter() - t0)
        t1 = time.perf_counter()
        dedup_regions_by_fingerprint(rows)
        d_samples.append(time.perf_counter() - t1)
    _summ("region_fingerprint(32)", f_samples)
    _summ("dedup_regions", d_samples)


def bench_fingerprint_aggregate(rounds=12000):
    rows = []
    for i in range(600):
        rows.append(
            {
                "fingerprint": f"fp_{i % 45}",
                "priority_score": 0.3 + (i % 20) * 0.04,
                "segment": f"seg{i % 10}",
                "start": hex(0x1000 + i * 8),
                "end": hex(0x1000 + i * 8 + 0x40),
            }
        )
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        aggregate_fingerprint_scores(rows, limit=24)
        samples.append(time.perf_counter() - t0)
    _summ("aggregate_fingerprint", samples)


def bench_fingerprint_boost(rounds=12000):
    regions = []
    for i in range(220):
        regions.append({"fingerprint": f"fp_{i%60}", "priority_score": 0.4 + (i % 30) * 0.03})
    fp_rank = [{"fingerprint": f"fp_{i}", "score": 0.6 + i * 0.02} for i in range(45)]
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        apply_fingerprint_boost(regions, fp_rank, boost_cap=0.35)
        samples.append(time.perf_counter() - t0)
    _summ("apply_fingerprint_boost", samples)


if __name__ == "__main__":
    print("=" * 72)
    print("Firmware Heuristic Benchmarks")
    print("=" * 72)
    bench_entropy()
    bench_ascii()
    bench_clusters()
    bench_plan()
    bench_region_ranking()
    bench_campaign_summary_and_plan()
    bench_region_fingerprint_dedup()
    bench_fingerprint_aggregate()
    bench_fingerprint_boost()
