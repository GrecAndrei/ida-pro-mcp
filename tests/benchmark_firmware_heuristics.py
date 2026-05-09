#!/usr/bin/env python3
"""Microbenchmarks for firmware heuristic primitives."""

import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools"))

from firmware_heuristics import (
    ascii_run_stats,
    build_carve_plan,
    cluster_pointer_hits,
    shannon_entropy,
)


def _summ(name, samples):
    ms = [x * 1000 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(f"{name:<34} mean={statistics.mean(ms):8.3f} ms median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms")


def bench_entropy(rounds=1000):
    data = bytes((i % 251 for i in range(1 << 16)))
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


if __name__ == "__main__":
    print("=" * 72)
    print("Firmware Heuristic Benchmarks")
    print("=" * 72)
    bench_entropy()
    bench_ascii()
    bench_clusters()
    bench_plan()
