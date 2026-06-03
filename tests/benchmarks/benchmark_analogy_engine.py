#!/usr/bin/env python3
"""Performance benchmarks for CrossBinaryAnalogyEngine."""

from __future__ import annotations

import os
import sys
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.intelligence.analogy import CrossBinaryAnalogyEngine


def _summ(name, samples):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(
        f"{name:<34} mean={statistics.mean(ms):8.3f} ms "
        f"median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms"
    )


def benchmark_analogy_score_calculation(rounds=10000):
    # Two identical functions (perfect candidate)
    attrs_a = {
        "size": 100,
        "bb_count": 5,
        "cyclomatic_complexity": 3,
        "api_count": 1,
        "xor_ratio": 0.1,
    }
    attrs_b = {
        "size": 100,
        "bb_count": 5,
        "cyclomatic_complexity": 3,
        "api_count": 1,
        "xor_ratio": 0.1,
    }
    vec_a = [1.0] + [0.0] * 1535
    vec_b = [1.0] + [0.0] * 1535

    # Match case (requires cheap structure check + expensive cosine dot product)
    samples_match = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _ = CrossBinaryAnalogyEngine.compute_analogy_score(
            attrs_a, attrs_b, vec_a, vec_b
        )
        samples_match.append(time.perf_counter() - t0)

    # Highly mismatched functions (pruned instantly by structural early-out)
    attrs_mismatch = {
        "size": 1000,
        "bb_count": 50,
        "cyclomatic_complexity": 25,
        "api_count": 10,
        "xor_ratio": 0.9,
    }

    samples_mismatch = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _ = CrossBinaryAnalogyEngine.compute_analogy_score(
            attrs_a, attrs_mismatch, vec_a, vec_b
        )
        samples_mismatch.append(time.perf_counter() - t0)

    _summ("analogy score match", samples_match)
    _summ("analogy score mismatch", samples_mismatch)


if __name__ == "__main__":
    print("=" * 72)
    print("Cross-Binary Analogy Engine Benchmarks")
    print("=" * 72)
    benchmark_analogy_score_calculation(20000)
