#!/usr/bin/env python3
"""Microbenchmarks for adaptive intelligence enrichment paths."""

import time
import statistics

from tests._isolated_repo_loader import load_host_module

ContextAssembler = load_host_module("intelligence.context").ContextAssembler


def _summ(name, samples):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(
        f"{name:<34} mean={statistics.mean(ms):8.3f} ms "
        f"median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms"
    )


def benchmark_focus_candidates(rounds=1000):
    asm = ContextAssembler()
    pack = {
        "related_findings": [{"id": "r1", "confidence": 0.9}],
        "structural": {"entropy": 6.8, "xor_count": 5, "cyclomatic_complexity": 22},
        "api_calls": ["VirtualAllocEx", "WriteProcessMemory"],
    }
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        asm._derive_focus_candidates(pack, "0x401000", "bench-focus")
        samples.append(time.perf_counter() - t0)
    _summ("focus candidate ranking", samples)


if __name__ == "__main__":
    print("=" * 72)
    print("Adaptive Intelligence Benchmarks")
    print("=" * 72)
    benchmark_focus_candidates(1200)
