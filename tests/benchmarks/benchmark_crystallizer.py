#!/usr/bin/env python3
"""Performance benchmarks for AgentMacroCrystallizer."""

from __future__ import annotations

import os
import time
import statistics

from tests._isolated_repo_loader import load_host_module

AgentMacroCrystallizer = load_host_module("intelligence.crystallizer").AgentMacroCrystallizer


def _summ(name, samples):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(
        f"{name:<34} mean={statistics.mean(ms):8.3f} ms "
        f"median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms"
    )


def benchmark_step_reward_calculation(rounds=10000):
    step = {
        "tool": "blackboard",
        "action": "write",
        "result": "ok"
    }
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _ = AgentMacroCrystallizer.calculate_step_reward(step)
        samples.append(time.perf_counter() - t0)
    _summ("crystallizer step reward", samples)


def benchmark_sequence_mining(rounds=100):
    # Setup a realistic activity log of 200 entries with repeating pattern
    activity_log = []
    pattern = [
        {"tool": "search", "action": "api", "result": "ok"},
        {"tool": "code", "action": "xrefs_to", "result": "ok"},
        {"tool": "blackboard", "action": "write", "result": "ok"},
    ]
    for i in range(50):
        activity_log.extend(pattern)
        # Noise
        activity_log.append({"tool": "misc", "action": "python", "result": "ok"})
    
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _ = AgentMacroCrystallizer.mine_sequences(activity_log, min_support=2)
        samples.append(time.perf_counter() - t0)
    _summ("crystallizer sequence mining", samples)


if __name__ == "__main__":
    print("=" * 72)
    print("Agent Macro Crystallizer Benchmarks")
    print("=" * 72)
    benchmark_step_reward_calculation(10000)
    benchmark_sequence_mining(100)
