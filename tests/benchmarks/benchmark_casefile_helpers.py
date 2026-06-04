#!/usr/bin/env python3
"""Microbenchmarks for casefile helper surfaces."""

import os
import statistics
import time

from tests._isolated_repo_loader import load_host_module

_casefile_helpers = load_host_module("casefile_helpers")
build_chain_of_custody = _casefile_helpers.build_chain_of_custody
build_risk_summary = _casefile_helpers.build_risk_summary
to_markdown_casefile = _casefile_helpers.to_markdown_casefile


def _summ(name, samples):
    ms = [x * 1000 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(f"{name:<28} mean={statistics.mean(ms):8.3f} ms median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms")


def bench_risk(rounds=10000):
    findings = [{"title": "Process injection", "tags": ["dangerous"], "evidence": [{"x": 1}]} for _ in range(150)]
    hyps = [{"status": "unknown"} for _ in range(120)]
    ai = [{"approved": False} for _ in range(80)]
    s = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        build_risk_summary(findings, hyps, ai)
        s.append(time.perf_counter() - t0)
    _summ("build_risk_summary", s)


def bench_chain(rounds=5000):
    sessions = [{"session_id": f"s{i}", "created_at": f"2026-01-01T00:{i%60:02d}:00", "binary_path": "a.bin"} for i in range(200)]
    replay = [{"timestamp": f"2026-01-01T01:{i%60:02d}:00", "tool": "code", "action_name": "decompile"} for i in range(1200)]
    ai = [{"timestamp": f"2026-01-01T02:{i%60:02d}:00", "reviewer": "alice", "target": "fn", "approved": bool(i % 2)} for i in range(900)]
    s = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        build_chain_of_custody(sessions, replay, ai)
        s.append(time.perf_counter() - t0)
    _summ("build_chain_of_custody", s)


def bench_markdown(rounds=20000):
    payload = {
        "generated_at": "2026-01-01T00:00:00",
        "summary": {"sessions": 1, "findings": 20, "hypotheses": 10, "ai_records": 5},
        "risk_summary": {"risk_level": "medium", "high_risk_findings": 4, "knowledge_debt_index": 12},
        "integrity": {"sha256": "abc"},
    }
    s = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        to_markdown_casefile(payload)
        s.append(time.perf_counter() - t0)
    _summ("to_markdown_casefile", s)


if __name__ == "__main__":
    print("=" * 64)
    print("Casefile Helper Benchmarks")
    print("=" * 64)
    bench_risk()
    bench_chain()
    bench_markdown()
