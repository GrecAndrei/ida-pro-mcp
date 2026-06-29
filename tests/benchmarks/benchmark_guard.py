#!/usr/bin/env python3
"""Lightweight benchmark guardrail for CI and local regression checks.

Runs selected benchmark scripts, parses mean latency lines, and fails if
critical metrics exceed configured thresholds.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Dict, Tuple

LINE_RE = re.compile(r"^(?P<name>[^=]+?)\s+mean=\s*(?P<mean>[0-9.]+)\s*ms", re.MULTILINE)


def parse_means(output: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for m in LINE_RE.finditer(output):
        name = m.group("name").strip()
        out[name] = float(m.group("mean"))
    return out


def run_benchmark(script: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def threshold(name: str, default: float) -> float:
    key = f"IDA_MCP_BENCH_{name.upper().replace(' ', '_').replace('-', '_')}"
    val = os.environ.get(key)
    if not val:
        return default
    try:
        return float(val)
    except Exception:
        return default


def main() -> int:
    checks = [
        {
            "script": "tests/benchmarks/benchmark_intelligence_adaptive.py",
            "limits": {
                "semantic cached": threshold("semantic_cached", 1.5),
                "focus candidate ranking": threshold("focus_candidate_ranking", 0.08),
            },
        },
        {
            "script": "tests/benchmarks/benchmark_firmware_heuristics.py",
            "limits": {
                "cluster_pointer_hits": threshold("cluster_pointer_hits", 20.0),
                "dedup_regions": threshold("dedup_regions", 9.0),
                "aggregate_fingerprint": threshold("aggregate_fingerprint", 6.0),
            },
        },
        {
            "script": "tests/benchmarks/benchmark_analogy_engine.py",
            "limits": {
                "analogy score match": threshold("analogy_score_match", 0.8),
                "analogy score mismatch": threshold("analogy_score_mismatch", 0.05),
            },
        },
    ]

    failed = []
    for chk in checks:
        rc, out, err = run_benchmark(chk["script"])
        if rc != 0:
            print(f"[FAIL] {chk['script']} exited with {rc}")
            if err:
                print(err)
            failed.append((chk["script"], "process_error"))
            continue
        means = parse_means(out)
        print(f"[OK] {chk['script']} parsed {len(means)} metrics")
        for metric, limit_ms in chk["limits"].items():
            if metric not in means:
                print(f"[FAIL] missing metric: {metric}")
                failed.append((chk["script"], f"missing:{metric}"))
                continue
            val = means[metric]
            if val > limit_ms:
                print(f"[FAIL] {metric}: {val:.3f} ms > {limit_ms:.3f} ms")
                failed.append((chk["script"], f"slow:{metric}"))
            else:
                print(f"[PASS] {metric}: {val:.3f} ms <= {limit_ms:.3f} ms")

    if failed:
        print(f"\nBenchmark guard failed ({len(failed)} issues)")
        return 2
    print("\nBenchmark guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
