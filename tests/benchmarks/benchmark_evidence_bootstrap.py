#!/usr/bin/env python3
"""Benchmarks for Evidence Physics bootstrap calibration pipeline."""
import os
import time
import tempfile
import shutil
import statistics

from tests._isolated_repo_loader import load_package_module, load_repo_module

load_package_module("host")
_stdio_mod = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
SessionManager = _stdio_mod.SessionManager
IDAMCPServer = _stdio_mod.IDAMCPServer


def _setup():
    tmpdir = tempfile.mkdtemp()
    mgr = SessionManager(tmpdir)
    binary = os.path.join(tmpdir, "bench.bin")
    with open(binary, "wb") as f:
        f.write(b"\x00" * 512)
    sess = mgr.create_session(binary)
    return tmpdir, mgr, sess.session_id


def _summarize(name, samples):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99_idx = max(0, min(len(ms_sorted) - 1, int(0.99 * (len(ms_sorted) - 1))))
    print(
        f"{name:<34} mean={statistics.mean(ms):8.3f} ms  "
        f"median={statistics.median(ms):8.3f} ms  "
        f"p99={ms_sorted[p99_idx]:8.3f} ms"
    )


def benchmark_bootstrap_init(rounds=100):
    tmpdir, mgr, sid = _setup()
    try:
        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            mgr.bootstrap_init(sid, overwrite=True)
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_init(overwrite=True)", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_tournament(rounds_per_run=500, runs=40):
    tmpdir, mgr, sid = _setup()
    try:
        mgr.bootstrap_init(sid, overwrite=True)
        samples = []
        for i in range(runs):
            t0 = time.perf_counter()
            mgr.bootstrap_run_tournament(sid, rounds=rounds_per_run, seed=1337 + i)
            samples.append(time.perf_counter() - t0)
        _summarize(f"bootstrap_run_tournament({rounds_per_run})", samples)
        total_rounds = rounds_per_run * runs
        total_time = sum(samples)
        print(f"{'tournament throughput':<34} {total_rounds / max(total_time, 1e-9):8.1f} rounds/sec")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_blend_compute(rounds=50000):
    tmpdir, mgr, sid = _setup()
    try:
        mgr.bootstrap_init(sid, overwrite=True)
        samples = []
        for i in range(rounds):
            t0 = time.perf_counter()
            mgr.bootstrap_compute_blend(sid, session_samples=i)
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_compute_blend", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_strategy_blended(rounds=2000):
    tmpdir, mgr, sid = _setup()
    try:
        mgr.bootstrap_init(sid, overwrite=True)
        mgr.bootstrap_run_tournament(sid, rounds=1000, seed=99)
        for i in range(40):
            name = f"Skill {i}"
            mgr.crystallize_skill(
                sid,
                name=name,
                description=f"Synthetic workflow {i} for malware and crypto analysis",
                steps=["triage", "decompile", "xref"],
                tags=["malware", "crypto" if i % 2 else "network"],
            )
            mgr.rate_skill(sid, f"skill_{name.lower().replace(' ', '_')}", reward=(0.8 if i % 3 else 0.2))

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            mgr.suggest_strategy(sid, context="crypto decoder network beacon")
            samples.append(time.perf_counter() - t0)
        _summarize("suggest_strategy(blended)", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_predictor_blended(rounds=1000):
    tmpdir = tempfile.mkdtemp()
    try:
        cache_dir = os.path.join(tmpdir, "cache")
        os.makedirs(cache_dir, exist_ok=True)
        binary = os.path.join(tmpdir, "pred.bin")
        with open(binary, "wb") as f:
            f.write(b"\x90" * 1024)
        srv = IDAMCPServer()
        create = srv._execute_tool("session", {"action": "create", "binary_path": binary})
        sid = create["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 800, "seed": 5})
        for i in range(16):
            srv._execute_tool(
                "session",
                {
                    "action": "log_activity",
                    "session_id": sid,
                    "tool": "search" if i % 2 else "code",
                    "activity_action": "find" if i % 2 else "decompile",
                    "result": f"item_{i}",
                },
            )

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool(
                "predictor",
                {
                    "action": "suggest_next_tool",
                    "session_id": sid,
                    "context": "network beacon c2",
                    "limit": 5,
                },
            )
            samples.append(time.perf_counter() - t0)
        _summarize("predictor.suggest_next_tool", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_dispute_lifecycle(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "disp.bin")
        with open(binary, "wb") as f:
            f.write(b"\x90" * 512)
        srv = IDAMCPServer()
        create = srv._execute_tool("session", {"action": "create", "binary_path": binary})
        sid = create["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})

        samples = []
        for i in range(rounds):
            t0 = time.perf_counter()
            opened = srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_open_dispute",
                    "session_id": sid,
                    "claim_id": f"claim-{i}",
                    "predicted": 0.6,
                    "reason": "benchmark",
                },
            )
            did = opened.get("dispute", {}).get("dispute_id")
            srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_resolve_dispute",
                    "session_id": sid,
                    "dispute_id": did,
                    "observed": i % 2,
                    "delay_seconds": 5,
                },
            )
            samples.append(time.perf_counter() - t0)
        _summarize("dispute open+resolve", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_bootstrap_summary(rounds=5000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "sum.bin")
        with open(binary, "wb") as f:
            f.write(b"\x41" * 512)
        srv = IDAMCPServer()
        create = srv._execute_tool("session", {"action": "create", "binary_path": binary})
        sid = create["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1200, "seed": 101})
        for i in range(120):
            opened = srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_open_dispute",
                    "session_id": sid,
                    "claim_id": f"sum-{i}",
                    "predicted": 0.45 + ((i % 10) * 0.05),
                    "reason": "summary benchmark",
                },
            )
            if i % 2 == 0:
                did = opened.get("dispute", {}).get("dispute_id")
                srv._execute_tool(
                    "session",
                    {
                        "action": "bootstrap_resolve_dispute",
                        "session_id": sid,
                        "dispute_id": did,
                        "observed": i % 3 == 0,
                        "delay_seconds": i,
                    },
                )

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_summary", "session_id": sid})
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_summary", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_snapshot_and_drift(rounds=3000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "drift.bin")
        with open(binary, "wb") as f:
            f.write(b"\x44" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1200, "seed": 123})

        snap_samples = []
        for i in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"s{i}"})
            snap_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_snapshot", snap_samples)

        drift_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_drift_report", "session_id": sid, "window": 25})
            drift_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_drift_report", drift_samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_simulate_batch(runs=80, batch_n=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "sim.bin")
        with open(binary, "wb") as f:
            f.write(b"\x55" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})

        samples = []
        for i in range(runs):
            t0 = time.perf_counter()
            srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_simulate_batch",
                    "session_id": sid,
                    "n": batch_n,
                    "seed": 700 + i,
                    "positive_rate": 0.57,
                },
            )
            samples.append(time.perf_counter() - t0)
        _summarize(f"bootstrap_simulate_batch({batch_n})", samples)
        total = runs * batch_n
        print(f"{'simulate throughput':<34} {total / max(sum(samples), 1e-9):8.1f} outcomes/sec")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_export_and_prune(rounds=3000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "exp.bin")
        with open(binary, "wb") as f:
            f.write(b"\x66" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 2000, "seed": 99, "positive_rate": 0.6})
        for i in range(40):
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"e{i}"})

        export_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_export_metrics", "session_id": sid})
            export_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_export_metrics", export_samples)

        prune_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_prune_data",
                    "session_id": sid,
                    "max_outcomes": 1000,
                    "max_disputes": 300,
                    "max_snapshots": 50,
                },
            )
            prune_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_prune_data", prune_samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_detailed_reports(rounds=5000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "det.bin")
        with open(binary, "wb") as f:
            f.write(b"\x77" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 3000, "seed": 55})
        srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 5000, "seed": 66, "positive_rate": 0.58})

        samples1 = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_summary_detailed", "session_id": sid, "top_policies": 10})
            samples1.append(time.perf_counter() - t0)
        _summarize("bootstrap_summary_detailed", samples1)

        samples2 = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_calibration_report", "session_id": sid, "min_bin_n": 5})
            samples2.append(time.perf_counter() - t0)
        _summarize("bootstrap_calibration_report", samples2)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_baseline_and_alerts(rounds=5000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "alert.bin")
        with open(binary, "wb") as f:
            f.write(b"\x88" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 2500, "seed": 77})
        for i in range(40):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 50, "seed": i + 100, "positive_rate": 0.53})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"a{i}"})

        b_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_update_baseline", "session_id": sid, "window": 30, "percentile": 95.0})
            b_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_update_baseline", b_samples)

        a_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_evaluate_alerts", "session_id": sid, "window": 30})
            a_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_evaluate_alerts", a_samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_mitigation_pipeline(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "mit.bin")
        with open(binary, "wb") as f:
            f.write(b"\x99" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1200, "seed": 211})
        for i in range(35):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 40, "seed": 2000 + i, "positive_rate": 0.52})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"m{i}"})
        srv._execute_tool("session", {"action": "bootstrap_update_baseline", "session_id": sid, "window": 30, "percentile": 95.0})

        plan_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_mitigation_plan", "session_id": sid, "window": 30})
            plan_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_mitigation_plan", plan_samples)

        dry_samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_apply_mitigation",
                    "session_id": sid,
                    "window": 30,
                    "max_actions": 3,
                    "dry_run": True,
                },
            )
            dry_samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_apply_mitigation(dry)", dry_samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_mitigation_analytics(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "mita.bin")
        with open(binary, "wb") as f:
            f.write(b"\xaa" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1500, "seed": 4242})
        for i in range(30):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 30, "seed": 5000 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"h{i}"})
            srv._execute_tool("session", {"action": "bootstrap_apply_mitigation", "session_id": sid, "window": 20, "max_actions": 2})

        hs = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_mitigation_history", "session_id": sid, "limit": 100, "offset": 0})
            hs.append(time.perf_counter() - t0)
        _summarize("bootstrap_mitigation_history", hs)

        es = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_mitigation_effectiveness", "session_id": sid, "window": 30})
            es.append(time.perf_counter() - t0)
        _summarize("bootstrap_mitigation_effectiveness", es)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_policy_adaptation(rounds=1500):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "adapt.bin")
        with open(binary, "wb") as f:
            f.write(b"\xbb" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1600, "seed": 5151})
        for i in range(25):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 40, "seed": 8000 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"p{i}"})
            srv._execute_tool("session", {"action": "bootstrap_apply_mitigation", "session_id": sid, "window": 20, "max_actions": 2})

        rw = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_policy_reweight", "session_id": sid, "window": 20, "max_shift": 0.08, "dry_run": True})
            rw.append(time.perf_counter() - t0)
        _summarize("bootstrap_policy_reweight(dry)", rw)

        ah = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_policy_reweight_history", "session_id": sid, "limit": 50, "offset": 0})
            ah.append(time.perf_counter() - t0)
        _summarize("bootstrap_policy_reweight_history", ah)

        ap = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_autopilot", "session_id": sid, "window": 20, "dry_run": True})
            ap.append(time.perf_counter() - t0)
        _summarize("bootstrap_autopilot(dry)", ap)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_autopilot_safeguards(rounds=1000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "safe.bin")
        with open(binary, "wb") as f:
            f.write(b"\xcc" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1200, "seed": 999})
        for i in range(20):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 30, "seed": 9000 + i, "positive_rate": 0.52})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"s{i}"})

        srv._execute_tool(
            "session",
            {
                "action": "bootstrap_set_autopilot_policy",
                "session_id": sid,
                "cooldown_seconds": 0,
                "daily_budget": 100000,
                "max_live_actions": 3,
                "rollback_on_regression": True,
            },
        )

        p1 = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_set_autopilot_policy", "session_id": sid, "cooldown_seconds": 0, "daily_budget": 100000, "max_live_actions": 3, "rollback_on_regression": True})
            p1.append(time.perf_counter() - t0)
        _summarize("bootstrap_set_autopilot_policy", p1)

        p2 = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_get_autopilot_policy", "session_id": sid})
            p2.append(time.perf_counter() - t0)
        _summarize("bootstrap_get_autopilot_policy", p2)

        p3 = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_autopilot", "session_id": sid, "window": 20, "dry_run": False})
            p3.append(time.perf_counter() - t0)
        _summarize("bootstrap_autopilot(live,no-cool)", p3)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_plan_status(rounds=3000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "plan.bin")
        with open(binary, "wb") as f:
            f.write(b"\xdd" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1000, "seed": 123})
        for i in range(10):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 20, "seed": 400 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"pl{i}"})

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_plan_status", "session_id": sid})
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_plan_status", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_readiness_gate(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "ready.bin")
        with open(binary, "wb") as f:
            f.write(b"\xee" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 2000, "seed": 700})
        for i in range(20):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 25, "seed": 900 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"r{i}"})
        srv._execute_tool("session", {"action": "bootstrap_update_baseline", "session_id": sid, "window": 20, "percentile": 95.0})

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool(
                "session",
                {
                    "action": "bootstrap_readiness_gate",
                    "session_id": sid,
                    "min_tournament_rounds": 1000,
                    "min_snapshots": 10,
                    "min_outcomes": 100,
                    "max_ece": 0.5,
                    "max_open_disputes": 100,
                },
            )
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_readiness_gate", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_readiness_trend_controls(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "trend.bin")
        with open(binary, "wb") as f:
            f.write(b"\xef" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1200, "seed": 12345})
        for i in range(25):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 20, "seed": 3000 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"t{i}"})
            srv._execute_tool("session", {"action": "bootstrap_record_readiness", "session_id": sid, "tag": f"tick{i}"})

        h = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_readiness_history", "session_id": sid, "limit": 100, "offset": 0})
            h.append(time.perf_counter() - t0)
        _summarize("bootstrap_readiness_history", h)

        t = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_readiness_trend", "session_id": sid, "window": 20})
            t.append(time.perf_counter() - t0)
        _summarize("bootstrap_readiness_trend", t)

        g = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_readiness_regression_guard", "session_id": sid, "window": 20, "auto_snapshot": False})
            g.append(time.perf_counter() - t0)
        _summarize("bootstrap_readiness_regression_guard", g)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def benchmark_finalize_report(rounds=2000):
    tmpdir = tempfile.mkdtemp()
    try:
        binary = os.path.join(tmpdir, "final.bin")
        with open(binary, "wb") as f:
            f.write(b"\xf0" * 1024)
        srv = IDAMCPServer()
        sid = srv._execute_tool("session", {"action": "create", "binary_path": binary})["session"]["session_id"]
        srv._execute_tool("session", {"action": "bootstrap_init", "session_id": sid, "overwrite": True})
        srv._execute_tool("session", {"action": "bootstrap_run_tournament", "session_id": sid, "rounds": 1500, "seed": 42})
        for i in range(20):
            srv._execute_tool("session", {"action": "bootstrap_simulate_batch", "session_id": sid, "n": 20, "seed": 100 + i, "positive_rate": 0.5})
            srv._execute_tool("session", {"action": "bootstrap_snapshot", "session_id": sid, "name": f"f{i}"})
            srv._execute_tool("session", {"action": "bootstrap_record_readiness", "session_id": sid, "tag": f"f{i}"})
        srv._execute_tool("session", {"action": "bootstrap_update_baseline", "session_id": sid, "window": 20, "percentile": 95.0})

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            srv._execute_tool("session", {"action": "bootstrap_finalize_report", "session_id": sid, "trend_window": 20, "effectiveness_window": 20})
            samples.append(time.perf_counter() - t0)
        _summarize("bootstrap_finalize_report", samples)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    print("=" * 78)
    print("Evidence Physics Bootstrap Benchmarks")
    print("=" * 78)
    benchmark_bootstrap_init()
    benchmark_tournament()
    benchmark_blend_compute()
    benchmark_strategy_blended()
    benchmark_predictor_blended()
    benchmark_dispute_lifecycle()
    benchmark_bootstrap_summary()
    benchmark_snapshot_and_drift()
    benchmark_simulate_batch()
    benchmark_export_and_prune()
    benchmark_detailed_reports()
    benchmark_baseline_and_alerts()
    benchmark_mitigation_pipeline()
    benchmark_mitigation_analytics()
    benchmark_policy_adaptation()
    benchmark_autopilot_safeguards()
    benchmark_plan_status()
    benchmark_readiness_gate()
    benchmark_readiness_trend_controls()
    benchmark_finalize_report()
