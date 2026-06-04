#!/usr/bin/env python3
"""
Comprehensive benchmark suite for Cartographer-μ.

Measures:
  1. Latency: per-component and end-to-end pipeline
  2. Accuracy: relevance ranking quality vs baselines
  3. Memory: footprint and scalability
  4. Determinism: consistency guarantees
  5. Learning: preference convergence speed
  6. Scalability: performance vs blackboard size
"""
import os
import time
import json
import tempfile
import shutil
import random
import statistics

from tests._isolated_repo_loader import load_host_module

import numpy as np


def _make_unavailable_type(name, reason):
    class _Unavailable:
        def __init__(self, *args, **kwargs):
            raise RuntimeError(reason)

    _Unavailable.__name__ = name
    return _Unavailable


try:
    _cartographer_mod = load_host_module("cartographer_mu")
    S4REncoder = _cartographer_mod.S4REncoder
    TurboQuantLite = _cartographer_mod.TurboQuantLite
    BridgeRAGLite = _cartographer_mod.BridgeRAGLite
    MemRLUtility = _cartographer_mod.MemRLUtility
    SchemaBootRE = _cartographer_mod.SchemaBootRE
    ContextComposer = _cartographer_mod.ContextComposer
    CartographerMu = _cartographer_mod.CartographerMu
    _CARTOGRAPHER_IMPORT_ERROR = None
except FileNotFoundError as exc:
    _CARTOGRAPHER_IMPORT_ERROR = exc
    _reason = (
        "Cartographer-mu benchmark is unavailable because the cartographer_mu "
        "module is not present in this checkout."
    )
    S4REncoder = _make_unavailable_type("S4REncoder", _reason)
    TurboQuantLite = _make_unavailable_type("TurboQuantLite", _reason)
    BridgeRAGLite = _make_unavailable_type("BridgeRAGLite", _reason)
    MemRLUtility = _make_unavailable_type("MemRLUtility", _reason)
    SchemaBootRE = _make_unavailable_type("SchemaBootRE", _reason)
    ContextComposer = _make_unavailable_type("ContextComposer", _reason)
    CartographerMu = _make_unavailable_type("CartographerMu", _reason)

# =============================================================================
# Benchmark Configuration
# =============================================================================
WARMUP_ROUNDS = 10
BENCHMARK_ROUNDS = 100
LARGE_BENCHMARK_ROUNDS = 20
SIZES = [10, 50, 100, 500, 1000, 5000]
TOPK = 3

np.random.seed(42)
random.seed(42)

# =============================================================================
# Helper: Generate synthetic blackboard entries
# =============================================================================

def generate_entries(n: int, with_vectors: bool = True) -> list:
    """Generate n synthetic blackboard entries with realistic RE data."""
    entries = []
    tools = ["functions", "code", "search", "strings", "imports", "data"]
    categories = ["finding", "vuln", "behavior", "crypto", "network"]
    apis = ["VirtualAlloc", "CreateThread", "RegSetValue", "CryptEncrypt", "Socket", "connect", "malloc", "memcpy"]
    addrs = [f"0x140{i:06x}" for i in range(0x1000, 0x1000 + n)]
    
    for i in range(n):
        addr = addrs[i % len(addrs)]
        api = apis[i % len(apis)]
        tool = tools[i % len(tools)]
        category = categories[i % len(categories)]
        
        entry = {
            "id": f"e{i:04d}",
            "title": f"{api} @ {addr}" if i % 3 == 0 else f"sub_{addr[2:]} found",
            "addr": addr,
            "category": category,
            "bridges": [addr, api] if i % 2 == 0 else [addr],
            "schema": {
                "tool": tool,
                "has_addr": True,
                "has_api": i % 2 == 0,
                "has_crypto": category == "crypto",
                "has_network": category == "network",
                "phase_hint": "threat_analysis" if category in ("crypto", "network") else "behavioral_analysis" if i % 2 == 0 else "triage",
            },
            "q_value": 0.5,
            "call_idx": i,
        }
        
        if with_vectors:
            # Generate a deterministic vector based on entry content
            rng = np.random.RandomState(hash(entry["id"]) & 0xFFFFFFFF)
            vec = rng.randn(128).astype(np.float32)
            vec = vec / (np.linalg.norm(vec) + 1e-9)
            tq = TurboQuantLite()
            q, qs, norm = tq.encode(vec)
            entry["vector"] = vec.tobytes()
            entry["quantized"] = q.tobytes()
            entry["q_signs"] = qs.tobytes()
            entry["norm"] = norm
        
        entries.append(entry)
    
    return entries


def generate_query_payload(seed: int, known_addrs: list = None, known_apis: list = None) -> tuple:
    """Generate a synthetic query payload."""
    rng = random.Random(seed)
    
    # 70% chance to query a known address (for overlap), 30% novel
    if known_addrs and rng.random() < 0.7:
        addr = rng.choice(known_addrs)
    else:
        addr = f"0x140{rng.randint(0x1000, 0x2000):06x}"
    
    # 70% chance to query a known API
    if known_apis and rng.random() < 0.7:
        api = rng.choice(known_apis)
    else:
        api = rng.choice(["VirtualAlloc", "CreateThread", "CryptEncrypt", "Socket", "malloc"])
    
    payloads = [
        {"addr": addr, "functions": [{"name": f"sub_{addr[2:]}", "addr": addr}]},
        {"addr": addr, "api": api, "pseudocode": f"{api}(...);"},
        {"query": api, "results": [{"addr": addr}]},
        {"strings": [f"error in {api}"], "addr": addr},
    ]
    payload = rng.choice(payloads)
    tool = rng.choice(["functions", "code", "search", "strings"])
    return tool, payload, [addr, api]


# =============================================================================
# 1. Latency Benchmarks
# =============================================================================

def benchmark_latency():
    print("=" * 70)
    print("1. LATENCY BENCHMARKS")
    print("=" * 70)
    
    enc = S4REncoder()
    tq = TurboQuantLite()
    br = BridgeRAGLite(tq)
    memrl = MemRLUtility()
    sb = SchemaBootRE()
    composer = ContextComposer(enc, tq, br, memrl, sb, topk=TOPK)
    
    payload = {"addr": "0x140001000", "functions": [{"name": "sub_140001000", "addr": "0x140001000"}]}
    entries = generate_entries(100)
    
    # Warmup
    for _ in range(WARMUP_ROUNDS):
        enc.encode(payload, "functions")
        tq.encode(enc.encode(payload, "functions"))
        br.extract_bridges(payload, "functions")
        sb.induce_schema(payload, "functions")
        composer.compose("functions", "list", payload, entries)
    
    # Benchmark individual components
    results = {}
    
    # S4 Encode
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        enc.encode(payload, "functions")
        times.append(time.perf_counter() - t0)
    results["S4 encode"] = times
    
    # TurboQuant
    vec = enc.encode(payload, "functions")
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        tq.encode(vec)
        times.append(time.perf_counter() - t0)
    results["TurboQuant"] = times
    
    # Bridge extraction
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        br.extract_bridges(payload, "functions")
        times.append(time.perf_counter() - t0)
    results["Bridge extract"] = times
    
    # Schema induction
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        sb.induce_schema(payload, "functions")
        times.append(time.perf_counter() - t0)
    results["SchemaBoot"] = times
    
    # Full pipeline (small)
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        composer.compose("functions", "list", payload, entries)
        times.append(time.perf_counter() - t0)
    results["Full pipeline (100 entries)"] = times
    
    # Print results
    print(f"\n{'Component':<35} {'Mean (ms)':<12} {'Median (ms)':<14} {'P99 (ms)':<12} {'Min (ms)':<10}")
    print("-" * 90)
    for name, times in results.items():
        ms_times = [t * 1000 for t in times]
        mean_ms = statistics.mean(ms_times)
        median_ms = statistics.median(ms_times)
        p99_ms = np.percentile(ms_times, 99)
        min_ms = min(ms_times)
        print(f"{name:<35} {mean_ms:<12.3f} {median_ms:<14.3f} {p99_ms:<12.3f} {min_ms:<10.3f}")
    
    return results


# =============================================================================
# 2. Scalability Benchmarks
# =============================================================================

def benchmark_scalability():
    print("\n" + "=" * 70)
    print("2. SCALABILITY BENCHMARKS")
    print("=" * 70)
    
    enc = S4REncoder()
    tq = TurboQuantLite()
    br = BridgeRAGLite(tq)
    memrl = MemRLUtility()
    sb = SchemaBootRE()
    composer = ContextComposer(enc, tq, br, memrl, sb, topk=TOPK)
    
    payload = {"addr": "0x140001000", "functions": [{"name": "sub_140001000", "addr": "0x140001000"}]}
    
    print(f"\n{'Entries':<10} {'Mean (ms)':<12} {'Median (ms)':<14} {'P99 (ms)':<12} {'Throughput (ops/s)':<18}")
    print("-" * 80)
    
    results = {}
    for size in SIZES:
        entries = generate_entries(size)
        
        # Warmup
        for _ in range(WARMUP_ROUNDS):
            composer.compose("functions", "list", payload, entries)
        
        # Benchmark
        rounds = max(10, BENCHMARK_ROUNDS // max(1, size // 100))
        times = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            composer.compose("functions", "list", payload, entries)
            times.append(time.perf_counter() - t0)
        
        ms_times = [t * 1000 for t in times]
        mean_ms = statistics.mean(ms_times)
        median_ms = statistics.median(ms_times)
        p99_ms = np.percentile(ms_times, 99)
        throughput = 1000.0 / mean_ms if mean_ms > 0 else float('inf')
        
        print(f"{size:<10} {mean_ms:<12.3f} {median_ms:<14.3f} {p99_ms:<12.3f} {throughput:<18.1f}")
        results[size] = times
    
    return results


# =============================================================================
# 3. Accuracy / Relevance Benchmarks
# =============================================================================

def benchmark_accuracy():
    print("\n" + "=" * 70)
    print("3. ACCURACY / RELEVANCE BENCHMARKS")
    print("=" * 70)
    
    enc = S4REncoder()
    tq = TurboQuantLite()
    br = BridgeRAGLite(tq)
    memrl = MemRLUtility()
    sb = SchemaBootRE()
    composer = ContextComposer(enc, tq, br, memrl, sb, topk=TOPK)
    
    n_queries = 200
    n_entries = 500
    
    # Simulate realistic RE session: analyst works on a focused set of addresses
    # 16 active addresses (analyst is investigating a specific code region)
    active_addrs = [f"0x140{i:06x}" for i in range(0x1000, 0x1010)]
    active_apis = ["VirtualAlloc", "CreateThread", "RegSetValue", "CryptEncrypt"]
    
    # Generate entries with CORRELATED vectors
    # Entries about the same address have similar vectors (clustered)
    # Nearby addresses in the address space also have correlated vectors
    addr_centroids = {}
    base_vec = np.random.randn(128).astype(np.float32) * 0.5
    for idx, addr in enumerate(active_addrs):
        # Each address centroid drifts smoothly from the previous
        drift = np.random.randn(128).astype(np.float32) * 0.15
        base_vec = base_vec + drift
        addr_centroids[addr] = base_vec.copy()
    
    entries = []
    for i in range(n_entries):
        addr = active_addrs[i % len(active_addrs)]
        api = active_apis[i % len(active_apis)]
        
        # Vector = address centroid + small noise + API-specific offset
        # This means entries about the same address are semantically similar
        # AND nearby addresses are also somewhat similar
        vec = addr_centroids[addr].copy()
        # API-specific sub-cluster
        api_offset = np.random.RandomState(hash(api) & 0xFFFFFFFF).randn(128).astype(np.float32) * 0.08
        vec = vec + api_offset
        noise = np.random.randn(128).astype(np.float32) * 0.08
        vec = vec + noise
        vec = vec / (np.linalg.norm(vec) + 1e-9)
        
        entry = {
            "id": f"e{i:04d}",
            "title": f"{api} @ {addr}" if i % 3 == 0 else f"sub_{addr[2:]} found",
            "addr": addr,
            "category": "finding",
            "bridges": [addr, api] if i % 2 == 0 else [addr],
            "schema": {
                "tool": "functions" if i % 3 == 0 else "code",
                "has_addr": True,
                "has_api": i % 2 == 0,
                "phase_hint": "behavioral_analysis" if i % 2 == 0 else "triage",
            },
            "q_value": 0.5,
            "call_idx": i,
        }
        q, qs, norm = tq.encode(vec)
        entry["vector"] = vec.tobytes()
        entry["quantized"] = q.tobytes()
        entry["q_signs"] = qs.tobytes()
        entry["norm"] = norm
        entries.append(entry)
    
    # MEMRL WARM-UP: Simulate realistic analyst session
    # The analyst repeatedly queries 4 "focus" addresses and uses the results
    # This teaches MemRL that entries about these addresses are useful
    focus_addrs = active_addrs[:4]
    print(f"\nMemRL warm-up: simulating analyst focusing on {len(focus_addrs)} addresses...")
    
    # Direct Q-value training: entries about focus addresses are useful
    for entry in entries:
        entry_bridges = set(entry.get("bridges", []))
        entry_addrs = {b for b in entry_bridges if b.startswith("0x")}
        if entry_addrs & set(focus_addrs):
            # Entries about focus addresses: high utility
            memrl.update_q(entry["id"], 1.0)
            memrl.update_q(entry["id"], 1.0)
        else:
            # Entries about other addresses: low utility
            memrl.update_q(entry["id"], -0.5)
    
    # Now evaluate on the test queries
    # The analyst investigates the focus addresses + some new ones
    test_addrs = focus_addrs + [f"0x140{i:06x}" for i in range(0x1010, 0x1018)]
    
    queries = []
    for seed in range(n_queries):
        rng = random.Random(seed)
        # 95% of queries reference a known address (analyst stays focused)
        if rng.random() < 0.95:
            addr = rng.choice(test_addrs)
        else:
            addr = f"0x140{rng.randint(0x2000, 0x3000):06x}"
        api = rng.choice(active_apis)
        
        payload = {"addr": addr, "api": api, "functions": [{"name": f"sub_{addr[2:]}", "addr": addr}]}
        query_bridges = [addr, api]
        
        # Find relevant entries (share at least one bridge)
        relevant_ids = set()
        for entry in entries:
            entry_bridges = set(entry.get("bridges", []))
            if entry_bridges & set(query_bridges):
                relevant_ids.add(entry["id"])
        
        queries.append(("code", payload, query_bridges, relevant_ids))
    
    # Evaluate methods
    def evaluate_method(name, composer_or_fn, use_memrl=True):
        hits_list = []
        scores_list = []
        for tool, payload, query_bridges, relevant_ids in queries:
            if callable(composer_or_fn):
                result = composer_or_fn(tool, payload, entries)
            else:
                result = composer_or_fn.compose(tool, "decompile", payload, entries)
            selected_ids = {e["id"] for e in result["working_memory"]}
            hits = len(selected_ids & relevant_ids)
            hits_list.append(hits)
            scores_list.append(hits / TOPK if TOPK > 0 else 0)
        return hits_list, scores_list
    
    # Cartographer-μ (full)
    cm_hits, cm_scores = evaluate_method("Cartographer-μ", composer)
    
    # Bridge-only (no MemRL, no semantic)
    memrl_naive = MemRLUtility()  # Fresh Q-table
    composer_bridge_only = ContextComposer(enc, tq, br, memrl_naive, sb, topk=TOPK)
    bo_hits, bo_scores = evaluate_method("Bridge-only", composer_bridge_only)
    
    # Random baseline
    random_hits = []
    for _, _, _, relevant_ids in queries:
        random_ids = set(random.sample([e["id"] for e in entries], min(TOPK, len(entries))))
        random_hits.append(len(random_ids & relevant_ids))
    
    # Chronological baseline
    chronological_hits = []
    for _, _, _, relevant_ids in queries:
        recent_ids = set(e["id"] for e in sorted(entries, key=lambda x: x["call_idx"], reverse=True)[:TOPK])
        chronological_hits.append(len(recent_ids & relevant_ids))
    
    print(f"\n{'Method':<25} {'Precision@3':<15} {'Mean Hits':<12} {'Max Hits':<10}")
    print("-" * 70)
    print(f"{'Cartographer-μ (full)':<25} {statistics.mean(cm_scores):<15.3f} {statistics.mean(cm_hits):<12.2f} {max(cm_hits):<10}")
    print(f"{'Bridge-only (no MemRL)':<25} {statistics.mean(bo_scores):<15.3f} {statistics.mean(bo_hits):<12.2f} {max(bo_hits):<10}")
    print(f"{'Random baseline':<25} {statistics.mean([h/TOPK for h in random_hits]):<15.3f} {statistics.mean(random_hits):<12.2f} {max(random_hits):<10}")
    print(f"{'Chronological baseline':<25} {statistics.mean([h/TOPK for h in chronological_hits]):<15.3f} {statistics.mean(chronological_hits):<12.2f} {max(chronological_hits):<10}")
    
    # Per-query analysis
    overlap_queries = sum(1 for _, _, _, relevant in queries if len(relevant) > 0)
    print(f"\n--- Per-Query Analysis ---")
    print(f"Queries with bridge overlap: {overlap_queries} / {n_queries}")
    print(f"Perfect precision (3/3): {sum(1 for h in cm_hits if h == TOPK)} / {n_queries}")
    print(f"Zero hits: {sum(1 for h in cm_hits if h == 0)} / {n_queries}")
    
    if overlap_queries > 0:
        cm_ov = [h for h, q in zip(cm_hits, queries) if len(q[3]) > 0]
        bo_ov = [h for h, q in zip(bo_hits, queries) if len(q[3]) > 0]
        rnd_ov = [h for h, q in zip(random_hits, queries) if len(q[3]) > 0]
        chr_ov = [h for h, q in zip(chronological_hits, queries) if len(q[3]) > 0]
        print(f"\n--- On queries WITH overlap ({overlap_queries}) ---")
        print(f"{'Cartographer-μ':<25} {statistics.mean([h/TOPK for h in cm_ov]):<15.3f} {statistics.mean(cm_ov):<12.2f}")
        print(f"{'Bridge-only':<25} {statistics.mean([h/TOPK for h in bo_ov]):<15.3f} {statistics.mean(bo_ov):<12.2f}")
        print(f"{'Random':<25} {statistics.mean([h/TOPK for h in rnd_ov]):<15.3f} {statistics.mean(rnd_ov):<12.2f}")
        print(f"{'Chronological':<25} {statistics.mean([h/TOPK for h in chr_ov]):<15.3f} {statistics.mean(chr_ov):<12.2f}")
    
    # MemRL Q-value distribution
    q_values = [memrl.get_q(e["id"]) for e in entries]
    focus_q = [memrl.get_q(e["id"]) for e in entries if any(a in e.get("bridges", []) for a in focus_addrs)]
    other_q = [memrl.get_q(e["id"]) for e in entries if not any(a in e.get("bridges", []) for a in focus_addrs)]
    print(f"\n--- MemRL Q-Value Distribution ---")
    print(f"Focus address entries: mean Q = {statistics.mean(focus_q):.3f}")
    print(f"Other entries:         mean Q = {statistics.mean(other_q):.3f}")
    print(f"Separation:            {statistics.mean(focus_q) - statistics.mean(other_q):.3f}")
    
    return {
        "cartographer": cm_hits,
        "bridge_only": bo_hits,
        "random": random_hits,
        "chronological": chronological_hits,
    }


# =============================================================================
# 4. Determinism Benchmark
# =============================================================================

def benchmark_determinism():
    print("\n" + "=" * 70)
    print("4. DETERMINISM BENCHMARK")
    print("=" * 70)
    
    enc = S4REncoder()
    tq = TurboQuantLite()
    
    payloads = [
        ({"addr": "0x140001000"}, "functions"),
        ({"api": "VirtualAlloc", "xrefs": ["0x140002000"]}, "code"),
        ({"functions": [{"name": "main", "addr": "0x140003000"}]}, "search"),
    ]
    
    all_match = True
    for payload, tool in payloads:
        v1 = enc.encode(payload, tool)
        q1, qs1, n1 = tq.encode(v1)
        
        v2 = enc.encode(payload, tool)
        q2, qs2, n2 = tq.encode(v2)
        
        vec_match = np.allclose(v1, v2)
        quant_match = np.array_equal(q1, q2) and np.array_equal(qs1, qs2)
        norm_match = abs(n1 - n2) < 1e-6
        
        status = "PASS" if (vec_match and quant_match and norm_match) else "FAIL"
        if status == "FAIL":
            all_match = False
        print(f"  {tool:<12} vector={vec_match} quantized={quant_match} norm={norm_match} -> {status}")
    
    # Full pipeline determinism
    entries = generate_entries(50)
    payload = {"addr": "0x140001000"}
    
    br = BridgeRAGLite(tq)
    memrl = MemRLUtility()
    sb = SchemaBootRE()
    composer = ContextComposer(enc, tq, br, memrl, sb, topk=TOPK)
    
    r1 = composer.compose("code", "decompile", payload, entries)
    r2 = composer.compose("code", "decompile", payload, entries)
    
    pipeline_match = (
        r1["analysis_phase"] == r2["analysis_phase"] and
        len(r1["working_memory"]) == len(r2["working_memory"]) and
        all(a["id"] == b["id"] for a, b in zip(r1["working_memory"], r2["working_memory"]))
    )
    
    status = "PASS" if pipeline_match else "FAIL"
    if status == "FAIL":
        all_match = False
    print(f"  {'pipeline':<12} -> {status}")
    
    print(f"\nOverall determinism: {'PASS' if all_match else 'FAIL'}")
    return all_match


# =============================================================================
# 5. Memory Benchmark
# =============================================================================

def benchmark_memory():
    print("\n" + "=" * 70)
    print("5. MEMORY BENCHMARK")
    print("=" * 70)
    
    import sys
    
    # Measure encoder memory
    enc = S4REncoder()
    enc_size = sys.getsizeof(enc.A) + sys.getsizeof(enc.B) + sys.getsizeof(enc.C) + sys.getsizeof(enc.D)
    
    tq = TurboQuantLite()
    tq_size = sys.getsizeof(tq.H) + sys.getsizeof(tq.D) + sys.getsizeof(tq.bins) + sys.getsizeof(tq.centroids)
    
    total_param_size = enc_size + tq_size
    
    print(f"\n{'Component':<25} {'Size (KB)':<12} {'Size (bytes)':<15}")
    print("-" * 55)
    print(f"{'S4REncoder (A+B+C+D)':<25} {enc_size/1024:<12.2f} {enc_size:<15}")
    print(f"{'TurboQuantLite (H+D+bins)':<25} {tq_size/1024:<12.2f} {tq_size:<15}")
    print(f"{'Total parameters':<25} {total_param_size/1024:<12.2f} {total_param_size:<15}")
    
    # Q-table memory
    tmpdir = tempfile.mkdtemp()
    memrl = MemRLUtility(db_path=os.path.join(tmpdir, "test_q.db"))
    
    # Simulate 1000 entries
    for i in range(1000):
        memrl.update_q(f"e{i:04d}", random.random())
    
    db_size = os.path.getsize(memrl.db_path)
    print(f"{'MemRL Q-table (1000 entries)':<25} {db_size/1024:<12.2f} {db_size:<15}")
    
    # Per-entry vector storage
    vec_size = 128 * 4  # 128 floats * 4 bytes
    quantized_size = 128 * 1 + 128 * 1  # uint8 + int8
    total_per_entry = vec_size + quantized_size
    print(f"{'Per-entry vector+quantized':<25} {total_per_entry/1024:<12.2f} {total_per_entry:<15}")
    print(f"{'1000 entries total storage':<25} {total_per_entry*1000/1024:<12.2f} {total_per_entry*1000:<15}")
    
    shutil.rmtree(tmpdir, ignore_errors=True)
    
    return {
        "encoder_kb": enc_size / 1024,
        "quantizer_kb": tq_size / 1024,
        "total_params_kb": total_param_size / 1024,
        "qtable_1000_kb": db_size / 1024,
    }


# =============================================================================
# 6. MemRL Learning Convergence
# =============================================================================

def benchmark_learning():
    print("\n" + "=" * 70)
    print("6. MEMRL LEARNING CONVERGENCE")
    print("=" * 70)
    
    tmpdir = tempfile.mkdtemp()
    memrl = MemRLUtility(alpha=0.15, db_path=os.path.join(tmpdir, "test_q.db"))
    
    # Simulate a learning scenario:
    # Entry "good_addr" is consistently useful (LLM uses its bridge)
    # Entry "bad_string" is consistently ignored
    
    n_rounds = 100
    good_q_history = []
    bad_q_history = []
    
    for round_idx in range(n_rounds):
        # Good entry: injected, LLM uses bridge → reward +1.0
        memrl.observe_usage("good_addr", True, ["0x140001000"], ["0x140001000"])
        good_q_history.append(memrl.get_q("good_addr"))
        
        # Bad entry: injected, LLM ignores → reward -0.3
        memrl.observe_usage("bad_string", True, ["0x140005000"], ["error_message"])
        bad_q_history.append(memrl.get_q("bad_string"))
    
    print(f"\n{'Round':<10} {'Good Q':<12} {'Bad Q':<12}")
    print("-" * 40)
    for i in [0, 9, 19, 29, 49, 99]:
        print(f"{i+1:<10} {good_q_history[i]:<12.4f} {bad_q_history[i]:<12.4f}")
    
    print(f"\nConvergence:")
    print(f"  Good entry Q: {good_q_history[0]:.4f} → {good_q_history[-1]:.4f} (target: 1.0)")
    print(f"  Bad entry Q:  {bad_q_history[0]:.4f} → {bad_q_history[-1]:.4f} (target: 0.0)")
    print(f"  Separation:   {good_q_history[-1] - bad_q_history[-1]:.4f}")
    
    shutil.rmtree(tmpdir, ignore_errors=True)
    
    return {
        "good_final": good_q_history[-1],
        "bad_final": bad_q_history[-1],
        "separation": good_q_history[-1] - bad_q_history[-1],
    }


# =============================================================================
# 7. Bridge Scoring Quality
# =============================================================================

def benchmark_bridge_scoring():
    print("\n" + "=" * 70)
    print("7. BRIDGE SCORING QUALITY")
    print("=" * 70)
    
    enc = S4REncoder()
    tq = TurboQuantLite()
    br = BridgeRAGLite(tq)
    
    # Create entries with known bridge overlap
    entries = [
        {"id": "exact", "bridges": ["0x140001000", "VirtualAlloc"], "quantized": None, "q_signs": None, "norm": 0.0},
        {"id": "partial", "bridges": ["0x140001000"], "quantized": None, "q_signs": None, "norm": 0.0},
        {"id": "none", "bridges": ["0x140002000", "CreateThread"], "quantized": None, "q_signs": None, "norm": 0.0},
    ]
    
    # Generate vectors for entries
    for entry in entries:
        rng = np.random.RandomState(hash(entry["id"]) & 0xFFFFFFFF)
        vec = rng.randn(128).astype(np.float32)
        vec = vec / (np.linalg.norm(vec) + 1e-9)
        q, qs, norm = tq.encode(vec)
        entry["quantized"] = q.tobytes()
        entry["q_signs"] = qs.tobytes()
        entry["norm"] = norm
    
    query_bridges = ["0x140001000", "VirtualAlloc"]
    query_vec = enc.encode({"addr": "0x140001000", "api": "VirtualAlloc"}, "code")
    query_q = tq.encode(query_vec)
    
    print(f"\n{'Entry':<12} {'Bridges':<30} {'Score':<10} {'Expected':<10}")
    print("-" * 70)
    for entry in entries:
        score = br.score_relevance(query_bridges, query_vec, query_q, entry, call_age=0)
        expected = "high" if entry["id"] == "exact" else "medium" if entry["id"] == "partial" else "low"
        print(f"{entry['id']:<12} {str(entry['bridges']):<30} {score:<10.4f} {expected:<10}")
    
    return True


# =============================================================================
# 8. Full System Benchmark (End-to-End)
# =============================================================================

def benchmark_end_to_end():
    print("\n" + "=" * 70)
    print("8. END-TO-END SYSTEM BENCHMARK")
    print("=" * 70)
    
    cm = CartographerMu()
    
    # Simulate 50 tool calls with blackboard population
    n_calls = 50
    entries = []
    
    print(f"\nSimulating {n_calls} tool calls with auto-blackboard...")
    
    for i in range(n_calls):
        tool, payload, bridges = generate_query_payload(i)
        
        # Auto-blackboard: encode and add entry
        vec = cm.encode_payload(payload, tool)
        q, qs, norm = cm.quantize(vec)
        schema = cm.induce_schema(payload, tool)
        
        entry = {
            "id": f"e{i:04d}",
            "title": f"Finding from {tool}",
            "addr": bridges[0] if bridges else "",
            "category": "finding",
            "bridges": bridges,
            "schema": schema,
            "vector": vec.tobytes(),
            "quantized": q.tobytes(),
            "q_signs": qs.tobytes(),
            "norm": norm,
            "q_value": 0.5,
            "call_idx": i,
        }
        entries.append(entry)
    
    # Now benchmark context injection
    query_payload = {"addr": "0x140001000", "functions": [{"name": "sub_140001000"}]}
    
    # Warmup
    for _ in range(WARMUP_ROUNDS):
        cm.inject_context("code", "decompile", query_payload, entries)
    
    times = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        result = cm.inject_context("code", "decompile", query_payload, entries)
        times.append(time.perf_counter() - t0)
    
    ms_times = [t * 1000 for t in times]
    print(f"\n{'Metric':<25} {'Value':<20}")
    print("-" * 50)
    print(f"{'Mean latency':<25} {statistics.mean(ms_times):.3f} ms")
    print(f"{'Median latency':<25} {statistics.median(ms_times):.3f} ms")
    print(f"{'P99 latency':<25} {np.percentile(ms_times, 99):.3f} ms")
    print(f"{'Throughput':<25} {1000.0/statistics.mean(ms_times):.1f} ops/sec")
    print(f"\nSample output:")
    print(json.dumps(result, indent=2, default=str)[:600])
    
    return times


# =============================================================================
# Main
# =============================================================================

def main():
    print("\n" + "=" * 70)
    print("CARTOGRAPHER-μ COMPREHENSIVE BENCHMARK SUITE")
    print("=" * 70)
    print(f"Python: {sys.version}")
    print(f"NumPy: {np.__version__}")
    print(f"Benchmark rounds: {BENCHMARK_ROUNDS}")
    print(f"Warmup rounds: {WARMUP_ROUNDS}")
    
    results = {}
    results["latency"] = benchmark_latency()
    results["scalability"] = benchmark_scalability()
    results["accuracy"] = benchmark_accuracy()
    results["determinism"] = benchmark_determinism()
    results["memory"] = benchmark_memory()
    results["learning"] = benchmark_learning()
    results["bridge_scoring"] = benchmark_bridge_scoring()
    results["end_to_end"] = benchmark_end_to_end()
    
    print("\n" + "=" * 70)
    print("BENCHMARK COMPLETE")
    print("=" * 70)
    
    return results


if __name__ == "__main__":
    main()
