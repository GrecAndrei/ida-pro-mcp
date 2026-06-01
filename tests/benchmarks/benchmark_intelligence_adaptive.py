#!/usr/bin/env python3
"""Microbenchmarks for adaptive intelligence enrichment paths."""

import os
import sys
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.host.intelligence_context import ContextAssembler


class FakeEmbedder:
    def __init__(self):
        self._use_llama = False
        self._batch_size = 16

    def embed(self, text):
        s = 1.0 if "VirtualAllocEx" in text else 0.25
        return [s, 1.0 - s]

    def embed_batch(self, texts):
        return [self.embed(t) for t in texts]

    @staticmethod
    def cosine(a, b):
        na = (a[0] ** 2 + a[1] ** 2) ** 0.5 or 1.0
        nb = (b[0] ** 2 + b[1] ** 2) ** 0.5 or 1.0
        return (a[0] * b[0] + a[1] * b[1]) / (na * nb)


class FakeStore:
    def __init__(self, n=300):
        self.rows = []
        for i in range(n):
            tag = "VirtualAllocEx" if i % 7 == 0 else "misc"
            self.rows.append({
                "id": f"e{i}",
                "title": f"entry {i}",
                "content": "uses VirtualAllocEx" if i % 7 == 0 else "misc content",
                "addr": f"0x{0x401000 + i:06x}",
                "tags": [tag],
                "confidence": 0.9 if i % 9 == 0 else 0.4,
                "updated_at": 1000 + i,
            })

    def list(self, category=None, addr=None, tag=None, min_confidence=0.0, limit=100, offset=0):
        rows = list(self.rows)
        if addr:
            rows = [r for r in rows if r.get("addr") == addr]
        if tag:
            rows = [r for r in rows if tag in (r.get("tags") or [])]
        if min_confidence > 0:
            rows = [r for r in rows if float(r.get("confidence") or 0.0) >= min_confidence]
        return rows[offset : offset + limit]

    def exists(self, addr, category, title):
        return False

    def write(self, **kwargs):
        return "new"


def _summ(name, samples):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(
        f"{name:<34} mean={statistics.mean(ms):8.3f} ms "
        f"median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms"
    )


def benchmark_semantic_cache(rounds=200):
    asm = ContextAssembler()
    asm._embedder = FakeEmbedder()
    store = FakeStore(400)
    q = [1.0, 0.0]
    sess = "bench-sem-cache"

    cold = []
    warm = []
    for i in range(rounds):
        t0 = time.perf_counter()
        asm._get_bb_semantic_vec(
            q,
            store,
            top_k=4,
            threshold=0.2,
            max_entries=28,
            api_calls=["VirtualAllocEx"],
            session_id=sess,
        )
        dt = time.perf_counter() - t0
        if i == 0:
            cold.append(dt)
        else:
            warm.append(dt)
    _summ("semantic first-call", cold)
    _summ("semantic cached", warm)


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
    benchmark_semantic_cache(180)
    benchmark_focus_candidates(1200)
