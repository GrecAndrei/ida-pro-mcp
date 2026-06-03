#!/usr/bin/env python3
"""Microbenchmarks for Phase 1, Phase 2, and Phase 3 of the Intelligence expansion."""

from __future__ import annotations

import os
import sqlite3
import statistics
import sys
import tempfile
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.intelligence.entropy import FunctionEntropyCalculator
from ida_pro_mcp.host.intelligence.reasoner import VulnerabilityReasoner
from ida_pro_mcp.host.intelligence.structural_index import (
    ensure_tables,
    upsert_functions_batch,
)
from ida_pro_mcp.host.intelligence_preference_store import PreferenceMemoryBank


def _summ(name: str, samples: List[float]):
    ms = [x * 1000.0 for x in samples]
    ms_sorted = sorted(ms)
    p99 = ms_sorted[int(0.99 * (len(ms_sorted) - 1))]
    print(
        f"{name:<45} mean={statistics.mean(ms):8.3f} ms median={statistics.median(ms):8.3f} ms p99={p99:8.3f} ms"
    )


def bench_phase1_reasoner(rounds: int = 1000):
    reasoner = VulnerabilityReasoner()

    # Generate 50 behavior hits and 50 evidence cards
    hits = [
        {
            "behavior": f"behavior_{i % 5}",
            "confidence": 0.1 * (i % 10),
            "id": f"hit_{i}",
        }
        for i in range(50)
    ]
    cards = [
        {
            "claim": f"claim_{i % 5}",
            "claim_type": f"type_{i % 5}",
            "confidence": 0.1 * (i % 10),
            "id": f"card_{i}",
        }
        for i in range(50)
    ]

    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _ = reasoner.reason(hits, cards)
        samples.append(time.perf_counter() - t0)

    _summ("VulnerabilityReasoner.reason (100 items)", samples)


def bench_phase2_preference_merge(rounds: int = 200):
    # Setup temporary db
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        bank = PreferenceMemoryBank(db_path=db_path)

        # Populate bank with 500 local triplets
        for i in range(500):
            bank.record(f"intent_{i}", f"exp_{i}", initial_q=0.5)

        # Generate 200 incoming preferences to merge
        incoming = [
            {
                "intent_key": f"intent_{i}",
                "experience_key": f"exp_{i}",
                "q_value": 0.8,
                "visit_count": 5,
                "experience_meta": {"tag": "bench"},
            }
            for i in range(200)
        ]

        samples = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            _ = bank.merge_preferences(incoming)
            samples.append(time.perf_counter() - t0)

        _summ("PreferenceMemoryBank.merge (200 updates)", samples)
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def bench_phase3_entropy_triage(rounds: int = 50):
    with tempfile.TemporaryDirectory() as tmpdir:
        idb_path = os.path.join(tmpdir, "bench_binary.i64")
        db_path = os.path.join(tmpdir, "bench_binary.schemaboot.db")

        # Create database and ensure tables
        conn = sqlite3.connect(db_path)
        ensure_tables(conn)

        # Populate structural index with 300 mock functions
        funcs = []
        for i in range(300):
            funcs.append(
                {
                    "ea": 0x401000 + i * 16,
                    "name": f"func_{i}",
                    "size": 100 + (i % 10) * 50,
                    "segment": ".text",
                    "is_thunk": 0,
                    "is_library": 0,
                    "bb_count": 1 + (i % 20),
                    "cyclomatic_complexity": 1 + (i % 15),
                    "incoming_xrefs": i % 5,
                    "outgoing_xrefs": i % 8,
                    "entropy": 3.5 + (i % 5),
                    "call_count": i % 10,
                    "xor_count": i % 4,
                    "mov_count": 10 + (i % 20),
                    "cmp_count": i % 6,
                    "jmp_count": i % 3,
                    "ret_count": 1,
                    "push_count": i % 5,
                    "pop_count": i % 5,
                    "lea_count": i % 4,
                    "test_count": i % 3,
                    "api_count": i % 5,
                    "string_count": i % 3,
                    "data_ref_count": i % 2,
                    "has_loops": 1 if (i % 5 == 0) else 0,
                    "xor_ratio": 0.05 * (i % 10),
                }
            )
        upsert_functions_batch(conn, funcs)
        conn.close()

        calc = FunctionEntropyCalculator()

        # We need to mock BgeCodeEmbedder to avoid actual model load latency or failures during benchmark
        import unittest.mock

        mock_embedder = MagicMock()
        dummy_vec = [1.0] + [0.0] * 1535
        mock_embedder.embed.return_value = dummy_vec

        with unittest.mock.patch(
            "ida_pro_mcp.host.intelligence.entropy.BgeCodeEmbedder"
        ) as mock_emb_class:
            mock_emb_class.return_value = mock_embedder
            mock_emb_class.cosine.side_effect = lambda a, b: sum(
                x * y for x, y in zip(a, b)
            )

            samples = []
            for _ in range(rounds):
                t0 = time.perf_counter()
                _ = calc.compute_triage_suggestions(
                    idb_path, context="find crypto key", limit=5
                )
                samples.append(time.perf_counter() - t0)

            _summ("FunctionEntropyCalculator.triage (300 functions)", samples)


if __name__ == "__main__":
    print("=" * 75)
    print("Intelligence Phases 1-3 Performance Benchmarks")
    print("=" * 75)
    bench_phase1_reasoner()
    bench_phase2_preference_merge()
    bench_phase3_entropy_triage()
