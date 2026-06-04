#!/usr/bin/env python3
"""Quality and Accuracy Benchmarks for the Intelligence layer (Phases 1-3)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any, Dict, List
from unittest.mock import MagicMock

from tests._isolated_repo_loader import load_host_module

FunctionEntropyCalculator = load_host_module("intelligence.entropy").FunctionEntropyCalculator
VulnerabilityReasoner = load_host_module("intelligence.reasoner").VulnerabilityReasoner
_structural_index_mod = load_host_module("intelligence.structural_index")
ensure_tables = _structural_index_mod.ensure_tables
upsert_functions_batch = _structural_index_mod.upsert_functions_batch
PreferenceMemoryBank = load_host_module("intelligence_preference_store").PreferenceMemoryBank


def evaluate_triage_prioritization_quality():
    """
    Asserts that the triage nudge engine correctly ranks high-complexity/outlier
    functions above simple thunks.
    Calculates the Triage Focus Ratio (TFR):
    TFR = Mean(structural_entropy of top-k) / Mean(structural_entropy of bottom-k)
    """
    calc = FunctionEntropyCalculator()

    with tempfile.TemporaryDirectory() as tmpdir:
        idb_path = os.path.join(tmpdir, "quality.i64")
        db_path = os.path.join(tmpdir, "quality.schemaboot.db")
        conn = sqlite3.connect(db_path)
        ensure_tables(conn)

        # Populate with 10 simple thunks and 2 highly complex functions
        funcs = []
        for i in range(10):
            funcs.append(
                {
                    "ea": 0x401000 + i * 16,
                    "name": f"thunk_{i}",
                    "size": 16,
                    "segment": ".text",
                    "is_thunk": 0,
                    "is_library": 0,
                    "bb_count": 1,
                    "cyclomatic_complexity": 1,
                    "incoming_xrefs": 1,
                    "outgoing_xrefs": 0,
                    "entropy": 1.0,
                    "call_count": 0,
                    "xor_count": 0,
                    "mov_count": 1,
                    "cmp_count": 0,
                    "jmp_count": 0,
                    "ret_count": 1,
                    "push_count": 0,
                    "pop_count": 0,
                    "lea_count": 0,
                    "test_count": 0,
                    "api_count": 0,
                    "string_count": 0,
                    "data_ref_count": 0,
                    "has_loops": 0,
                    "xor_ratio": 0.0,
                }
            )

        funcs.append(
            {
                "ea": 0x500000,
                "name": "crypto_obfuscated_func",
                "size": 800,
                "segment": ".text",
                "is_thunk": 0,
                "is_library": 0,
                "bb_count": 45,
                "cyclomatic_complexity": 35,
                "incoming_xrefs": 5,
                "outgoing_xrefs": 12,
                "entropy": 7.8,
                "call_count": 8,
                "xor_count": 30,
                "mov_count": 45,
                "cmp_count": 15,
                "jmp_count": 8,
                "ret_count": 1,
                "push_count": 12,
                "pop_count": 12,
                "lea_count": 8,
                "test_count": 5,
                "api_count": 12,
                "string_count": 5,
                "data_ref_count": 3,
                "has_loops": 1,
                "max_loop_depth": 3,
                "xor_ratio": 0.4,
            }
        )

        funcs.append(
            {
                "ea": 0x501000,
                "name": "network_parsing_func",
                "size": 600,
                "segment": ".text",
                "is_thunk": 0,
                "is_library": 0,
                "bb_count": 25,
                "cyclomatic_complexity": 20,
                "incoming_xrefs": 3,
                "outgoing_xrefs": 8,
                "entropy": 5.5,
                "call_count": 4,
                "xor_count": 2,
                "mov_count": 35,
                "cmp_count": 8,
                "jmp_count": 4,
                "ret_count": 1,
                "push_count": 8,
                "pop_count": 8,
                "lea_count": 4,
                "test_count": 3,
                "api_count": 8,
                "string_count": 10,
                "data_ref_count": 2,
                "has_loops": 1,
                "max_loop_depth": 1,
                "xor_ratio": 0.05,
            }
        )

        upsert_functions_batch(conn, funcs)
        conn.close()

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

            sugs = calc.compute_triage_suggestions(idb_path, limit=12)

            # The top 2 suggestions MUST be our complex and network functions
            top_names = {sugs[0]["name"], sugs[1]["name"]}
            expected_names = {"crypto_obfuscated_func", "network_parsing_func"}
            assert (
                top_names == expected_names
            ), f"Triage failed to prioritize complex functions: {top_names}"

            mean_top = (
                sugs[0]["structural_entropy"] + sugs[1]["structural_entropy"]
            ) / 2.0
            mean_bottom = sum(s["structural_entropy"] for s in sugs[2:]) / 10.0

            tfr = mean_top / (mean_bottom or 1.0)
            print(f"Triage Focus Ratio (TFR): {tfr:.3f} (Expected > 2.0)")
            assert tfr > 2.0, f"Quality evaluation failed: TFR={tfr}"


def evaluate_bayesian_confidence_propagation():
    """
    Asserts that the Noisy-OR reasoner propagates confidence correctly:
    - Independent indicators should cause asymptotic growth of joint confidence toward 1.0.
    - Low-confidence indicators should not inflate synthesized risk profiles.
    """
    reasoner = VulnerabilityReasoner()

    # Base case: background leak only
    hits_empty = []
    res_empty = reasoner.reason(hits_empty)
    assert (
        len(res_empty) == 0
    )  # No profile is triggered if confidence <= background leak + 0.05

    # Single indicator format string (very low confidence of 0.02)
    hits_fmt_low = [{"behavior": "format_string_vuln", "confidence": 0.02}]
    res_low = reasoner.reason(hits_fmt_low)
    # Very low confidence shouldn't trigger profile
    assert len(res_low) == 0

    hits_fmt_high = [{"behavior": "format_string_vuln", "confidence": 0.9}]
    res_high = reasoner.reason(hits_fmt_high)
    assert len(res_high) == 1
    p_high = res_high[0]["confidence"]
    # P(V) = 1 - 0.95 * (1 - 0.90 * 0.90) = 1 - 0.95 * 0.19 = 1 - 0.1805 = 0.8195
    assert abs(p_high - 0.8195) < 1e-4

    # Adding more indicators to format string (e.g. format_string_vuln + integer_overflow + path_traversal)
    hits_multi = [
        {"behavior": "format_string_vuln", "confidence": 0.9},
        {"behavior": "integer_overflow", "confidence": 0.8},
        {"behavior": "path_traversal", "confidence": 0.75},
    ]
    res_multi = reasoner.reason(hits_multi)
    p_multi = next(
        h["confidence"]
        for h in res_multi
        if h["claim"] == "Improper Input Validation"
    )
    # P(V) should approach 1.0 (asymptotic confidence propagation)
    assert p_multi > p_high
    print(
        f"Bayesian Confidence Growth: Single={p_high:.4f} -> Multi-indicator={p_multi:.4f} (Correctly asymptotic)"
    )


def evaluate_federated_utility_stability():
    """
    Asserts that Q-value merging does not cause local optimal policy degradation.
    URS (Utility Rank Stability):
    Check if the local optimal action (highest Q-value) remains the top choice after merge.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        bank = PreferenceMemoryBank(db_path=db_path)

        # Local experiences: Action A (Q=0.8, visits=5), Action B (Q=0.4, visits=5)
        # Optimal action is Action A.
        bank.record("intent_x", "action_A", initial_q=0.8)
        bank.record("intent_x", "action_B", initial_q=0.4)

        with bank._conn() as conn:
            conn.execute("UPDATE memrl_triplets SET visit_count=5")
            conn.commit()

        # Incoming experience: Action A (Q=0.6, visits=3), Action B (Q=0.5, visits=3)
        incoming = [
            {
                "intent_key": "intent_x",
                "experience_key": "action_A",
                "q_value": 0.6,
                "visit_count": 3,
            },
            {
                "intent_key": "intent_x",
                "experience_key": "action_B",
                "q_value": 0.5,
                "visit_count": 3,
            },
        ]

        # Merge
        bank.merge_preferences(incoming)

        # Check post-merge values
        with bank._conn() as conn:
            rows = conn.execute(
                "SELECT experience_key, q_value FROM memrl_triplets ORDER BY q_value DESC"
            ).fetchall()

        # Highest Q-value must still be Action A (Optimal rank preserved)
        assert (
            rows[0][0] == "action_A"
        ), f"Optimal action rank degraded: top is {rows[0][0]}"
        print(
            f"Optimal action Q-value post-merge: {rows[0][1]:.3f} vs second: {rows[1][1]:.3f} (Optimal rank preserved)"
        )

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    print("=" * 75)
    print("Intelligence Phases 1-3 Quality and Accuracy Performance")
    print("=" * 75)
    evaluate_triage_prioritization_quality()
    evaluate_bayesian_confidence_propagation()
    evaluate_federated_utility_stability()
    print("=" * 75)
    print("All Quality and Accuracy Checks Passed!")
