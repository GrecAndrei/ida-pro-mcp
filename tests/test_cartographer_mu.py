#!/usr/bin/env python3
"""Tests for Cartographer-μ semantic engine components."""
import os
import sys
import json
import tempfile
import shutil
import unittest

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from ida_pro_mcp.host.cartographer_mu import (
    S4REncoder,
    TurboQuantLite,
    BridgeRAGLite,
    MemRLUtility,
    SchemaBootRE,
    ContextComposer,
    CartographerMu,
)


class TestS4REncoder(unittest.TestCase):
    def test_encode_shape(self):
        enc = S4REncoder(state_dim=128)
        v = enc.encode({"functions": [{"name": "sub_140001000"}]}, "functions")
        self.assertEqual(v.shape, (128,))
        self.assertAlmostEqual(float(v.dot(v)), 1.0, places=4)

    def test_determinism(self):
        enc = S4REncoder(state_dim=128)
        payload = {"addr": "0x140001000", "api": "VirtualAlloc"}
        v1 = enc.encode(payload, "code")
        v2 = enc.encode(payload, "code")
        self.assertTrue((v1 == v2).all())

    def test_different_inputs_different_outputs(self):
        enc = S4REncoder(state_dim=128)
        v1 = enc.encode({"addr": "0x140001000"}, "code")
        v2 = enc.encode({"addr": "0x140002000"}, "code")
        self.assertFalse((v1 == v2).all())


class TestTurboQuantLite(unittest.TestCase):
    def test_quantize_shape(self):
        tq = TurboQuantLite(dim=128)
        vec = np.random.randn(128).astype(np.float32)
        q, qs, norm = tq.encode(vec)
        self.assertEqual(q.shape, (128,))
        self.assertEqual(qs.shape, (128,))
        self.assertTrue(norm > 0)

    def test_similarity_range(self):
        tq = TurboQuantLite(dim=128)
        v1 = np.random.randn(128).astype(np.float32)
        v2 = np.random.randn(128).astype(np.float32)
        q1, qs1, n1 = tq.encode(v1)
        q2, qs2, n2 = tq.encode(v2)
        sim = tq.similarity(q1, qs1, n1, q2, qs2, n2)
        self.assertTrue(0.0 <= sim <= 1.0)

    def test_self_similarity_high(self):
        tq = TurboQuantLite(dim=128)
        v = np.random.randn(128).astype(np.float32)
        q, qs, n = tq.encode(v)
        sim = tq.similarity(q, qs, n, q, qs, n)
        self.assertTrue(sim > 0.9)


class TestBridgeRAGLite(unittest.TestCase):
    def test_extract_bridges(self):
        tq = TurboQuantLite(dim=128)
        br = BridgeRAGLite(tq)
        payload = {"functions": [{"addr": "0x140001000", "name": "sub_140001000"}]}
        bridges = br.extract_bridges(payload, "functions")
        self.assertTrue(len(bridges) > 0)
        self.assertTrue(all(isinstance(b, str) and b.startswith("b_") for b in bridges[:3]))

    def test_score_relevance_with_bridge_overlap(self):
        tq = TurboQuantLite(dim=128)
        br = BridgeRAGLite(tq)
        enc = S4REncoder(state_dim=128)
        payload = {"addr": "0x140001000"}
        vec = enc.encode(payload, "code")
        q = tq.encode(vec)
        entry = {
            "bridges": ["0x140001000"],
            "quantized": q[0].tobytes(),
            "q_signs": q[1].tobytes(),
            "norm": q[2],
        }
        score, breakdown = br.score_relevance(
            ["0x140001000"], vec, q, entry, call_age=0
        )
        self.assertTrue(score > 0.4)  # High bridge overlap should give high score
        self.assertIn("exact_addr", breakdown)  # Should have exact address match


class TestMemRLUtility(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_q.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_q_update(self):
        memrl = MemRLUtility(alpha=0.5, db_path=self.db_path)
        self.assertAlmostEqual(memrl.get_q("e1"), 0.5)
        memrl.update_q("e1", 1.0)
        self.assertAlmostEqual(memrl.get_q("e1"), 0.75)

    def test_observe_usage_reward(self):
        memrl = MemRLUtility(alpha=0.5, db_path=self.db_path)
        memrl.observe_usage("e1", True, ["0x140001000"], ["0x140001000"])
        self.assertTrue(memrl.get_q("e1") > 0.5)

    def test_rank_entries(self):
        memrl = MemRLUtility(alpha=0.5, db_path=self.db_path)
        memrl.update_q("e1", 1.0)
        memrl.update_q("e2", 0.2)
        ranked = memrl.rank_entries(["e2", "e1"])
        self.assertEqual(ranked[0][1], "e1")


class TestSchemaBootRE(unittest.TestCase):
    def setUp(self):
        # Clear learned classifier weights to ensure cold-start behavior
        import os
        db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "phase_classifier.db")
        if os.path.exists(db_path):
            os.remove(db_path)

    def test_induce_schema_addr(self):
        sb = SchemaBootRE()
        schema = sb.induce_schema({"addr": "0x140001000"}, "code")
        self.assertTrue(schema["has_addr"])
        self.assertEqual(schema["phase_hint"], "triage")

    def test_induce_schema_api(self):
        sb = SchemaBootRE()
        schema = sb.induce_schema({"api": "VirtualAlloc"}, "code")
        self.assertIn("has_api", schema)
        self.assertIn(schema["phase_hint"], {"triage", "behavioral_analysis", "threat_analysis"})

    def test_pre_filter_phase_match(self):
        sb = SchemaBootRE()
        entries = [
            {"schema": {"phase_hint": "threat_analysis"}},
            {"schema": {"phase_hint": "triage"}},
        ]
        query = {"phase_hint": "threat_analysis"}
        filtered = sb.pre_filter(entries, query)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["schema"]["phase_hint"], "threat_analysis")


class TestContextComposer(unittest.TestCase):
    def test_compose_selects_relevant(self):
        enc = S4REncoder(state_dim=128)
        tq = TurboQuantLite(dim=128)
        br = BridgeRAGLite(tq)
        memrl = MemRLUtility(alpha=0.5)
        sb = SchemaBootRE()
        composer = ContextComposer(enc, tq, br, memrl, sb, topk=2)

        entries = [
            {"id": "a1", "title": "sub_140001000", "addr": "0x140001000", "category": "finding",
             "bridges": ["0x140001000"], "schema": {"phase_hint": "triage"}, "call_idx": 1},
            {"id": "b2", "title": "VirtualAlloc", "addr": "", "category": "finding",
             "bridges": ["VirtualAlloc"], "schema": {"phase_hint": "behavioral_analysis"}, "call_idx": 2},
        ]

        result = composer.compose("code", "decompile", {"addr": "0x140001000"}, entries)
        self.assertTrue(len(result["working_memory"]) <= 2)
        self.assertIn("memory_stats", result)
        self.assertIn("analysis_phase", result)


class TestCartographerMuIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_q.db")
        self.cm = CartographerMu(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_pipeline(self):
        entries = [
            {"id": "a1", "title": "sub_140001000", "addr": "0x140001000", "category": "finding",
             "bridges": ["0x140001000"], "schema": {"phase_hint": "triage"}, "q_value": 0.5, "call_idx": 1},
        ]
        result = self.cm.inject_context("code", "decompile", {"addr": "0x140001000"}, entries)
        self.assertIn("working_memory", result)
        self.assertIn("analysis_phase", result)

    def test_memrl_learning(self):
        self.cm.observe_usage("e1", True, ["0x140001000"], ["0x140001000"])
        self.assertTrue(self.cm.get_q("e1") > 0.5)


if __name__ == "__main__":
    unittest.main()
