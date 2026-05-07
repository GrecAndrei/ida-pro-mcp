#!/usr/bin/env python3
"""Tests for AttentionKernel smart features."""
import os
import sys
import json
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from ida_pro_mcp.host.attention_kernel import (
    BridgeSimilarityEngine,
    EpisodicLearner,
    ObligationKindQLearner,
    ObligationDependencyGraph,
    SemanticCropper,
    AttentionKernel,
)


class TestBridgeSimilarity(unittest.TestCase):
    def test_exact_match(self):
        e = BridgeSimilarityEngine(":memory:")
        self.assertEqual(e.address_proximity("0x140001000", "0x140001000"), 1.0)

    def test_nearby_addresses(self):
        e = BridgeSimilarityEngine(":memory:")
        self.assertEqual(e.address_proximity("0x140001000", "0x1400010ff"), 0.8)
        self.assertEqual(e.address_proximity("0x140001000", "0x140011000"), 0.5)
        self.assertEqual(e.address_proximity("0x140001000", "0x150001000"), 0.0)

    def test_bridge_similarity_exact(self):
        e = BridgeSimilarityEngine(":memory:")
        self.assertEqual(e.bridge_similarity({"0x140001000"}, {"0x140001000"}), 1.0)

    def test_bridge_similarity_nearby(self):
        e = BridgeSimilarityEngine(":memory:")
        sim = e.bridge_similarity({"0x140001000"}, {"0x1400010ff"})
        self.assertTrue(0.5 < sim < 1.0)

    def test_bridge_similarity_no_overlap(self):
        e = BridgeSimilarityEngine(":memory:")
        self.assertEqual(e.bridge_similarity({"0x140001000"}, {"0x150001000"}), 0.0)


class TestEpisodicLearner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "episodic.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_subsequence_matching(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        el = EpisodicLearner(conn_fn)
        el.record_sequence("s1", ["code:decompile", "funcs:rename", "code:decompile", "search:bytes"], "success", 0.5)
        el.record_sequence("s1", ["code:decompile", "funcs:rename", "code:decompile", "graph:callgraph"], "failure", -0.5)
        pred = el.predict_next_outcome("s1", ["code:decompile", "funcs:rename", "code:decompile"])
        self.assertIn(pred["outcome"], {"success", "failure"})
        self.assertTrue(pred["confidence"] > 0.0)

    def test_stuck_detection_repeated_tools(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        el = EpisodicLearner(conn_fn)
        # Manually insert observations for stuck detection
        with conn_fn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, session_id TEXT, ts REAL, tool TEXT, action TEXT)")
            for i in range(5):
                conn.execute("INSERT INTO observations VALUES(?, ?, ?, ?, ?)", (f"o{i}", "s1", float(i), "code", "decompile"))
            conn.commit()
        self.assertTrue(el.detect_stuck_pattern("s1"))

    def test_stuck_detection_failure_outcomes(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        el = EpisodicLearner(conn_fn)
        with conn_fn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, session_id TEXT, ts REAL, tool TEXT, action TEXT)")
            for i in range(3):
                conn.execute("INSERT INTO observations VALUES(?, ?, ?, ?, ?)", (f"o{i}", "s1", float(i), "code", "decompile"))
            conn.commit()
        el.record_sequence("s1", ["a", "b", "c", "d", "e"], "failure", -0.5)
        el.record_sequence("s1", ["a", "b", "c", "d", "e"], "failure", -0.5)
        el.record_sequence("s1", ["a", "b", "c", "d", "e"], "failure", -0.5)
        self.assertTrue(el.detect_stuck_pattern("s1"))


class TestObligationKindQLearner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "kind_q.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_q_update_resolved(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        q = ObligationKindQLearner(conn_fn)
        q.update("s1", "coverage_gap", resolved=True, overridden=False)
        val = q.get_enforcement_multiplier("s1", "coverage_gap")
        self.assertTrue(val > 1.0)

    def test_q_update_overridden(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        q = ObligationKindQLearner(conn_fn)
        q.update("s1", "shadow_warning", resolved=False, overridden=True)
        val = q.get_enforcement_multiplier("s1", "shadow_warning")
        self.assertTrue(val < 1.0)

    def test_q_clipping(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        q = ObligationKindQLearner(conn_fn)
        for _ in range(20):
            q.update("s1", "coverage_gap", resolved=True, overridden=False)
        val = q.get_enforcement_multiplier("s1", "coverage_gap")
        self.assertTrue(val <= 2.0)


class TestDependencyGraph(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "dep.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_record_and_predict(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        dg = ObligationDependencyGraph(conn_fn)
        dg.record_resolution_pair("coverage_gap", "narrative_gap", 1)
        dg.record_resolution_pair("coverage_gap", "narrative_gap", 2)
        preds = dg.get_predicted_resolution_time("coverage_gap", ["narrative_gap"])
        self.assertIn("narrative_gap", preds)
        self.assertTrue(preds["narrative_gap"]["co_resolution_rate"] > 0.3)

    def test_no_prediction_for_unrelated(self):
        def conn_fn():
            import sqlite3
            return sqlite3.connect(self.db_path)
        dg = ObligationDependencyGraph(conn_fn)
        preds = dg.get_predicted_resolution_time("coverage_gap", ["narrative_gap"])
        self.assertNotIn("narrative_gap", preds)


class TestSemanticCropper(unittest.TestCase):
    def test_no_crop_short_text(self):
        text = "line1\nline2\nline3"
        result = SemanticCropper.crop_decompile(text, {"0x140001000"})
        self.assertEqual(result, text)

    def test_preserves_bridge_lines(self):
        lines = [f"line {i}" for i in range(100)]
        lines[10] = "mov rax, 0x140001000"
        text = "\n".join(lines)
        result = SemanticCropper.crop_decompile(text, {"0x140001000"})
        self.assertIn("mov rax, 0x140001000", result)
        self.assertTrue(len(result.split('\n')) < len(lines))

    def test_preserves_string_lines(self):
        lines = [f"line {i}" for i in range(50)]
        lines[20] = 'push offset "http://example.com"'
        text = "\n".join(lines)
        result = SemanticCropper.crop_decompile(text, {"0x140001000"})
        self.assertIn('"http://example.com"', result)

    def test_reorder_xrefs(self):
        class FakeEngine:
            def bridge_similarity(self, a, b):
                if "0x140001000" in a and "0x140001000" in b:
                    return 1.0
                return 0.0
        xrefs = [
            {"addr": "0x140002000", "text": "call sub_1234"},
            {"addr": "0x140001000", "text": "mov rax, rbx"},
        ]
        reordered = SemanticCropper.reorder_xrefs(xrefs, {"0x140001000"}, FakeEngine())
        self.assertEqual(reordered[0]["addr"], "0x140001000")


class TestAttentionKernelIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "kernel.db")
        self.autogenic_path = os.path.join(self.tmpdir, "autogenic.db")
        self.kernel = AttentionKernel(db_path=self.db_path, autogenic_db_path=self.autogenic_path)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_end_to_end_obligation_lifecycle(self):
        # Create obligation
        self.kernel.add_obligation("s1", "coverage_gap", {"voids": [{"category": "import_table"}]}, "inspect_unseen_surface", bridges=["0x140001000"])
        unresolved = self.kernel.unresolved_obligations("s1")
        self.assertEqual(len(unresolved), 1)

        # Resolve with matching bridge
        self.kernel.observe_result("s1", "data", "imports", {"addr": "0x140001000"}, {"imports": [{"name": "LoadLibraryA"}]})
        unresolved = self.kernel.unresolved_obligations("s1")
        self.assertEqual(len(unresolved), 0)

    def test_preflight_blocks_high_impact(self):
        # Create multiple obligations to raise debt
        for i in range(5):
            self.kernel.add_obligation("s1", "coverage_gap", {"voids": []}, "inspect", bridges=[f"0x140{i:04x}"])

        pre = self.kernel.preflight("s1", "funcs", "rename", {"addr": "0x140001000"})
        self.assertEqual(pre["decision"], "block_high_impact")

    def test_preflight_allows_after_resolution(self):
        self.kernel.add_obligation("s1", "coverage_gap", {"voids": []}, "inspect", bridges=["0x140001000"])
        self.kernel.observe_result("s1", "data", "imports", {"addr": "0x140001000"}, {})
        pre = self.kernel.preflight("s1", "funcs", "rename", {"addr": "0x140001000"})
        self.assertEqual(pre["decision"], "allow")

    def test_shape_reorders_xrefs(self):
        self.kernel.add_obligation("s1", "coverage_gap", {"voids": []}, "inspect", bridges=["0x140001000"])
        pre = self.kernel.preflight("s1", "code", "decompile", {"addr": "0x140001000"})
        result = {"xrefs": [{"addr": "0x140002000"}, {"addr": "0x140001000"}]}
        shaped = self.kernel.shape_result(pre, result)
        self.assertEqual(shaped["xrefs"][0]["addr"], "0x140001000")

    def test_override_reduces_q(self):
        self.kernel.add_obligation("s1", "shadow_warning", {"warnings": []}, "disprove", bridges=["0x140001000"])
        oid = self.kernel.unresolved_obligations("s1")[0]["id"]
        q_before = self.kernel.kind_q_learner.get_enforcement_multiplier("s1", "shadow_warning")
        self.kernel.record_override("s1", oid, "funcs", "rename")
        q_after = self.kernel.kind_q_learner.get_enforcement_multiplier("s1", "shadow_warning")
        self.assertTrue(q_after < q_before)


if __name__ == "__main__":
    unittest.main()
