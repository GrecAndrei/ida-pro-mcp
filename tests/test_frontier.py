"""Unit tests for FrontierEngine (host/frontier.py)."""
import math
import os
import sqlite3
import struct
import tempfile
import time
import unittest

from tests._isolated_repo_loader import load_host_module

_frontier_mod = load_host_module("frontier")
_blackboard_store_mod = load_host_module("blackboard_store")
FrontierEngine = _frontier_mod.FrontierEngine
_kmeans = _frontier_mod._kmeans
_cosine = _frontier_mod._cosine
BlackboardStore = _blackboard_store_mod.BlackboardStore
_pack_vec = _blackboard_store_mod._pack_vec


def _make_emb_db(path: str, entries: list) -> None:
    """Create a minimal embeddings DB with given (ea, name, vec) entries."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS func_embeddings (
            ea TEXT PRIMARY KEY, name TEXT, dim INTEGER,
            vec_blob BLOB NOT NULL, pseudo_hash TEXT, indexed_at REAL
        )
    """)
    for ea, name, vec in entries:
        blob = struct.pack(f"{len(vec)}f", *vec)
        conn.execute(
            "INSERT INTO func_embeddings VALUES (?,?,?,?,?,?)",
            (ea, name, len(vec), blob, "hash", time.time())
        )
    conn.commit()
    conn.close()


def _make_bb_db(path: str, entries: list) -> None:
    """Create a minimal blackboard DB with given entries."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blackboard (
            id TEXT PRIMARY KEY, category TEXT, title TEXT, content TEXT,
            addr TEXT, confidence REAL, created_at REAL, updated_at REAL,
            resolved INTEGER DEFAULT 0, contradicted INTEGER DEFAULT 0,
            source_type TEXT DEFAULT 'manual', tags TEXT,
            ioc_type TEXT, ioc_value TEXT, depends_on TEXT, blocks_addr TEXT,
            register TEXT, reg_type TEXT, evidence TEXT DEFAULT '[]',
            version INTEGER DEFAULT 1, entropy REAL DEFAULT 0.0,
            xref_count INTEGER DEFAULT 0, calibrated INTEGER DEFAULT 0,
            addr_end TEXT, contradiction_reason TEXT,
            bridges TEXT DEFAULT '{}', schema TEXT DEFAULT '{}',
            quantized BLOB, q_signs BLOB, norm REAL DEFAULT 0.0,
            call_idx INTEGER DEFAULT 0, q_value REAL DEFAULT 0.5,
            source TEXT DEFAULT 'manual', vector BLOB
        )
    """)
    for i, (addr, cat, title, conf) in enumerate(entries):
        conn.execute(
            "INSERT OR REPLACE INTO blackboard "
            "(id, category, title, addr, confidence, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (f"id_{i}", cat, title, addr, conf, time.time(), time.time())
        )
    conn.commit()
    conn.close()


class TestFrontierEngineBasic(unittest.TestCase):
    def setUp(self):
        self.FrontierEngine = FrontierEngine
        self.tmp = tempfile.mkdtemp()
        self.emb_db = os.path.join(self.tmp, "test.embeddings.db")
        self.bb_db = os.path.join(self.tmp, "test.blackboard.db")

        # 10 functions: 2 clusters of 5 (similar within cluster)
        dim = 8
        cluster_a = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        cluster_b = [0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0]

        entries = []
        for i in range(5):
            noise = [0.01 * i if j == i % dim else 0.0 for j in range(dim)]
            vec_a = [cluster_a[j] + noise[j] for j in range(dim)]
            vec_b = [cluster_b[j] + noise[j] for j in range(dim)]
            # Use 0x1000-based addresses so hex formatting is consistent
            entries.append((f"0x{0x1000 + i * 4:x}", f"func_a_{i}", vec_a))
            entries.append((f"0x{0x2000 + i * 4:x}", f"func_b_{i}", vec_b))

        _make_emb_db(self.emb_db, entries)
        # Don't pre-create bb_db — tests that need entries call _make_bb_db
        # Tests that don't need entries get an empty DB from FrontierEngine's _bb_conn

    def test_refresh_returns_count(self):
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        n = fe.refresh()
        self.assertEqual(n, 10)

    def test_refresh_builds_clusters(self):
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        self.assertEqual(len(fe._clusters), 10)
        self.assertEqual(len(fe._centroids), 2)
        # Functions in same cluster should have same cluster id
        # cluster_a functions should all be in one cluster
        a_clusters = [fe._clusters[i] for i, ea in enumerate(fe._ea_list) if "func_a" in fe._names.get(ea, "")]
        b_clusters = [fe._clusters[i] for i, ea in enumerate(fe._ea_list) if "func_b" in fe._names.get(ea, "")]
        self.assertEqual(len(set(a_clusters)), 1, "All func_a should be in same cluster")
        self.assertEqual(len(set(b_clusters)), 1, "All func_b should be in same cluster")
        self.assertNotEqual(a_clusters[0], b_clusters[0], "func_a and func_b should be in different clusters")

    def test_frontier_returns_all_unvisited_when_no_labels(self):
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        results = fe.frontier(limit=20)
        self.assertEqual(len(results), 10)
        for r in results:
            self.assertIn("addr", r)
            self.assertIn("score", r)
            self.assertIn("cluster", r)
            self.assertIn("proximity", r)

    def test_frontier_excludes_labeled_functions(self):
        # Label func_a_0
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        results = fe.frontier(limit=20)
        addrs = [r["addr"] for r in results]
        self.assertNotIn("0x1000", addrs, "Labeled function should not appear in frontier")
        self.assertEqual(len(results), 9)

    def test_frontier_scores_sorted_descending(self):
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        results = fe.frontier(limit=20)
        scores = [r["score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_frontier_proximity_higher_for_same_cluster(self):
        # Label func_a_0 — func_a_1..4 should have higher proximity than func_b_*
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        results = fe.frontier(limit=20)
        a_results = [r for r in results if "func_a" in r.get("name", "")]
        b_results = [r for r in results if "func_b" in r.get("name", "")]
        if a_results and b_results:
            avg_a_prox = sum(r["proximity"] for r in a_results) / len(a_results)
            avg_b_prox = sum(r["proximity"] for r in b_results) / len(b_results)
            self.assertGreater(avg_a_prox, avg_b_prox,
                               "Same-cluster functions should have higher proximity")

    def test_coverage_returns_correct_counts(self):
        _make_bb_db(self.bb_db, [
            ("0x1000", "hypothesis", "func A0", 0.9),
            ("0x1004", "hypothesis", "func A1", 0.8),
        ])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        cov = fe.coverage()
        self.assertEqual(cov["total_indexed"], 10)
        self.assertEqual(cov["analyzed"], 2)
        self.assertEqual(cov["unvisited"], 8)
        self.assertAlmostEqual(cov["coverage_pct"], 20.0, places=0)

    def test_coverage_cluster_breakdown(self):
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        cov = fe.coverage()
        self.assertIn("cluster_breakdown", cov)
        self.assertGreater(len(cov["cluster_breakdown"]), 0)
        # Sorted by least covered first
        pcts = [c["coverage_pct"] for c in cov["cluster_breakdown"]]
        self.assertEqual(pcts, sorted(pcts))

    def test_propagate_labels_writes_to_blackboard(self):
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        propagated = fe.propagate_labels()
        # Should propagate to other func_a functions (same cluster, high similarity)
        self.assertGreater(len(propagated), 0)
        for p in propagated:
            self.assertIn("addr", p)
            self.assertIn("confidence", p)
            self.assertIn("similarity", p)
            self.assertLessEqual(p["confidence"], 0.9)  # decayed

    def test_propagate_labels_respects_threshold(self):
        # Label func_a_0 — should NOT propagate to func_b (different cluster, low similarity)
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        propagated = fe.propagate_labels()
        propagated_addrs = {p["addr"] for p in propagated}
        # func_b addresses should not be propagated (cosine similarity too low)
        b_addrs = {f"0x{0x2000 + i * 4:x}" for i in range(5)}
        overlap = propagated_addrs & b_addrs
        self.assertEqual(len(overlap), 0, f"Should not propagate to different cluster: {overlap}")

    def test_propagate_labels_no_duplicate_writes(self):
        _make_bb_db(self.bb_db, [("0x1000", "hypothesis", "AES key schedule", 0.9)])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        p1 = fe.propagate_labels()
        p2 = fe.propagate_labels()  # second call should not re-propagate
        self.assertEqual(len(p2), 0, "Second propagation should find nothing new")

    def test_detect_contradictions_same_cluster_different_labels(self):
        # Label two func_a functions with different categories
        _make_bb_db(self.bb_db, [
            ("0x1000", "hypothesis", "AES key schedule", 0.9),
            ("0x1004", "vuln", "buffer overflow", 0.8),
        ])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        contradictions = fe.detect_contradictions()
        # Should flag the pair (same cluster, different categories)
        self.assertGreater(len(contradictions), 0)
        c = contradictions[0]
        self.assertIn("addr_a", c)
        self.assertIn("addr_b", c)
        self.assertIn("embedding_similarity", c)
        self.assertGreater(c["embedding_similarity"], 0.5)

    def test_detect_contradictions_different_clusters_no_flag(self):
        # Label one func_a and one func_b with different categories — should NOT flag
        _make_bb_db(self.bb_db, [
            ("0x1000", "hypothesis", "AES key schedule", 0.9),
            ("0x2000", "vuln", "buffer overflow", 0.8),
        ])
        fe = self.FrontierEngine(self.emb_db, self.bb_db)
        fe.refresh(k=2)
        contradictions = fe.detect_contradictions()
        # Different clusters — should not be flagged as contradiction
        self.assertEqual(len(contradictions), 0)

    def test_empty_embeddings_db(self):
        empty_db = os.path.join(self.tmp, "empty.embeddings.db")
        _make_emb_db(empty_db, [])
        fe = self.FrontierEngine(empty_db, self.bb_db)
        n = fe.refresh()
        self.assertEqual(n, 0)
        self.assertEqual(fe.frontier(), [])
        cov = fe.coverage()
        self.assertEqual(cov["total_indexed"], 0)

    def test_single_function(self):
        single_db = os.path.join(self.tmp, "single.embeddings.db")
        _make_emb_db(single_db, [("0x1000", "main", [1.0, 0.0, 0.0, 0.0])])
        fe = self.FrontierEngine(single_db, self.bb_db)
        n = fe.refresh()
        self.assertEqual(n, 1)
        results = fe.frontier()
        self.assertEqual(len(results), 1)


class TestFrontierKMeans(unittest.TestCase):
    def test_kmeans_assigns_all(self):
        vecs = [[1.0, 0.0], [0.9, 0.1], [0.0, 1.0], [0.1, 0.9]]
        assignments = _kmeans(vecs, k=2)
        self.assertEqual(len(assignments), 4)
        # First two should be in same cluster, last two in same cluster
        self.assertEqual(assignments[0], assignments[1])
        self.assertEqual(assignments[2], assignments[3])
        self.assertNotEqual(assignments[0], assignments[2])

    def test_kmeans_k_larger_than_n(self):
        vecs = [[1.0, 0.0], [0.0, 1.0]]
        assignments = _kmeans(vecs, k=10)
        self.assertEqual(len(assignments), 2)

    def test_kmeans_k_equals_1(self):
        vecs = [[1.0, 0.0], [0.0, 1.0], [0.5, 0.5]]
        assignments = _kmeans(vecs, k=1)
        self.assertEqual(set(assignments), {0})

    def test_cosine_similarity(self):
        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        self.assertAlmostEqual(_cosine(a, b), 1.0)
        c = [0.0, 1.0, 0.0]
        self.assertAlmostEqual(_cosine(a, c), 0.0)
        d = [-1.0, 0.0, 0.0]
        self.assertAlmostEqual(_cosine(a, d), -1.0)

    def test_cosine_zero_vector(self):
        self.assertAlmostEqual(_cosine([0.0, 0.0], [1.0, 0.0]), 0.0)


class TestFrontierAndBlackboardSmarter(unittest.TestCase):
    def setUp(self):
        self.FrontierEngine = FrontierEngine
        self.tmp = tempfile.mkdtemp()
        self.emb_db = os.path.join(self.tmp, "test.embeddings.db")
        self.bb_db = os.path.join(self.tmp, "test.blackboard.db")

        # 2 functions with distinct vectors
        self.dim = 8
        self.entries = [
            ("0x1000", "func_crypto", [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
            ("0x1004", "func_network", [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
        ]
        _make_emb_db(self.emb_db, self.entries)

    def tearDown(self):
        try:
            import shutil
            shutil.rmtree(self.tmp)
        except Exception:
            pass

    def test_frontier_with_query_semantic_scoring(self):
        import sys
        import types
        from unittest import mock

        class FakeEmbedder:
            def embed(self, text):
                # Returns vector that aligns with func_crypto
                return [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        class FakeClassifier:
            @classmethod
            def instance(cls, emb):
                return cls()
            def classify_vec(self, vec, **kw):
                return []

        fake_intel = types.ModuleType("ida_pro_mcp.host.intelligence.core")
        fake_intel.BgeCodeEmbedder = FakeEmbedder
        fake_intel.BehaviorClassifier = FakeClassifier

        with mock.patch.dict("sys.modules", {"ida_pro_mcp.host.intelligence.core": fake_intel}):
            fe = self.FrontierEngine(self.emb_db, self.bb_db)
            fe.refresh()
            # Query matches func_crypto
            results = fe.frontier(query="crypto")
            self.assertEqual(len(results), 2)
            # Crypto should be top ranked
            self.assertEqual(results[0]["addr"], "0x1000")
            self.assertEqual(results[0]["query_similarity"], 1.0)
            self.assertEqual(results[1]["query_similarity"], 0.0)

    def test_frontier_with_zero_shot_behavior_boost(self):
        import sys
        import types
        from unittest import mock

        class FakeEmbedder:
            def embed(self, text):
                return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        class FakeClassifier:
            @classmethod
            def instance(cls, emb):
                return cls()
            def classify_vec(self, vec, **kw):
                # If it's func_crypto vector
                if vec[0] > 0.9:
                    return [{"behavior": "crypto", "confidence": 0.8}]
                return []

        fake_intel = types.ModuleType("ida_pro_mcp.host.intelligence.core")
        fake_intel.BgeCodeEmbedder = FakeEmbedder
        fake_intel.BehaviorClassifier = FakeClassifier

        with mock.patch.dict("sys.modules", {"ida_pro_mcp.host.intelligence.core": fake_intel}):
            fe = self.FrontierEngine(self.emb_db, self.bb_db)
            fe.refresh()
            results = fe.frontier()
            # func_crypto has zero-shot behavior boost
            crypto_res = [r for r in results if r["addr"] == "0x1000"][0]
            network_res = [r for r in results if r["addr"] == "0x1004"][0]
            self.assertIn("crypto", crypto_res["detected_behaviors"])
            self.assertGreater(crypto_res["score"], network_res["score"])

    def test_next_target_with_query_semantic_scoring(self):
        import sys
        import types
        from unittest import mock

        class FakeEmbedder:
            def embed(self, text):
                return [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        fake_intel = types.ModuleType("ida_pro_mcp.host.intelligence_core")
        fake_intel.BgeCodeEmbedder = FakeEmbedder

        store = BlackboardStore(self.bb_db)

        # Write entries with vectors
        vec_crypto = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        vec_network = [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        with store._conn() as conn:
            conn.execute(
                "INSERT INTO blackboard (id, category, title, addr, confidence, created_at, updated_at, vector) "
                "VALUES (?,?,?,?,?,?,?,?)",
                ("id1", "general", "crypto stuff", "0x1000", 0.5, time.time(), time.time(), _pack_vec(vec_crypto))
            )
            conn.execute(
                "INSERT INTO blackboard (id, category, title, addr, confidence, created_at, updated_at, vector) "
                "VALUES (?,?,?,?,?,?,?,?)",
                ("id2", "general", "network stuff", "0x1004", 0.5, time.time(), time.time(), _pack_vec(vec_network))
            )
            conn.commit()

        # Query matches crypto
        with mock.patch.dict("sys.modules", {"ida_pro_mcp.host.intelligence_core": fake_intel, "host.intelligence_core": fake_intel}):
            targets = store.next_target(query="crypto")
            self.assertEqual(len(targets), 2)
            self.assertEqual(targets[0]["addr"], "0x1000")
            self.assertEqual(targets[0]["semantic_similarity"], 1.0)
            self.assertEqual(targets[1]["semantic_similarity"], 0.0)

    def test_next_target_with_query_keyword_fallback(self):
        store = BlackboardStore(self.bb_db)

        with store._conn() as conn:
            conn.execute(
                "INSERT INTO blackboard (id, category, title, content, addr, confidence, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                ("id1", "general", "crypto functions", "aes implementation", "0x1000", 0.5, time.time(), time.time())
            )
            conn.execute(
                "INSERT INTO blackboard (id, category, title, content, addr, confidence, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                ("id2", "general", "network functions", "http connection", "0x1004", 0.5, time.time(), time.time())
            )
            conn.commit()

        # Query matches keyword in title
        targets = store.next_target(query="aes")
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["addr"], "0x1000")
        self.assertEqual(targets[0]["semantic_similarity"], 0.5)
        self.assertEqual(targets[1]["semantic_similarity"], 0.0)


if __name__ == "__main__":
    unittest.main()
