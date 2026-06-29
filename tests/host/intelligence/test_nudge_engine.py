from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp.host.intelligence.entropy import FunctionEntropyCalculator
from ida_pro_mcp.services import (
    SessionManager,
    ensure_tables,
    get_db_path,
    upsert_functions_batch,
)


class TestNudgeEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.idb_path = os.path.join(self.tmpdir, "test_binary.i64")

        # Initialize structural database schema
        self.db_path = get_db_path(self.idb_path)
        conn = sqlite3.connect(self.db_path)
        ensure_tables(conn)
        conn.close()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_instruction_entropy_math(self):
        # Even distribution of 4 instructions -> entropy = -4 * (0.25 * log2(0.25)) = 2.0
        row = {
            "xor_count": 5,
            "mov_count": 5,
            "cmp_count": 5,
            "jmp_count": 5,
            "ret_count": 0,
        }
        ent = FunctionEntropyCalculator.compute_instruction_entropy(row)
        self.assertAlmostEqual(ent, 2.0)

        # 0 instruction count -> entropy = 0.0
        self.assertEqual(FunctionEntropyCalculator.compute_instruction_entropy({}), 0.0)

    def test_structural_entropy_bounds(self):
        # Empty row / thunk
        row = {
            "cyclomatic_complexity": 1,
            "bb_count": 1,
            "entropy": 0.0,
            "xor_ratio": 0.0,
            "api_count": 0,
        }
        score = FunctionEntropyCalculator.compute_structural_entropy(row)
        self.assertTrue(0.0 <= score <= 1.0)

        # High complexity row
        high_row = {
            "cyclomatic_complexity": 50,
            "bb_count": 80,
            "entropy": 7.5,
            "xor_count": 20,
            "mov_count": 10,
            "xor_ratio": 0.66,
            "api_count": 15,
        }
        high_score = FunctionEntropyCalculator.compute_structural_entropy(high_row)
        self.assertTrue(0.0 <= high_score <= 1.0)
        self.assertGreater(high_score, score)

    @patch("ida_pro_mcp.host.intelligence.entropy.BgeCodeEmbedder")
    def test_compute_triage_suggestions(self, mock_embedder_class):
        # Mock the embedder and its cosine classmethod
        mock_embedder = MagicMock()
        # Mock embed method to return a dummy vector (1536 floats)
        dummy_vec = [1.0] + [0.0] * 1535
        mock_embedder.embed.return_value = dummy_vec
        mock_embedder_class.return_value = mock_embedder
        mock_embedder_class.cosine.side_effect = lambda a, b: sum(
            x * y for x, y in zip(a, b, strict=False)
        )

        # Insert some mock functions to structural database
        # We have one high entropy function and one low entropy function
        conn = sqlite3.connect(self.db_path)

        # We will use upsert_functions_batch to populate structural index
        funcs = [
            {
                "ea": 0x401000,
                "name": "complex_func",
                "size": 500,
                "segment": ".text",
                "is_thunk": 0,
                "is_library": 0,
                "bb_count": 20,
                "cyclomatic_complexity": 15,
                "incoming_xrefs": 2,
                "outgoing_xrefs": 5,
                "entropy": 6.8,
                "call_count": 5,
                "xor_count": 10,
                "mov_count": 20,
                "cmp_count": 5,
                "jmp_count": 2,
                "ret_count": 1,
                "push_count": 5,
                "pop_count": 5,
                "lea_count": 3,
                "test_count": 2,
                "api_count": 4,
                "string_count": 2,
                "data_ref_count": 1,
                "has_loops": 1,
                "max_loop_depth": 2,
                "xor_ratio": 0.33,
            },
            {
                "ea": 0x402000,
                "name": "simple_thunk",
                "size": 16,
                "segment": ".text",
                "is_thunk": 0,
                "is_library": 0,
                "bb_count": 1,
                "cyclomatic_complexity": 1,
                "incoming_xrefs": 1,
                "outgoing_xrefs": 0,
                "entropy": 1.2,
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
            },
        ]
        upsert_functions_batch(conn, funcs)
        conn.close()

        # Instantiate calculator
        calc = FunctionEntropyCalculator()

        # 1. Test triage suggestions without context (unexplored)
        sugs = calc.compute_triage_suggestions(self.idb_path, limit=2)
        self.assertEqual(len(sugs), 2)

        # The complex function should be ranked first
        self.assertEqual(sugs[0]["name"], "complex_func")
        self.assertEqual(sugs[0]["ea"], "0x401000")
        self.assertFalse(sugs[0]["explored"])

        # 2. Test triage suggestions with context
        sugs_ctx = calc.compute_triage_suggestions(
            self.idb_path, context="find crypto key", limit=2
        )
        self.assertEqual(len(sugs_ctx), 2)
        self.assertEqual(sugs_ctx[0]["name"], "complex_func")

    @patch("ida_pro_mcp.host.intelligence.entropy.BgeCodeEmbedder")
    def test_session_manager_suggest_triage(self, mock_embedder_class):
        mock_embedder = MagicMock()
        dummy_vec = [1.0] + [0.0] * 1535
        mock_embedder.embed.return_value = dummy_vec
        mock_embedder_class.return_value = mock_embedder
        mock_embedder_class.cosine.side_effect = lambda a, b: sum(
            x * y for x, y in zip(a, b, strict=False)
        )

        # Insert structural features to DB
        conn = sqlite3.connect(self.db_path)
        upsert_functions_batch(
            conn,
            [
                {
                    "ea": 0x401000,
                    "name": "some_func",
                    "size": 100,
                    "segment": ".text",
                    "is_thunk": 0,
                    "is_library": 0,
                    "bb_count": 5,
                    "cyclomatic_complexity": 3,
                    "incoming_xrefs": 1,
                    "outgoing_xrefs": 1,
                    "entropy": 4.5,
                    "call_count": 1,
                    "xor_count": 1,
                    "mov_count": 5,
                    "cmp_count": 1,
                    "jmp_count": 1,
                    "ret_count": 1,
                    "push_count": 2,
                    "pop_count": 2,
                    "lea_count": 1,
                    "test_count": 1,
                    "api_count": 1,
                    "string_count": 0,
                    "data_ref_count": 0,
                    "has_loops": 0,
                    "xor_ratio": 0.16,
                }
            ],
        )
        conn.close()

        # Initialize SessionManager
        session_mgr = SessionManager(self.tmpdir)
        session = session_mgr.create_session(
            binary_path=os.path.join(self.tmpdir, "dummy.bin")
        )

        # Set session idb_path
        session.idb_path = self.idb_path
        session_mgr.sessions[session.session_id] = session

        # Call suggest_triage action
        res = session_mgr.suggest_triage(
            session.session_id, context="look for decoder", limit=1
        )
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("session_id"), session.session_id)

        sugs = res.get("suggestions", [])
        self.assertEqual(len(sugs), 1)
        self.assertEqual(sugs[0]["name"], "some_func")

    def test_nudge_engine_edge_cases(self):
        calc = FunctionEntropyCalculator()

        # 1. Non-existent database path should return empty suggestions list
        self.assertEqual(calc.compute_triage_suggestions("non_existent_file.i64"), [])

        # 2. Empty/new database with no functions should return empty list
        empty_idb = os.path.join(self.tmpdir, "empty_binary.i64")
        empty_db = get_db_path(empty_idb)
        conn = sqlite3.connect(empty_db)
        ensure_tables(conn)
        conn.close()
        self.assertEqual(calc.compute_triage_suggestions(empty_idb), [])

        # 3. Instruction entropy with nulls or empty dict -> 0.0
        self.assertEqual(FunctionEntropyCalculator.compute_instruction_entropy({}), 0.0)
        self.assertEqual(FunctionEntropyCalculator.compute_instruction_entropy({"xor_count": None}), 0.0)

