from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ida_pro_mcp.host.intelligence.analogy import CrossBinaryAnalogyEngine
from ida_pro_mcp.host.intelligence.structural_index import (
    ensure_tables,
    get_db_path,
    upsert_functions_batch,
)
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from ida_pro_mcp.host.session import SessionManager
from ida_pro_mcp.host.server_session import ServerSessionMixin
from ida_pro_mcp.host.errors import MCPError


def make_func_attrs(ea, name, **kwargs):
    attrs = {
        "ea": ea,
        "name": name,
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
        "xor_ratio": 0.1,
    }
    attrs.update(kwargs)
    return attrs


class TestCrossBinaryAnalogyEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.active_idb = os.path.join(self.tmpdir, "active_binary.i64")
        self.library_idb = os.path.join(self.tmpdir, "library_binary.i64")

        # Initialize structural DBs
        for path in [self.active_idb, self.library_idb]:
            db_path = get_db_path(path)
            conn = sqlite3.connect(db_path)
            ensure_tables(conn)
            conn.close()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_compute_analogy_score_thresholds(self):
        # 1. Cosine similarity fails
        cur_attrs = make_func_attrs(0x401000, "sub_401000")
        src_attrs = make_func_attrs(0x501000, "parse_config")
        cur_vector = [1.0, 0.0]
        src_vector = [0.0, 1.0]  # dot product = 0.0

        confidence, cosine_sim, struct_sim = CrossBinaryAnalogyEngine.compute_analogy_score(
            cur_attrs, src_attrs, cur_vector, src_vector, threshold_cosine=0.85
        )
        self.assertEqual(confidence, 0.0)

        # 2. Structural similarity fails
        cur_vector = [1.0, 0.0]
        src_vector = [1.0, 0.0]  # dot product = 1.0
        # Highly mismatched structures
        cur_attrs_diff = make_func_attrs(0x401000, "sub_401000", size=10, bb_count=1)
        src_attrs_diff = make_func_attrs(0x501000, "parse_config", size=1000, bb_count=50)

        confidence, cosine_sim, struct_sim = CrossBinaryAnalogyEngine.compute_analogy_score(
            cur_attrs_diff, src_attrs_diff, cur_vector, src_vector, threshold_structural=0.70
        )
        self.assertEqual(confidence, 0.0)

        # 3. Successful match
        confidence, cosine_sim, struct_sim = CrossBinaryAnalogyEngine.compute_analogy_score(
            cur_attrs, src_attrs, cur_vector, src_vector, threshold_cosine=0.85, threshold_structural=0.70
        )
        self.assertEqual(cosine_sim, 1.0)
        self.assertEqual(struct_sim, 1.0)
        self.assertEqual(confidence, 1.0)

    @patch("ida_pro_mcp.host.intelligence.analogy.BgeCodeEmbedder")
    def test_suggest_analogies_basic(self, mock_embedder_class):
        # 1. Setup mock BgeCodeEmbedder
        mock_embedder = MagicMock()
        mock_embedder.dim = 1536
        mock_embedder.backend = "tfidf-fallback"
        # Deterministic fixed-size vector
        mock_embedder.embed.return_value = [1.0] + [0.0] * 1535
        mock_embedder_class.return_value = mock_embedder
        mock_embedder_class.cosine.side_effect = lambda a, b: sum(x * y for x, y in zip(a, b))

        # 2. Populate active DB with a generic function
        conn_active = sqlite3.connect(get_db_path(self.active_idb))
        upsert_functions_batch(conn_active, [make_func_attrs(0x401000, "sub_401000")])
        conn_active.close()

        # Populate active embedding
        active_idx = FunctionEmbeddingIndex(self.active_idb + ".embeddings.db", mock_embedder)
        active_idx.index("0x401000", "sub_401000", "some text")

        # 3. Populate library DB with a named matching function
        conn_lib = sqlite3.connect(get_db_path(self.library_idb))
        upsert_functions_batch(conn_lib, [make_func_attrs(0x501000, "parse_config_packet")])
        conn_lib.close()

        # Populate library embedding
        lib_idx = FunctionEmbeddingIndex(self.library_idb + ".embeddings.db", mock_embedder)
        lib_idx.index("0x501000", "parse_config_packet", "some text")

        # Create library sideband comments
        sideband_path = os.path.splitext(self.library_idb)[0] + ".sideband"
        conn_sideband = sqlite3.connect(sideband_path)
        conn_sideband.execute("CREATE TABLE IF NOT EXISTS notes (title TEXT, body TEXT, kind TEXT)")
        conn_sideband.execute(
            "INSERT INTO notes (title, body, kind) VALUES (?, ?, ?)",
            ("parse_config_packet", "Decodes configuration packet from server", "function_comment")
        )
        conn_sideband.commit()
        conn_sideband.close()

        # Run suggestion engine
        engine = CrossBinaryAnalogyEngine()
        suggestions = engine.suggest_analogies(
            self.active_idb,
            [self.library_idb],
            threshold_cosine=0.85,
            threshold_structural=0.70,
        )

        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s["addr"], "0x401000")
        self.assertEqual(s["current_name"], "sub_401000")
        self.assertEqual(s["matched_name"], "parse_config_packet")
        self.assertEqual(s["matched_comment"], "Decodes configuration packet from server")
        self.assertEqual(s["confidence"], 1.0)
        self.assertEqual(s["source_idb"], self.library_idb)

    @patch("ida_pro_mcp.host.intelligence.analogy.BgeCodeEmbedder")
    def test_session_manager_integration(self, mock_embedder_class):
        mock_embedder = MagicMock()
        mock_embedder.dim = 1536
        mock_embedder.backend = "tfidf-fallback"
        mock_embedder.embed.return_value = [1.0] + [0.0] * 1535
        mock_embedder_class.return_value = mock_embedder
        mock_embedder_class.cosine.side_effect = lambda a, b: sum(x * y for x, y in zip(a, b))

        # Setup structural and embedding DBs
        conn_active = sqlite3.connect(get_db_path(self.active_idb))
        upsert_functions_batch(conn_active, [make_func_attrs(0x401000, "sub_401000")])
        conn_active.close()

        active_idx = FunctionEmbeddingIndex(self.active_idb + ".embeddings.db", mock_embedder)
        active_idx.index("0x401000", "sub_401000", "some text")

        conn_lib = sqlite3.connect(get_db_path(self.library_idb))
        upsert_functions_batch(conn_lib, [make_func_attrs(0x501000, "parse_config_packet")])
        conn_lib.close()

        lib_idx = FunctionEmbeddingIndex(self.library_idb + ".embeddings.db", mock_embedder)
        lib_idx.index("0x501000", "parse_config_packet", "some text")

        # Initialize SessionManager
        session_mgr = SessionManager(self.tmpdir)
        session_active = session_mgr.create_session(binary_path=os.path.join(self.tmpdir, "active.bin"))
        session_active.idb_path = self.active_idb
        session_mgr.sessions[session_active.session_id] = session_active
        session_mgr._save_metadata(session_active)

        session_lib = session_mgr.create_session(binary_path=os.path.join(self.tmpdir, "library.bin"))
        session_lib.idb_path = self.library_idb
        session_mgr.sessions[session_lib.session_id] = session_lib
        session_mgr._save_metadata(session_lib)

        # Call suggest_analogy
        res = session_mgr.suggest_analogy(session_active.session_id, limit=2)
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("session_id"), session_active.session_id)
        suggestions = res.get("suggestions", [])
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["matched_name"], "parse_config_packet")

    def test_apply_analogy_via_server(self):
        class DummyServer(ServerSessionMixin):
            def __init__(self, session_mgr):
                self.session_mgr = session_mgr
                self.current_session = None
                self.session_runtimes = {}
                self._session_capsules = {}
                self.call_tool = MagicMock()

        session_mgr = SessionManager(self.tmpdir)
        session = session_mgr.create_session(binary_path=os.path.join(self.tmpdir, "dummy.bin"))
        session.idb_path = self.active_idb
        session_mgr.sessions[session.session_id] = session

        srv = DummyServer(session_mgr)
        srv.call_tool.return_value = {"ok": True}

        # 1. Invalid args - no mappings
        res = srv._handle_session({"action": "apply_analogy", "session_id": session.session_id})
        self.assertFalse(res.get("ok"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)

        # 2. Valid mapping with rename and comment
        mappings = [
            {
                "addr": "0x401000",
                "name": "parse_packet",
                "comment": "Decodes network packet"
            }
        ]
        res = srv._handle_session({
            "action": "apply_analogy",
            "session_id": session.session_id,
            "mappings": mappings
        })

        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("applied"), 1)
        self.assertEqual(srv.call_tool.call_count, 2)
        
        # Check call arguments
        srv.call_tool.assert_any_call("modify", self.active_idb, action="rename", addr="0x401000", value="parse_packet")
        srv.call_tool.assert_any_call("modify", self.active_idb, action="comment", addr="0x401000", value="Decodes network packet", comment_type="repeatable")


if __name__ == "__main__":
    unittest.main()
