import os
import sqlite3
import unittest
from unittest.mock import MagicMock, patch

from src.ida_pro_mcp.host.intelligence.ppaa import PPAAEngine
from src.ida_pro_mcp.host.intelligence.structural_index import get_db_path

class TestPPAAEngine(unittest.TestCase):
    def setUp(self):
        self.dummy_idb = "dummy_test.idb"
        self.db_path = get_db_path(self.dummy_idb)
        
        # Ensure we start clean
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        # Create a mock SchemaBoot SQLite database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            """
            CREATE TABLE function_attrs (
                ea INTEGER PRIMARY KEY,
                name TEXT,
                size INTEGER,
                segment TEXT,
                is_thunk INTEGER,
                is_library INTEGER,
                bb_count INTEGER,
                cyclomatic_complexity INTEGER,
                incoming_xrefs INTEGER,
                outgoing_xrefs INTEGER,
                entropy REAL,
                call_count INTEGER
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE function_apis (
                func_ea INTEGER,
                api_name TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE function_strings (
                func_ea INTEGER,
                string_text TEXT,
                string_ea INTEGER
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE function_constants (
                func_ea INTEGER,
                constant_value INTEGER,
                constant_name TEXT
            )
            """
        )
        
        # Populate test data
        self.conn.execute(
            """
            INSERT INTO function_attrs VALUES 
            (0x140001080, 'aes_decrypt_block', 128, '.text', 0, 0, 8, 4, 3, 2, 4.5, 5)
            """
        )
        self.conn.execute("INSERT INTO function_apis VALUES (0x140001080, 'memcpy')")
        self.conn.execute("INSERT INTO function_apis VALUES (0x140001080, 'memset')")
        self.conn.execute("INSERT INTO function_strings VALUES (0x140001080, 'AES Decrypt Error', 0x140080100)")
        self.conn.execute("INSERT INTO function_constants VALUES (0x140001080, 0x1010101, 'AES_CONSTANT')")
        self.conn.commit()

    def tearDown(self):
        try:
            self.conn.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_ppaa_initialization(self):
        engine = PPAAEngine(self.dummy_idb)
        self.assertEqual(engine.db_path, self.db_path)

    def test_query_function_metadata_success(self):
        engine = PPAAEngine(self.dummy_idb)
        meta = engine.query_function_metadata(0x140001080)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["name"], "aes_decrypt_block")
        self.assertEqual(meta["size"], 128)
        self.assertEqual(meta["segment"], ".text")
        self.assertEqual(meta["referenced_apis"], ["memcpy", "memset"])
        self.assertEqual(len(meta["referenced_strings"]), 1)
        self.assertEqual(meta["referenced_strings"][0]["text"], "AES Decrypt Error")
        self.assertEqual(len(meta["referenced_constants"]), 1)
        self.assertEqual(meta["referenced_constants"][0]["name"], "AES_CONSTANT")

    def test_query_function_metadata_missing_ea(self):
        engine = PPAAEngine(self.dummy_idb)
        meta = engine.query_function_metadata(0x999999)
        self.assertIsNone(meta)

    def test_query_symbol_analogy_none_or_missing(self):
        engine = PPAAEngine(self.dummy_idb)
        # Verify symbolDB query doesn't crash even if mock is empty or absent
        analogy = engine.query_symbol_analogy("aes_decrypt_block")
        self.assertIsNone(analogy)

    def test_query_related_bridges_empty(self):
        engine = PPAAEngine(self.dummy_idb)
        # Should gracefully return empty list when no bridge match is found
        bridges = engine.query_related_bridges(0x140001080)
        self.assertEqual(bridges, [])
