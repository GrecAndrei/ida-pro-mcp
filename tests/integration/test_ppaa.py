import contextlib
import os
import sqlite3
import unittest
from unittest.mock import MagicMock, patch

from tests._isolated_repo_loader import load_host_module

_ppaa_mod = load_host_module("intelligence.ppaa")
_structural_index_mod = load_host_module("intelligence.structural_index")
PPAAEngine = _ppaa_mod.PPAAEngine
get_db_path = _structural_index_mod.get_db_path

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
                call_count INTEGER,
                cfg_hash TEXT,
                reconstructed_structs TEXT
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
            (0x140001080, 'aes_decrypt_block', 128, '.text', 0, 0, 8, 4, 3, 2, 4.5, 5, 'a1b2c3d4e5f6g7h8', '[{"base_register": "rsi", "fields": [{"offset": 16, "offset_hex": "0x10", "type": "char"}]}]')
            """
        )
        self.conn.execute("INSERT INTO function_apis VALUES (0x140001080, 'memcpy')")
        self.conn.execute("INSERT INTO function_apis VALUES (0x140001080, 'memset')")
        self.conn.execute("INSERT INTO function_strings VALUES (0x140001080, 'AES Decrypt Error', 0x140080100)")
        self.conn.execute("INSERT INTO function_constants VALUES (0x140001080, 0x1010101, 'AES_CONSTANT')")
        self.conn.commit()

    def tearDown(self):
        with contextlib.suppress(Exception):
            self.conn.close()
        # Force any cached sqlite3 connections (created by PPAAEngine or
        # downstream helpers via WAL mode) to release the file. On Windows
        # a closed connection can still hold a transient lock; collect gc
        # and retry the remove.
        import gc
        import time
        gc.collect()
        for _ in range(5):
            if not os.path.exists(self.db_path):
                break
            try:
                os.remove(self.db_path)
                break
            except PermissionError:
                time.sleep(0.05)
                gc.collect()
        # SQLite WAL creates sidecar files; remove those too.
        for side in (self.db_path + "-wal", self.db_path + "-shm",
                     self.db_path + "-journal"):
            if os.path.exists(side):
                with contextlib.suppress(OSError):
                    os.remove(side)

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

    def test_query_string_metadata_success(self):
        engine = PPAAEngine(self.dummy_idb)
        str_meta = engine.query_string_metadata(0x140080100)
        self.assertIsNotNone(str_meta)
        self.assertEqual(str_meta["string_text"], "AES Decrypt Error")
        self.assertEqual(str_meta["referencing_function"], "aes_decrypt_block")

    def test_query_constant_usage_success(self):
        engine = PPAAEngine(self.dummy_idb)
        usages = engine.query_constant_usage(0x1010101)
        self.assertEqual(len(usages), 1)
        self.assertEqual(usages[0]["constant_name"], "AES_CONSTANT")
        self.assertEqual(usages[0]["used_in_function"], "aes_decrypt_block")

    def test_lazy_symbol_db_initialization(self):
        engine = PPAAEngine(self.dummy_idb)
        # Verify self._symbol_db is not initialized yet
        self.assertIsNone(engine._symbol_db)
        # Trigger property access
        sdb = engine.symbol_db
        self.assertIsNotNone(sdb)
        self.assertIsNotNone(engine._symbol_db)
