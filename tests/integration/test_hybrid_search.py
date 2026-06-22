"""
Tests for HybridSearch — SQL pre-filtering for structured semantic retrieval.

These tests exercise the standalone modules (hybrid_search.py) that have
NO IDA Pro dependencies. They use only sqlite3 and the standard library.
"""

import os
import sys
import sqlite3
import time
import unittest
from typing import Any, Dict, List

# Ensure the source is importable
SRC_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools")
)
SUPPORT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "support")
)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if SUPPORT_DIR not in sys.path:
    sys.path.insert(0, SUPPORT_DIR)


# ============================================================================
# Test: HybridQueryBuilder — SQL WHERE clause construction
# ============================================================================

class TestHybridQueryBuilder(unittest.TestCase):
    """Test SQL WHERE clause generation from constraints."""

    def _import(self):
        """Lazy import to handle missing test env gracefully."""
        from hybrid_search import HybridQueryBuilder
        return HybridQueryBuilder

    def test_empty_constraints(self):
        QB = self._import()
        where, params, junctions = QB.build({})
        self.assertEqual(where, "")
        self.assertEqual(params, [])
        self.assertEqual(junctions, [])

    def test_legacy_min_max(self):
        QB = self._import()
        where, params, junctions = QB.build({"min_size": 100, "max_entropy": 6.0})
        self.assertIn("fa.size >= ?", where)
        self.assertIn("fa.entropy <= ?", where)
        self.assertIn(100, params)
        self.assertIn(6.0, params)

    def test_legacy_boolean(self):
        QB = self._import()
        where, params, _ = QB.build({"has_loops": True, "is_thunk": False})
        self.assertIn("fa.has_loops = ?", where)
        self.assertIn("fa.is_thunk = ?", where)
        # Check booleans normalized to 1/0
        idx_loops = where.find("fa.has_loops = ?")
        idx_thunk = where.find("fa.is_thunk = ?")
        # params order matches condition order
        self.assertIn(1, params)  # has_loops=True → 1
        self.assertIn(0, params)  # is_thunk=False → 0

    def test_legacy_apis(self):
        QB = self._import()
        where, params, junctions = QB.build({"apis": "VirtualAlloc"})
        self.assertIn("EXISTS", where)
        self.assertIn("function_apis", where)
        self.assertIn("api_name = ?", where)
        self.assertIn("VirtualAlloc", params)
        self.assertIn("apis", junctions)

    def test_legacy_name_like(self):
        QB = self._import()
        where, params, _ = QB.build({"name_like": "crypt"})
        self.assertIn("fa.name LIKE ?", where)
        self.assertIn("%crypt%", params)

    def test_legacy_strings_like(self):
        QB = self._import()
        where, params, _ = QB.build({"strings_like": "http"})
        self.assertIn("EXISTS", where)
        self.assertIn("string_text LIKE ?", where)
        self.assertIn("%http%", params)

    def test_operator_format_eq(self):
        QB = self._import()
        where, params, _ = QB.build({"size": ("==", 100)})
        self.assertIn("fa.size = ?", where)
        self.assertIn(100, params)

    def test_operator_format_ne(self):
        QB = self._import()
        where, params, _ = QB.build({"segment": ("!=", ".text")})
        self.assertIn("fa.segment != ?", where)
        self.assertIn(".text", params)

    def test_operator_format_range(self):
        QB = self._import()
        where, params, _ = QB.build({"size": (">=", 100), "size": ("<=", 500)})
        # The second "size" overwrites the first since dict
        self.assertIn("fa.size <= ?", where)

    def test_operator_format_contains(self):
        QB = self._import()
        where, params, _ = QB.build({"name": ("contains", "crypt")})
        self.assertIn("fa.name LIKE ?", where)
        self.assertIn("%crypt%", params)

    def test_operator_format_regex(self):
        QB = self._import()
        # Regex should produce a LIKE pre-filter
        where, params, _ = QB.build({"name": ("~", r"crypt.*")})
        self.assertIn("fa.name LIKE ?", where)
        self.assertIn("%crypt.*%", params)

    def test_mixed_legacy_and_operator(self):
        QB = self._import()
        where, params, _ = QB.build({
            "min_size": 100,
            "has_loops": True,
            "apis": "VirtualAlloc",
        })
        self.assertIn("fa.size >= ?", where)
        self.assertIn("fa.has_loops = ?", where)
        self.assertIn("EXISTS", where)
        self.assertIn(100, params)
        self.assertIn(1, params)
        self.assertIn("VirtualAlloc", params)

    def test_unknown_keys_skipped(self):
        QB = self._import()
        where, params, _ = QB.build({
            "min_size": 100,
            "behavior_tags": "crypto",  # not SQL-filterable, should be skipped
            "nonexistent_key": 42,
        })
        self.assertIn("fa.size >= ?", where)
        self.assertNotIn("behavior", where)

    def test_none_values_skipped(self):
        QB = self._import()
        where, params, _ = QB.build({"min_size": None, "max_size": 200})
        self.assertEqual(where, "WHERE fa.size <= ?")
        self.assertEqual(params, [200])


# ============================================================================
# Test: Constraint parsing
# ============================================================================

class TestConstraintParsing(unittest.TestCase):
    """Test the _parse_constraints function directly."""

    def _import(self):
        from hybrid_search import _parse_constraints
        return _parse_constraints

    def test_legacy_min_max(self):
        parse = self._import()
        result = parse({"min_size": 100, "max_entropy": 6.0})
        self.assertIn(("size", ">=", 100), result)
        self.assertIn(("entropy", "<=", 6.0), result)

    def test_legacy_bool(self):
        parse = self._import()
        result = parse({"has_loops": True, "is_thunk": False})
        self.assertIn(("has_loops", "==", 1), result)
        self.assertIn(("is_thunk", "==", 0), result)

    def test_operator_format(self):
        parse = self._import()
        result = parse({"size": (">=", 100), "name": ("~", "crypt.*")})
        self.assertIn(("size", ">=", 100), result)
        self.assertIn(("name", "~", "crypt.*"), result)

    def test_dict_format(self):
        parse = self._import()
        result = parse({"size": {"gte": 100, "lte": 500}})
        self.assertIn(("size", ">=", 100), result)
        self.assertIn(("size", "<=", 500), result)


# ============================================================================
# Test: HybridSearchEngine — SQL pre-filter execution
# ============================================================================

class TestHybridSearchEngine(unittest.TestCase):
    """Test SQL pre-filter execution against a file-backed schemaboot DB."""

    @classmethod
    def setUpClass(cls):
        """Create a file-backed schemaboot DB with test data."""
        import tempfile
        cls._tmpfile = tempfile.NamedTemporaryFile(suffix=".schemaboot.db", delete=False)
        cls.db_path = cls._tmpfile.name
        cls._tmpfile.close()

        conn = sqlite3.connect(cls.db_path)

        # Create tables matching schemaboot schema
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS function_attrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ea INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                segment TEXT,
                is_thunk INTEGER DEFAULT 0,
                is_library INTEGER DEFAULT 0,
                bb_count INTEGER DEFAULT 0,
                cyclomatic_complexity INTEGER DEFAULT 0,
                incoming_xrefs INTEGER DEFAULT 0,
                outgoing_xrefs INTEGER DEFAULT 0,
                entropy REAL DEFAULT 0.0,
                call_count INTEGER DEFAULT 0,
                xor_count INTEGER DEFAULT 0,
                mov_count INTEGER DEFAULT 0,
                cmp_count INTEGER DEFAULT 0,
                jmp_count INTEGER DEFAULT 0,
                ret_count INTEGER DEFAULT 0,
                push_count INTEGER DEFAULT 0,
                pop_count INTEGER DEFAULT 0,
                lea_count INTEGER DEFAULT 0,
                test_count INTEGER DEFAULT 0,
                api_count INTEGER DEFAULT 0,
                string_count INTEGER DEFAULT 0,
                data_ref_count INTEGER DEFAULT 0,
                has_loops INTEGER DEFAULT 0,
                max_loop_depth INTEGER DEFAULT 0,
                has_crypto_constants INTEGER DEFAULT 0,
                xor_ratio REAL DEFAULT 0.0,
                created_at REAL DEFAULT 0.0,
                updated_at REAL DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS function_apis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                func_ea INTEGER NOT NULL,
                api_name TEXT NOT NULL,
                FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
            );
            CREATE TABLE IF NOT EXISTS function_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                func_ea INTEGER NOT NULL,
                string_text TEXT NOT NULL,
                string_ea INTEGER NOT NULL,
                FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
            );
            CREATE TABLE IF NOT EXISTS function_constants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                func_ea INTEGER NOT NULL,
                constant_value INTEGER NOT NULL,
                constant_name TEXT,
                FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
            );
            CREATE INDEX IF NOT EXISTS idx_apis_func ON function_apis(func_ea);
            CREATE INDEX IF NOT EXISTS idx_apis_name ON function_apis(api_name);
            CREATE INDEX IF NOT EXISTS idx_strings_func ON function_strings(func_ea);
        """)

        # Insert test functions
        test_funcs = [
            (0x401000, "main", 500, ".text", 0, 0, 12, 8, 5, 3, 5.2,
             8, 3, 10, 4, 2, 1, 2, 3, 1, 2, 2, 3, 1, 0, 0, 0, 0.01),
            (0x402000, "crypto_Handler", 1200, ".text", 0, 0, 30, 15, 2, 5, 6.8,
             15, 12, 20, 8, 5, 2, 6, 8, 4, 6, 5, 4, 2, 1, 3, 1, 0.08),
            (0x403000, "helper_func", 80, ".text", 1, 0, 3, 2, 10, 1, 3.5,
             2, 0, 3, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0.0),
            (0x404000, "thunk_stub", 20, ".text", 1, 1, 1, 1, 1, 0, 1.2,
             1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0),
            (0x405000, "network_io", 800, ".text", 0, 0, 18, 10, 12, 8, 5.5,
             20, 0, 25, 6, 8, 2, 5, 6, 2, 4, 4, 2, 0, 0, 0, 0, 0.0),
            (0x406000, "decrypt_data", 950, ".text", 0, 0, 25, 14, 3, 4, 7.1,
             10, 15, 18, 7, 4, 2, 4, 5, 3, 5, 6, 3, 1, 1, 4, 1, 0.12),
            (0x407000, "setup_env", 150, ".data", 0, 1, 5, 3, 2, 1, 4.0,
             2, 0, 4, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0.0),
        ]

        for tf in test_funcs:
            conn.execute("""
                INSERT INTO function_attrs (
                    ea, name, size, segment, is_thunk, is_library,
                    bb_count, cyclomatic_complexity, incoming_xrefs, outgoing_xrefs,
                    entropy, call_count, xor_count, mov_count, cmp_count,
                    jmp_count, ret_count, push_count, pop_count, lea_count,
                    test_count, api_count, string_count, data_ref_count,
                    has_loops, max_loop_depth, has_crypto_constants, xor_ratio
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, tf)

        # Insert APIs
        api_data = [
            (0x401000, "printf"),
            (0x401000, "malloc"),
            (0x402000, "AES_set_encrypt_key"),
            (0x402000, "memcpy"),
            (0x402000, "malloc"),
            (0x405000, "socket"),
            (0x405000, "connect"),
            (0x405000, "send"),
            (0x405000, "recv"),
            (0x406000, "VirtualAlloc"),
            (0x406000, "memcpy"),
            (0x406000, "AES_cbc_encrypt"),
        ]
        for ea, api in api_data:
            conn.execute("INSERT INTO function_apis (func_ea, api_name) VALUES (?, ?)", (ea, api))

        # Insert strings
        string_data = [
            (0x401000, "Hello, World!", 0x500000),
            (0x402000, "https://crypto.example.com/key", 0x500010),
            (0x405000, "http://malware.example.com/beacon", 0x500020),
            (0x406000, "Encryption key loaded", 0x500030),
        ]
        for ea, text, addr in string_data:
            conn.execute(
                "INSERT INTO function_strings (func_ea, string_text, string_ea) VALUES (?, ?, ?)",
                (ea, text, addr),
            )

        # Insert crypto constants
        conn.execute(
            "INSERT INTO function_constants (func_ea, constant_value, constant_name) VALUES (?, ?, ?)",
            (0x402000, 0x67452301, "MD5_A"),
        )
        conn.execute(
            "INSERT INTO function_constants (func_ea, constant_value, constant_name) VALUES (?, ?, ?)",
            (0x406000, 0x6A09E667, "SHA256_H0"),
        )

        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.db_path)

    def _import(self):
        from hybrid_search import HybridSearchEngine
        return HybridSearchEngine

    def test_pre_filter_empty_constraints(self):
        """Empty constraints should match ALL functions."""
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({})
        self.assertIsNotNone(eas)
        self.assertGreater(len(eas), 0)

    def test_pre_filter_min_size(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"min_size": 500})
        self.assertIsNotNone(eas)
        # Functions with size >= 500: 0x401000 (500), 0x402000 (1200), 0x405000 (800), 0x406000 (950)
        self.assertEqual(len(eas), 4)
        expected = {0x401000, 0x402000, 0x405000, 0x406000}
        self.assertEqual(set(eas), expected)

    def test_pre_filter_max_size(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"max_size": 100})
        self.assertIsNotNone(eas)
        # Functions with size <= 100: 0x403000 (80), 0x404000 (20)
        self.assertEqual(len(eas), 2)

    def test_pre_filter_has_loops(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"has_loops": True})
        self.assertIsNotNone(eas)
        # Functions with loops: 0x402000 (crypto_Handler), 0x406000 (decrypt_data)
        self.assertEqual(len(eas), 2)
        self.assertIn(0x402000, eas)
        self.assertIn(0x406000, eas)

    def test_pre_filter_apis(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"apis": "AES_set_encrypt_key"})
        self.assertIsNotNone(eas)
        self.assertEqual(len(eas), 1)
        self.assertIn(0x402000, eas)

    def test_pre_filter_entropy_range(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"min_entropy": 5.0, "max_entropy": 6.5})
        self.assertIsNotNone(eas)
        # entropy >= 5.0 and <= 6.5: 0x401000 (5.2), 0x405000 (5.5)
        self.assertEqual(len(eas), 2)

    def test_pre_filter_combined(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({
            "min_size": 500,
            "min_xor_count": 5,
            "has_crypto_constants": True,
        })
        self.assertIsNotNone(eas)
        # 0x402000 (size=1200, xor=12, crypto=1), 0x406000 (size=950, xor=15, crypto=1)
        self.assertEqual(len(eas), 2)

    def test_pre_filter_no_matches(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"min_size": 99999})
        self.assertIsNotNone(eas)
        self.assertEqual(len(eas), 0)

    def test_pre_filter_junction_strings(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"strings_like": "http"})
        self.assertIsNotNone(eas)
        # Functions referencing strings containing "http": 0x402000, 0x405000
        self.assertEqual(len(eas), 2)
        self.assertIn(0x402000, eas)
        self.assertIn(0x405000, eas)

    def test_pre_filter_is_library(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        eas, elapsed, meta = engine.pre_filter({"is_library": True})
        self.assertIsNotNone(eas)
        self.assertEqual(len(eas), 2)  # 0x404000 (is_library=1), 0x407000 (is_library=1)

    def test_search_full_results(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        result = engine.search({"min_size": 500}, top_k=10)
        self.assertTrue(result["ok"])
        self.assertEqual(result["total_matches"], 4)
        self.assertGreaterEqual(result["returned"], 4)
        self.assertIn("candidates", result)
        names = {c["name"] for c in result["candidates"]}
        self.assertIn("main", names)
        self.assertIn("crypto_Handler", names)
        self.assertIn("network_io", names)
        self.assertIn("decrypt_data", names)

    def test_search_with_order(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        result = engine.search({"min_size": 100}, top_k=10, order_by="size DESC")
        self.assertTrue(result["ok"])
        sizes = [c["size"] for c in result["candidates"]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_search_limit(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        result = engine.search({}, top_k=3)
        self.assertTrue(result["ok"])
        self.assertLessEqual(result["returned"], 3)

    def test_search_with_apis(self):
        Engine = self._import()
        engine = Engine(self.db_path)
        result = engine.search({"apis": "socket"}, top_k=5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["total_matches"], 1)
        c = result["candidates"][0]
        self.assertEqual(c["name"], "network_io")
        self.assertIn("apis", c)
        self.assertIn("socket", c["apis"])


# ============================================================================
# Test: Pattern filtering on candidates
# ============================================================================

class TestPatternFilter(unittest.TestCase):
    """Test application-level pattern filtering."""

    def _import(self):
        from hybrid_search import apply_pattern_filter
        return apply_pattern_filter

    def test_no_pattern(self):
        filt = self._import()
        candidates = [{"name": "main", "ea": "0x401000"}]
        result = filt(candidates, None)
        self.assertEqual(result, candidates)

    def test_empty_candidates(self):
        filt = self._import()
        result = filt([], "pattern")
        self.assertEqual(result, [])

    def test_substring_match(self):
        filt = self._import()
        candidates = [
            {"name": "crypto_handler", "ea": "0x401000"},
            {"name": "helper_func", "ea": "0x402000"},
        ]
        result = filt(candidates, "crypto")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "crypto_handler")

    def test_regex_match(self):
        filt = self._import()
        candidates = [
            {"name": "crypto_handler_AES", "ea": "0x401000"},
            {"name": "helper_func", "ea": "0x402000"},
        ]
        result = filt(candidates, r".*AES.*")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "crypto_handler_AES")

    def test_ea_match(self):
        filt = self._import()
        candidates = [
            {"name": "func_a", "ea": "0x401000"},
            {"name": "func_b", "ea": "0x402000"},
        ]
        result = filt(candidates, "0x402000")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "func_b")


# ============================================================================
# Test: Operator format constraints (from user perspective)
# ============================================================================

class TestOperatorFormat(unittest.TestCase):
    """Test the operator constraint format end-to-end."""

    def _import_engine(self):
        from hybrid_search import HybridSearchEngine
        return HybridSearchEngine

    def _setup_db(self):
        """Create a minimal file-backed DB for operator format tests."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".schemaboot.db", delete=False)
        db_path = tmp.name
        tmp.close()
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE function_attrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ea INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                segment TEXT,
                has_loops INTEGER DEFAULT 0,
                entropy REAL DEFAULT 0.0,
                call_count INTEGER DEFAULT 0
            );
            INSERT INTO function_attrs (ea, name, size, segment, has_loops, entropy, call_count) VALUES
                (0x401000, 'func_a', 100, '.text', 0, 4.0, 5),
                (0x402000, 'func_b', 200, '.text', 1, 6.0, 10),
                (0x403000, 'func_c', 300, '.data', 0, 7.5, 2);
        """)
        conn.commit()
        conn.close()
        self._tmp_dbs = getattr(self, '_tmp_dbs', [])
        self._tmp_dbs.append(db_path)
        return db_path

    def tearDown(self):
        for p in getattr(self, '_tmp_dbs', []):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_eq_operator(self):
        Engine = self._import_engine()
        db = self._setup_db()
        engine = Engine(db)
        eas, elapsed, meta = engine.pre_filter({"size": ("==", 200)})
        self.assertEqual(len(eas), 1)
        self.assertEqual(eas[0], 0x402000)

    def test_ne_operator(self):
        Engine = self._import_engine()
        db = self._setup_db()
        engine = Engine(db)
        eas, elapsed, meta = engine.pre_filter({"segment": ("!=", ".text")})
        self.assertEqual(len(eas), 1)
        self.assertEqual(eas[0], 0x403000)

    def test_gt_operator(self):
        Engine = self._import_engine()
        db = self._setup_db()
        engine = Engine(db)
        eas, elapsed, meta = engine.pre_filter({"entropy": (">", 5.0)})
        self.assertEqual(len(eas), 2)
        self.assertIn(0x402000, eas)
        self.assertIn(0x403000, eas)

    def test_contains_operator(self):
        Engine = self._import_engine()
        db = self._setup_db()
        engine = Engine(db)
        eas, elapsed, meta = engine.pre_filter({"name": ("contains", "func")})
        self.assertEqual(len(eas), 3)

    def test_multiple_operators(self):
        Engine = self._import_engine()
        db = self._setup_db()
        engine = Engine(db)
        eas, elapsed, meta = engine.pre_filter({
            "size": (">=", 150),
            "call_count": (">=", 5),
        })
        self.assertEqual(len(eas), 1)
        self.assertEqual(eas[0], 0x402000)


# ============================================================================
# Test: Benchmark utilities
# ============================================================================

class TestHybridBenchmark(unittest.TestCase):
    """Test the benchmark utility."""

    def _import(self):
        from hybrid_search import HybridBenchmark
        return HybridBenchmark

    def _setup_db(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".schemaboot.db", delete=False)
        db_path = tmp.name
        tmp.close()
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE function_attrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ea INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                segment TEXT,
                has_loops INTEGER DEFAULT 0,
                entropy REAL DEFAULT 0.0,
                call_count INTEGER DEFAULT 0,
                xor_count INTEGER DEFAULT 0,
                api_count INTEGER DEFAULT 0,
                string_count INTEGER DEFAULT 0,
                bb_count INTEGER DEFAULT 0,
                cyclomatic_complexity INTEGER DEFAULT 0,
                incoming_xrefs INTEGER DEFAULT 0,
                outgoing_xrefs INTEGER DEFAULT 0,
                is_thunk INTEGER DEFAULT 0,
                is_library INTEGER DEFAULT 0,
                has_crypto_constants INTEGER DEFAULT 0,
                xor_ratio REAL DEFAULT 0.0,
                max_loop_depth INTEGER DEFAULT 0,
                data_ref_count INTEGER DEFAULT 0,
                created_at REAL DEFAULT 0.0,
                updated_at REAL DEFAULT 0.0
            );
            INSERT INTO function_attrs (ea, name, size, entropy, call_count, xor_count, has_loops, api_count, bb_count, cyclomatic_complexity, segment)
            VALUES
                (0x401000, 'func_a', 100, 4.0, 5, 0, 0, 2, 5, 3, '.text'),
                (0x402000, 'func_b', 500, 6.5, 10, 8, 1, 4, 15, 8, '.text'),
                (0x403000, 'func_c', 2000, 7.2, 20, 15, 1, 6, 30, 15, '.text');
        """)
        conn.commit()
        conn.close()
        self._tmp_db_path = db_path
        return db_path

    def tearDown(self):
        if hasattr(self, '_tmp_db_path'):
            try:
                os.unlink(self._tmp_db_path)
            except OSError:
                pass

    def test_benchmark_query(self):
        BM = self._import()
        db = self._setup_db()
        result = BM.run_query(db, {"min_size": 200}, label="test")
        self.assertEqual(result["label"], "test")
        self.assertGreater(result["total_ms"], 0)

    def test_benchmark_suite(self):
        BM = self._import()
        db = self._setup_db()
        result = BM.run_benchmark_suite(db, [
            {"min_size": 100},
            {"has_loops": True},
        ])
        self.assertEqual(result["queries"], 2)
        self.assertGreater(result["average_ms"], 0)


# ============================================================================
# Test: apply_regex_constraints
# ============================================================================

class TestRegexConstraints(unittest.TestCase):
    """Test regex constraint application at the application level."""

    def _import(self):
        from hybrid_search import apply_regex_constraints
        return apply_regex_constraints

    def test_regex_on_name(self):
        filt = self._import()
        candidates = [
            {"name": "crypto_aes", "size": 100},
            {"name": "helper_func", "size": 200},
            {"name": "crypto_rsa", "size": 300},
        ]
        result = filt(candidates, {"name": ("~", "crypto.*")})
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "crypto_aes")
        self.assertEqual(result[1]["name"], "crypto_rsa")

    def test_no_regex_constraints(self):
        filt = self._import()
        candidates = [{"name": "test"}]
        result = filt(candidates, {"size": (">=", 100)})
        self.assertEqual(len(result), 1)  # no regex constraint, all pass

    def test_invalid_regex_ignored(self):
        filt = self._import()
        candidates = [{"name": "test"}]
        result = filt(candidates, {"name": ("~", "[invalid")})
        self.assertEqual(len(result), 1)  # bad regex, ignored


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    unittest.main()
