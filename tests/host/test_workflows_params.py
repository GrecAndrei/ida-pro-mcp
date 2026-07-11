"""Tests for workflow $param substitution and session narrative.

Covers host-side logic that doesn't require a live IDA session.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.server.server_session import _substitute_params


class TestSubstituteParams(unittest.TestCase):
    """$param substitution in workflow values."""

    def test_string_substitution(self):
        result = _substitute_params("addr is $addr and name is $name", {"addr": "0x401000", "name": "main"})
        self.assertEqual(result, "addr is 0x401000 and name is main")

    def test_dict_substitution(self):
        result = _substitute_params({"action": "read", "addr": "$addr"}, {"addr": "0x401000"})
        self.assertEqual(result, {"action": "read", "addr": "0x401000"})

    def test_list_substitution(self):
        result = _substitute_params(["$a", "$b", 42], {"a": "hello", "b": "world"})
        self.assertEqual(result, ["hello", "world", 42])

    def test_nested_substitution(self):
        result = _substitute_params(
            {"data": {"addr": "$addr", "items": ["$a", "$b"]}},
            {"addr": "0x401000", "a": "x", "b": "y"}
        )
        self.assertEqual(result, {"data": {"addr": "0x401000", "items": ["x", "y"]}})

    def test_non_string_passthrough(self):
        result = _substitute_params(42, {"a": "x"})
        self.assertEqual(result, 42)

    def test_no_params(self):
        result = _substitute_params("no subs here", {})
        self.assertEqual(result, "no subs here")

    def test_dollar_prefix_stripped(self):
        """Params can be passed as $addr or addr — both should work."""
        result = _substitute_params("$addr", {"$addr": "0x401000"})
        self.assertEqual(result, "0x401000")

    def test_multiple_occurrences(self):
        result = _substitute_params("$x and $x again", {"x": "hello"})
        self.assertEqual(result, "hello and hello again")


class TestTruncationSearchParams(unittest.TestCase):
    """Truncation search with various param combinations."""

    def test_search_with_limit(self):
        from ida_pro_mcp.host.stores.truncation import (
            _TRUNCATION_ORDER,
            _TRUNCATION_STORE,
            _store_truncation,
            search_truncated,
        )
        _TRUNCATION_STORE.clear()
        _TRUNCATION_ORDER.clear()
        try:
            items = [f"item_{i}" for i in range(100)]
            token = _store_truncation(
                {"items": items},
                {"items": {"type": "list", "total": 100, "chunk_size": 10, "next_offset": 10}}
            )
            result = search_truncated(token, pattern="item_5", limit=5)
            self.assertTrue(result.get("ok"))
            self.assertLessEqual(result["match_count"], 5)
        finally:
            _TRUNCATION_STORE.clear()
            _TRUNCATION_ORDER.clear()


class TestErrorRecoveryCodes(unittest.TestCase):
    """Verify error codes have proper categories and hints."""

    def test_all_recovery_codes_in_categories(self):
        from ida_pro_mcp.host.errors import _ERROR_CATEGORIES, _RECOVERY_ACTIONS
        for code in _RECOVERY_ACTIONS:
            self.assertIn(code, _ERROR_CATEGORIES, f"{code} has recovery but no category")

    def test_all_recovery_codes_have_hints(self):
        from ida_pro_mcp.host.errors import _HOST_ERROR_HINTS, _RECOVERY_ACTIONS
        for code in _RECOVERY_ACTIONS:
            self.assertIn(code, _HOST_ERROR_HINTS, f"{code} has recovery but no hint")


if __name__ == "__main__":
    unittest.main()
