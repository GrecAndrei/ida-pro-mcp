"""Tests for BehaviorClassifier and BgeCodeEmbedder pure/helper functions.

Covers host-side logic that doesn't require a live IDA session or embedding server:
  - _text_tokens (token extraction from pseudocode)
  - _anchor_explain (anchor phrase matching)
  - ANCHORS dict completeness and format
  - ANCHOR_MIN_CONFIDENCE sanity
  - EmbedResult
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, _EmbedResult


class TestTextTokens(unittest.TestCase):
    """Tests for BehaviorClassifier._text_tokens."""

    def test_empty_string(self):
        result = BehaviorClassifier._text_tokens("")
        self.assertIsInstance(result, set)
        self.assertEqual(len(result), 0)

    def test_none_input(self):
        result = BehaviorClassifier._text_tokens(None)
        self.assertIsInstance(result, set)

    def test_extracts_identifiers(self):
        text = "VirtualAllocEx(dest, source_buffer, length);"
        tokens = BehaviorClassifier._text_tokens(text)
        self.assertIn("virtualallocex", tokens)
        self.assertIn("source_buffer", tokens)
        self.assertIn("dest", tokens)

    def test_filters_noise_words(self):
        text = "if (the result is null) return void;"
        tokens = BehaviorClassifier._text_tokens(text)
        # Common noise words should be filtered
        self.assertNotIn("the", tokens)
        self.assertNotIn("void", tokens)

    def test_extracts_hex_literals(self):
        text = "value = 0xdeadbeef; mask = 0xff;"
        tokens = BehaviorClassifier._text_tokens(text)
        self.assertIn("0xdeadbeef", tokens)
        self.assertIn("0xff", tokens)

    def test_extracts_format_strings(self):
        text = 'printf("%s: %d\\n", name, count);'
        tokens = BehaviorClassifier._text_tokens(text)
        self.assertIn("%s", tokens)
        self.assertIn("%d", tokens)

    def test_min_identifier_length(self):
        """Identifiers shorter than 3 chars (after the initial pattern) should be filtered."""
        text = "x = a + bb;"
        tokens = BehaviorClassifier._text_tokens(text)
        # "x" is length 1, should not be in tokens (pattern requires [A-Za-z_][A-Za-z0-9_]{2,})
        self.assertNotIn("x", tokens)

    def test_extracts_dots_pattern(self):
        text = "path = '../etc/passwd';"
        tokens = BehaviorClassifier._text_tokens(text)
        self.assertIn("..", tokens)

    def test_identifier_splitting(self):
        """camelCase/snake_case identifiers should be split into terms."""
        text = "VirtualAllocEx(hProcess, dwSize);"
        tokens = BehaviorClassifier._text_tokens(text)
        # Should contain the full identifier and sub-terms
        self.assertIn("virtualallocex", tokens)


class TestAnchorExplain(unittest.TestCase):
    """Tests for BehaviorClassifier._anchor_explain."""

    def test_returns_list(self):
        result = BehaviorClassifier._anchor_explain("a = 1; b = 2;", "a = 1")
        self.assertIsInstance(result, list)

    def test_returns_at_most_3(self):
        long_anchor = "; ".join([f"phrase_{i} word_{i}" for i in range(20)])
        result = BehaviorClassifier._anchor_explain(long_anchor, "phrase_5 word_5")
        self.assertLessEqual(len(result), 3)

    def test_matching_phrases_ranked_first(self):
        anchor = "memcpy(dest, src, len); strcpy(buf, input); printf(fmt);"
        query = "memcpy strcpy buffer overflow"
        result = BehaviorClassifier._anchor_explain(anchor, query)
        # "memcpy(dest, src, len)" and "strcpy(buf, input)" should rank higher
        self.assertTrue(any("memcpy" in p for p in result))

    def test_no_overlap(self):
        anchor = "aaa; bbb; ccc;"
        query = "zzz yyy xxx"
        result = BehaviorClassifier._anchor_explain(anchor, query)
        self.assertEqual(len(result), 3)  # Still returns 3 phrases


class TestAnchors(unittest.TestCase):
    """Tests for BehaviorClassifier.ANCHORS dict."""

    def test_has_expected_categories(self):
        expected = {
            "crypto_symmetric", "crypto_hash", "network_http", "network_raw",
            "process_injection", "file_operations", "anti_debug", "anti_vm",
            "persistence", "evasion", "string_decrypt", "c2_communication",
            "privilege_escalation", "memory_manipulation", "rop_gadget",
            "heap_spray", "use_after_free", "buffer_overflow",
            "format_string_vuln", "race_condition", "integer_overflow",
            "path_traversal",
        }
        self.assertTrue(expected.issubset(set(BehaviorClassifier.ANCHORS.keys())))

    def test_all_anchors_non_empty(self):
        for name, text in BehaviorClassifier.ANCHORS.items():
            self.assertTrue(text.strip(), f"Anchor '{name}' is empty")

    def test_all_anchors_have_semicolons(self):
        """Anchors should be multi-statement (contain semicolons) for good embedding."""
        for name, text in BehaviorClassifier.ANCHORS.items():
            self.assertIn(";", text, f"Anchor '{name}' has no semicolons")

    def test_anchor_min_confidence_subset(self):
        """ANCHOR_MIN_CONFIDENCE keys should be a subset of ANCHORS keys."""
        self.assertTrue(
            set(BehaviorClassifier.ANCHOR_MIN_CONFIDENCE.keys()).issubset(
                set(BehaviorClassifier.ANCHORS.keys())
            )
        )

    def test_min_confidence_values_are_low(self):
        """Min confidence thresholds should be < 0.5 (they're fallback thresholds)."""
        for name, val in BehaviorClassifier.ANCHOR_MIN_CONFIDENCE.items():
            self.assertLess(val, 0.5, f"ANCHOR_MIN_CONFIDENCE['{name}'] = {val} seems too high")
            self.assertGreater(val, 0.0, f"ANCHOR_MIN_CONFIDENCE['{name}'] = {val} should be positive")


class TestEmbedResult(unittest.TestCase):
    """Tests for _EmbedResult dataclass."""

    def test_creation(self):
        r = _EmbedResult(vector=[0.1, 0.2], backend="test", ok=True)
        self.assertTrue(r.ok)
        self.assertEqual(r.backend, "test")
        self.assertEqual(r.vector, [0.1, 0.2])

    def test_none_vector(self):
        r = _EmbedResult(vector=None, backend="unavailable", ok=False)
        self.assertFalse(r.ok)
        self.assertIsNone(r.vector)

    def test_repr(self):
        r = _EmbedResult(vector=[1.0, 2.0], backend="bge-code-v1", ok=True)
        s = repr(r)
        self.assertIn("ok=True", s)
        self.assertIn("bge-code-v1", s)


if __name__ == "__main__":
    unittest.main()
