"""Tests for AnalysisEngine pure/helper functions.

Covers host-side logic that doesn't require a live IDA session:
  - _byte_entropy (Shannon entropy of byte sequences)
  - Proposal store integration
  - Stage helper methods that are pure computations
"""
import math
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.analysis.analysis_engine import AnalysisEngine


class TestByteEntropy(unittest.TestCase):
    """Tests for AnalysisEngine._byte_entropy."""

    def _make_engine(self):
        """Create a minimal AnalysisEngine instance for testing pure methods."""
        # We only need the class, not a fully initialized engine.
        # Use __new__ to skip __init__ which requires IDA RPC.
        engine = object.__new__(AnalysisEngine)
        return engine

    def test_empty_data(self):
        e = self._make_engine()
        self.assertEqual(e._byte_entropy(b""), 0.0)

    def test_single_byte(self):
        e = self._make_engine()
        # Single byte: entropy is 0 (one symbol, p=1, -1*log2(1)=0)
        self.assertEqual(e._byte_entropy(b"\x00"), 0.0)
        self.assertEqual(e._byte_entropy(b"\xff"), 0.0)

    def test_uniform_distribution(self):
        e = self._make_engine()
        # All 256 bytes exactly once: entropy = log2(256) = 8.0
        data = bytes(range(256))
        result = e._byte_entropy(data)
        self.assertAlmostEqual(result, 8.0, places=3)

    def test_repeated_byte(self):
        e = self._make_engine()
        # Repeated byte: entropy = 0
        data = b"\x41" * 1000
        self.assertEqual(e._byte_entropy(data), 0.0)

    def test_two_values(self):
        e = self._make_engine()
        # Two equally likely values: entropy = 1.0
        data = b"\x00" * 50 + b"\xff" * 50
        result = e._byte_entropy(data)
        self.assertAlmostEqual(result, 1.0, places=3)

    def test_biased_distribution(self):
        e = self._make_engine()
        # 90% one value, 10% another: entropy should be low
        data = b"\x00" * 90 + b"\xff" * 10
        result = e._byte_entropy(data)
        # H = -(0.9*log2(0.9) + 0.1*log2(0.1)) ≈ 0.469
        expected = -(0.9 * math.log2(0.9) + 0.1 * math.log2(0.1))
        self.assertAlmostEqual(result, expected, places=3)

    def test_random_looking_data(self):
        e = self._make_engine()
        # Structured data with moderate entropy
        data = bytes(range(16)) * 64  # 16 unique bytes, each repeated 64 times
        result = e._byte_entropy(data)
        # log2(16) = 4.0
        self.assertAlmostEqual(result, 4.0, places=3)

    def test_return_type(self):
        e = self._make_engine()
        result = e._byte_entropy(b"\x00\x01\x02")
        self.assertIsInstance(result, float)


class TestDangerousSinks(unittest.TestCase):
    """Verify DANGEROUS_SINKS is a sensible set."""

    def test_contains_common_sinks(self):
        expected = {"memcpy", "strcpy", "sprintf", "gets", "system", "exec"}
        self.assertTrue(expected.issubset(AnalysisEngine.DANGEROUS_SINKS))

    def test_is_set(self):
        self.assertIsInstance(AnalysisEngine.DANGEROUS_SINKS, set)
        self.assertGreater(len(AnalysisEngine.DANGEROUS_SINKS), 10)


if __name__ == "__main__":
    unittest.main()
