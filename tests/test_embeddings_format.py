"""
Tests API response format handling in BgeCodeEmbedder._llama_embed and _llama_embed_batch.
Created: 2026-07-06
"""

import json
import math
import unittest
from unittest.mock import patch, MagicMock

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder


class TestExtractEmbedding(unittest.TestCase):
    """Test the _extract_embedding static method handles both old and new API formats."""

    def test_new_format_list_of_lists(self):
        """Newer llama-server returns embedding as [[...]] (list of lists)."""
        item = {"index": 0, "embedding": [[0.1, 0.2, 0.3]]}
        result = BgeCodeEmbedder._extract_embedding(item)
        self.assertEqual(result, [0.1, 0.2, 0.3])

    def test_old_format_flat_list(self):
        """Older format returns embedding as flat list."""
        item = {"index": 0, "embedding": [0.5, 0.6, 0.7]}
        result = BgeCodeEmbedder._extract_embedding(item)
        self.assertEqual(result, [0.5, 0.6, 0.7])

    def test_non_dict_returns_none(self):
        result = BgeCodeEmbedder._extract_embedding([1, 2, 3])
        self.assertIsNone(result)

    def test_missing_embedding_key(self):
        result = BgeCodeEmbedder._extract_embedding({"index": 0})
        self.assertIsNone(result)

    def test_empty_embedding(self):
        result = BgeCodeEmbedder._extract_embedding({"embedding": []})
        self.assertIsNone(result)

    def test_float_conversion(self):
        item = {"embedding": [1, 2, 3]}
        result = BgeCodeEmbedder._extract_embedding(item)
        self.assertEqual(result, [1.0, 2.0, 3.0])
        self.assertIsInstance(result[0], float)


class TestLlamaEmbedResponseHandling(unittest.TestCase):
    """Test _llama_embed handles both response formats."""

    def _make_embedder(self):
        """Create a BgeCodeEmbedder instance without full init."""
        e = BgeCodeEmbedder.__new__(BgeCodeEmbedder)
        e._port = 12345
        e._ready = True
        e._use_llama = True
        e._consecutive_rpc_failures = 0
        e._max_rpc_failures = 2
        return e

    def test_new_format_single_embedding(self):
        """Response is a list with nested embedding."""
        e = self._make_embedder()
        mock_response = json.dumps([
            {"index": 0, "embedding": [[0.1] * 1536]}
        ]).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            vec = e._llama_embed("test code")

        self.assertIsNotNone(vec)
        self.assertEqual(len(vec), 1536)

    def test_old_format_single_embedding(self):
        """Response is a dict with data key."""
        e = self._make_embedder()
        mock_response = json.dumps({
            "data": [{"index": 0, "embedding": [0.5] * 768}]
        }).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            vec = e._llama_embed("test code")

        self.assertIsNotNone(vec)
        self.assertEqual(len(vec), 768)

    def test_normalization(self):
        """Embedding vector should be L2-normalized."""
        e = self._make_embedder()
        mock_response = json.dumps([
            {"index": 0, "embedding": [[3.0, 4.0]]}
        ]).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            vec = e._llama_embed("test code")

        self.assertIsNotNone(vec)
        norm = math.sqrt(sum(x * x for x in vec))
        self.assertAlmostEqual(norm, 1.0, places=5)

    def test_failure_increments_counter(self):
        """Failed embed increments consecutive_rpc_failures."""
        e = self._make_embedder()
        e._max_rpc_failures = 3

        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            vec = e._llama_embed("test code")

        self.assertIsNone(vec)
        self.assertEqual(e._consecutive_rpc_failures, 1)
        self.assertTrue(e._use_llama)

    def test_transient_failure_not_permanent(self):
        """After max failures, _ready is reset but _use_llama stays True."""
        e = self._make_embedder()
        e._max_rpc_failures = 2

        with patch("urllib.request.urlopen", side_effect=Exception("fail")):
            e._llama_embed("call 1")
            e._llama_embed("call 2")

        self.assertFalse(e._ready)
        self.assertTrue(e._use_llama)
        self.assertEqual(e._consecutive_rpc_failures, 0)


class TestLlamaEmbedBatchResponseHandling(unittest.TestCase):
    """Test _llama_embed_batch handles both response formats."""

    def _make_embedder(self):
        e = BgeCodeEmbedder.__new__(BgeCodeEmbedder)
        e._port = 12345
        e._ready = True
        e._use_llama = True
        e._consecutive_rpc_failures = 0
        e._max_rpc_failures = 2
        e._batch_size = 16
        e._batch_lock = __import__("threading").Lock()
        return e

    def test_new_format_batch(self):
        """Batch response is a list."""
        e = self._make_embedder()
        mock_response = json.dumps([
            {"index": 0, "embedding": [[0.1] * 10]},
            {"index": 1, "embedding": [[0.2] * 10]},
            {"index": 2, "embedding": [[0.3] * 10]},
        ]).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            result = e._llama_embed_batch(["a", "b", "c"])

        self.assertEqual(len(result), 3)

    def test_old_format_batch(self):
        """Batch response is a dict with data key."""
        e = self._make_embedder()
        mock_response = json.dumps({
            "data": [
                {"index": 0, "embedding": [0.1] * 10},
                {"index": 1, "embedding": [0.2] * 10},
            ]
        }).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            result = e._llama_embed_batch(["a", "b"])

        self.assertEqual(len(result), 2)

    def test_batch_mismatch_returns_none(self):
        """If response count doesn't match input count, return None."""
        e = self._make_embedder()
        mock_response = json.dumps([
            {"index": 0, "embedding": [[0.1] * 10]},
        ]).encode()

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = mock_response
            mock_urlopen.return_value = mock_ctx

            result = e._llama_embed_batch(["a", "b", "c"])

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
