import unittest
from unittest import mock
import urllib.error
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.intelligence import BgeCodeEmbedder


class TestBgeCodeEmbedderFailOpen(unittest.TestCase):
    def setUp(self):
        self._old_instance = BgeCodeEmbedder._instance
        BgeCodeEmbedder._instance = None

    def tearDown(self):
        inst = BgeCodeEmbedder._instance
        if inst is not None:
            try:
                inst.stop()
            except Exception:
                pass
        BgeCodeEmbedder._instance = self._old_instance

    def test_embed_disables_llama_after_repeated_rpc_failures(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0

        with mock.patch(
            "ida_pro_mcp.host.intelligence.urllib.request.urlopen",
            side_effect=urllib.error.URLError("forced timeout"),
        ):
            out1 = emb.embed("first request")
            self.assertEqual(len(out1), emb.dim)
            self.assertTrue(emb._use_llama)
            self.assertEqual(emb._consecutive_rpc_failures, 1)

            out2 = emb.embed("second request")
            self.assertEqual(len(out2), emb.dim)
            self.assertFalse(emb._use_llama)
            self.assertEqual(emb._consecutive_rpc_failures, 2)

    def test_embed_recovers_counter_on_successful_rpc(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 1

        good_response = mock.MagicMock()
        good_response.read.return_value = b'{"data":[{"embedding":[0.0,1.0]}]}'
        good_response.__enter__.return_value = good_response
        good_response.__exit__.return_value = False
        with mock.patch(
            "ida_pro_mcp.host.intelligence.urllib.request.urlopen",
            return_value=good_response,
        ):
            emb.embed("healthy request")
        self.assertEqual(emb._consecutive_rpc_failures, 0)
        self.assertTrue(emb._use_llama)

    def test_embed_batch_disables_llama_after_repeated_rpc_failures(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._batch_size = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0

        with mock.patch(
            "ida_pro_mcp.host.intelligence.urllib.request.urlopen",
            side_effect=urllib.error.URLError("forced batch timeout"),
        ):
            out = emb.embed_batch(["a", "b", "c"])

        self.assertEqual(len(out), 3)
        self.assertFalse(emb._use_llama)
        self.assertEqual(emb._consecutive_rpc_failures, 2)
        self.assertEqual(emb._batch_size, 1)

    def test_embed_batch_resets_failure_counter_on_successful_rpc(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._batch_size = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 1

        good_response = mock.MagicMock()
        good_response.read.return_value = b'{"data":[{"embedding":[0.0,1.0]},{"embedding":[1.0,0.0]}]}'
        good_response.__enter__.return_value = good_response
        good_response.__exit__.return_value = False
        with mock.patch(
            "ida_pro_mcp.host.intelligence.urllib.request.urlopen",
            return_value=good_response,
        ):
            out = emb.embed_batch(["x", "y"])

        self.assertEqual(len(out), 2)
        self.assertEqual(emb._consecutive_rpc_failures, 0)
        self.assertTrue(emb._use_llama)


if __name__ == "__main__":
    unittest.main()
