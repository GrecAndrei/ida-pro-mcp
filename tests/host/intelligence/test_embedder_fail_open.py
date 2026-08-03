import os
import socket
import sys
import threading
import time
import unittest
import urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import contextlib

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder


class TestBgeCodeEmbedderFailOpen(unittest.TestCase):
    def setUp(self):
        self._old_instance = BgeCodeEmbedder._instance
        BgeCodeEmbedder._instance = None

    def tearDown(self):
        inst = BgeCodeEmbedder._instance
        if inst is not None:
            with contextlib.suppress(Exception):
                inst.stop()
        BgeCodeEmbedder._instance = self._old_instance

    def test_embed_marks_not_ready_after_repeated_rpc_failures(self):
        """After max failures: mark not-ready, keep _use_llama so recovery is possible.

        Fail-closed on vectors (ok=False) but do not permanently disable llama —
        that was a prior bug (_use_llama stuck False after transient errors).
        """
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0

        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            side_effect=urllib.error.URLError("forced timeout"),
        ):
            out1 = emb.embed("first request")
            self.assertFalse(out1.ok)
            self.assertIsNone(out1.vector)
            self.assertTrue(emb._use_llama)
            self.assertEqual(emb._consecutive_rpc_failures, 1)

            out2 = emb.embed("second request")
            self.assertFalse(out2.ok)
            self.assertIsNone(out2.vector)
            # Threshold hit: not ready, counter reset, llama still enabled for retry.
            self.assertTrue(emb._use_llama)
            self.assertFalse(emb._ready)
            self.assertEqual(emb._consecutive_rpc_failures, 0)

    def test_timeout_inside_activation_grace_keeps_server_alive(self):
        """A timeout during the activation-grace window is cold-start latency,
        not a wedged server — the process must NOT be retired."""
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0
        emb._server_started_at = time.time()  # still inside the grace window

        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            side_effect=socket.timeout("cold start timeout"),
        ), mock.patch.object(
            BgeCodeEmbedder, "_retire_lease_process"
        ) as retire:
            out = emb.embed("first request after cold start")
            self.assertFalse(out.ok)
            retire.assert_not_called()  # never killed the just-started server
            self.assertTrue(emb._ready)  # still ready for the next attempt

    def test_timeout_outside_activation_grace_retires_server(self):
        """After the grace window, a timeout is genuine wedging and the
        process should be retired so the next request gets a fresh start."""
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0
        emb._server_started_at = 0.0  # long ago: grace window elapsed

        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            side_effect=socket.timeout("stuck timeout"),
        ), mock.patch.object(
            BgeCodeEmbedder, "_retire_lease_process"
        ) as retire:
            emb.embed("request")
            retire.assert_called_once()

    def test_embed_recovers_counter_on_successful_rpc(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 1

        good_response = mock.MagicMock()
        good_response.read.return_value = b'{"data":[{"embedding":[0.0,1.0]}]}'
        good_response.__enter__.return_value = good_response
        good_response.__exit__.return_value = False
        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            return_value=good_response,
        ):
            result = emb.embed("healthy request")
        self.assertTrue(result.ok)
        self.assertEqual(emb._consecutive_rpc_failures, 0)
        self.assertTrue(emb._use_llama)

    def test_incidental_embed_does_not_launch_a_cold_server(self):
        """Routine enrichment fails closed until an explicit semantic action activates it."""
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = False

        with mock.patch("ida_pro_mcp.host.intelligence.core.subprocess.Popen") as popen:
            result = emb.embed("ordinary tool context")

        self.assertFalse(result.ok)
        self.assertIsNone(result.vector)
        popen.assert_not_called()

    def test_constructing_classifier_does_not_preload_anchors(self):
        """Ordinary tool setup must not queue background model work."""
        old_shared = BehaviorClassifier._shared
        BehaviorClassifier._shared = None
        called = threading.Event()

        class Embedder:
            def embed(self, _text):
                called.set()

        try:
            BehaviorClassifier.instance(Embedder())
            self.assertFalse(called.wait(0.15))
        finally:
            BehaviorClassifier._shared = old_shared

    def test_embed_batch_marks_not_ready_after_repeated_rpc_failures(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._batch_size = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 0

        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            side_effect=urllib.error.URLError("forced batch timeout"),
        ):
            out = emb.embed_batch(["a", "b", "c"])

        self.assertEqual(len(out), 3)
        self.assertTrue(emb._use_llama)
        self.assertFalse(emb._ready)
        # Batch path may shrink batch_size on failure; accept either behavior.
        self.assertGreaterEqual(emb._batch_size, 1)
        for r in out:
            self.assertFalse(r.ok)
            self.assertIsNone(r.vector)

    def test_embed_batch_resets_failure_counter_on_successful_rpc(self):
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._dimension = 2
        emb._batch_size = 2
        emb._max_rpc_failures = 2
        emb._consecutive_rpc_failures = 1

        good_response = mock.MagicMock()
        good_response.read.return_value = b'{"data":[{"embedding":[0.0,1.0]},{"embedding":[1.0,0.0]}]}'
        good_response.__enter__.return_value = good_response
        good_response.__exit__.return_value = False
        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            return_value=good_response,
        ):
            out = emb.embed_batch(["x", "y"])

        self.assertEqual(len(out), 2)
        self.assertEqual(emb._consecutive_rpc_failures, 0)
        self.assertTrue(emb._use_llama)
        for r in out:
            self.assertTrue(r.ok)


if __name__ == "__main__":
    unittest.main()
