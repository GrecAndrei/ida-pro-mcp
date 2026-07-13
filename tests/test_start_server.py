"""
Tests BgeCodeEmbedder._start_server lease file priority, path re-check, and LD_LIBRARY_PATH.
Created: 2026-07-06
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import contextlib

from ida_pro_mcp.host.intelligence import core as _core
from ida_pro_mcp.host.intelligence.core import CACHE_DIR, BgeCodeEmbedder


def _make_minimal_embedder():
    """Create a BgeCodeEmbedder without triggering full singleton init."""
    e = BgeCodeEmbedder.__new__(BgeCodeEmbedder)
    e._server_bin = "/usr/bin/llama-server"
    e._model_path = "/tmp/model.gguf"
    e._port = None
    e._proc = None
    e._ready = False
    e._start_lock = __import__("threading").Lock()
    e._use_llama = False
    e._anchor_cache = {}
    e._batch_size = 16
    e._batch_lock = __import__("threading").Lock()
    e._owns_proc = False
    e._stop_registered = False
    e._consecutive_rpc_failures = 0
    e._max_rpc_failures = 2
    return e


def _mock_socket_boundary():
    """Mock ephemeral-port allocation at the network boundary."""
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.getsockname.return_value = ("127.0.0.1", 43123)
    return patch("socket.socket", return_value=sock)


class TestStartServerLeaseFilePriority(unittest.TestCase):
    """Test that _start_server checks lease file BEFORE _use_llama gate."""

    def setUp(self):
        self._orig_lease = _core._EMBED_LEASE_FILE
        self._tmpdir = tempfile.mkdtemp()
        self._lease_file = os.path.join(self._tmpdir, "test-lease.json")
        _core._EMBED_LEASE_FILE = self._lease_file

    def tearDown(self):
        _core._EMBED_LEASE_FILE = self._orig_lease
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_legacy_lease_is_not_reused_when_use_llama_false(self):
        """A lease without owner/model identity is unsafe to attach to."""
        e = _make_minimal_embedder()
        e._use_llama = False
        e._server_bin = ""

        with open(self._lease_file, "w") as f:
            json.dump({"pid": 999, "port": 5555, "updated_at": 0}, f)

        with patch.object(_core, "_find_llama_server", return_value=""), patch.object(
            _core, "_find_model", return_value=""
        ):
            result = e._start_server()

        self.assertFalse(result)
        self.assertFalse(e._ready)

    def test_no_lease_file_and_no_paths_returns_false(self):
        """Without lease file and without server binary, return False."""
        e = _make_minimal_embedder()
        e._use_llama = False
        e._server_bin = ""

        with patch.object(_core, "_find_llama_server", return_value=""), patch.object(_core, "_find_model", return_value=""):
            result = e._start_server()
        self.assertFalse(result)
        self.assertFalse(e._ready)

    def test_lease_with_dead_server_falls_through(self):
        """If lease file points to dead server, fall through to path check."""
        e = _make_minimal_embedder()
        e._use_llama = False
        e._server_bin = ""

        with open(self._lease_file, "w") as f:
            json.dump({"pid": 0, "port": 9999, "updated_at": 0}, f)

        with patch("urllib.request.urlopen", side_effect=Exception("refused")), patch.object(_core, "_find_llama_server", return_value=""), patch.object(_core, "_find_model", return_value=""):
            result = e._start_server()

        self.assertFalse(result)

    def test_stop_terminates_owned_server_and_removes_its_lease(self):
        class FakeProcess:
            pid = 12345

            def __init__(self):
                self.alive = True

            def poll(self):
                return None if self.alive else 0

            def terminate(self):
                self.alive = False

            def wait(self, timeout=None):
                return 0

        process = FakeProcess()
        embedder = _make_minimal_embedder()
        embedder._proc = process
        embedder._owns_proc = True
        embedder._ready = True
        with open(self._lease_file, "w", encoding="utf-8") as f:
            json.dump({"pid": process.pid, "owner_pid": os.getpid(), "port": 5555}, f)

        embedder.stop()

        self.assertFalse(process.alive)
        self.assertFalse(embedder._ready)
        self.assertIsNone(embedder._proc)
        self.assertFalse(os.path.exists(self._lease_file))


class TestStartServerPathRecheck(unittest.TestCase):
    """Test that _start_server re-checks paths when _use_llama is False."""

    def setUp(self):
        self._orig_lease = _core._EMBED_LEASE_FILE
        self._tmpdir = tempfile.mkdtemp()
        self._lease_file = os.path.join(self._tmpdir, "test-lease.json")
        _core._EMBED_LEASE_FILE = self._lease_file

    def tearDown(self):
        _core._EMBED_LEASE_FILE = self._orig_lease
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_paths_found_after_init(self):
        """If paths weren't available at init but are now, set _use_llama."""
        e = _make_minimal_embedder()
        e._use_llama = False
        e._server_bin = ""
        e._model_path = ""

        # Don't create lease file — force path re-check
        with (
            patch.object(_core, "_find_llama_server", return_value="/usr/bin/llama-server"),
            patch.object(_core, "_find_model", return_value="/tmp/model.gguf"),
            patch.object(_core, "EMBED_DISABLED", False),
            patch("subprocess.Popen") as mock_popen,
            _mock_socket_boundary(),
        ):
                    mock_proc = MagicMock()
                    mock_proc.poll.return_value = None
                    mock_popen.return_value = mock_proc

                    with patch("urllib.request.urlopen") as mock_urlopen:
                        mock_ctx = MagicMock()
                        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
                        mock_ctx.__exit__ = MagicMock(return_value=False)
                        mock_ctx.read.return_value = b'{"status":"ok"}'
                        mock_urlopen.return_value = mock_ctx

                        result = e._start_server()

        self.assertTrue(result)
        self.assertTrue(e._use_llama)
        self.assertEqual(e._server_bin, "/usr/bin/llama-server")
        self.assertEqual(e._model_path, "/tmp/model.gguf")


class TestStartServerLDPath(unittest.TestCase):
    """Test that _start_server passes LD_LIBRARY_PATH to subprocess."""

    def setUp(self):
        self._orig_lease = _core._EMBED_LEASE_FILE
        self._tmpdir = tempfile.mkdtemp()
        self._lease_file = os.path.join(self._tmpdir, "test-lease.json")
        _core._EMBED_LEASE_FILE = self._lease_file

    def tearDown(self):
        _core._EMBED_LEASE_FILE = self._orig_lease
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_ld_library_path_in_env(self):
        """Subprocess must get LD_LIBRARY_PATH with binary directory."""
        e = _make_minimal_embedder()
        e._use_llama = True
        e._ready = False

        captured_env = {}

        def fake_popen(cmd, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            return mock_proc

        # Don't create lease file — force new server start path
        with patch("subprocess.Popen", side_effect=fake_popen), patch("urllib.request.urlopen") as mock_urlopen, _mock_socket_boundary():
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.read.return_value = b'{"status":"ok"}'
            mock_urlopen.return_value = mock_ctx

            e._start_server()

        ld_path = captured_env.get("LD_LIBRARY_PATH", "")
        bin_dir = os.path.dirname(e._server_bin)
        self.assertIn(bin_dir, ld_path)


if __name__ == "__main__":
    unittest.main()
