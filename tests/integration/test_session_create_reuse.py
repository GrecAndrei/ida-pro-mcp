#!/usr/bin/env python3
"""
Tests for the session-create-reuse logic.

Bug class: smoke runs that call ``session(action='create', processor=...)``
would always create a NEW session (and spawn a NEW idat child), even when
an existing session for the same binary had the same architecture options.
This left orphan idat children running on the same binary across smoke
runs that crashed or were killed.

Fix: when an existing session is found AND its architecture/loader options
match what the caller requested, reuse the existing session even with a
preload request. ``force_new=true`` still always creates a new one.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import unittest

from tests._isolated_repo_loader import load_repo_module

ida_mcp_stdio = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
IDAMCPServer = ida_mcp_stdio.IDAMCPServer
SessionManager = ida_mcp_stdio.SessionManager


class _SessionReuseBase(unittest.TestCase):
    """Common setup: stub out IDA detection so the host never tries to spawn."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
        self._orig_detect = IDAMCPServer._detect_ida_dir
        self._orig_find = IDAMCPServer._find_idat
        IDAMCPServer._detect_ida_dir = lambda self: ""
        IDAMCPServer._find_idat = lambda self: ""
        self.server = IDAMCPServer()
        self.server.cache_dir = self.tmpdir
        self.server.session_mgr = SessionManager(self.tmpdir)

    def tearDown(self):
        IDAMCPServer._detect_ida_dir = self._orig_detect
        IDAMCPServer._find_idat = self._orig_find
        with contextlib.suppress(Exception):
            self.server.shutdown()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create(self, **kwargs):
        kwargs.setdefault("_risk_ack", True)
        return self.server._execute_tool("session", {"action": "create", "binary_path": self.test_binary, **kwargs})

    def _all_session_ids(self):
        rows = self.server.session_mgr.list_sessions(offset=0, limit=1000).get("sessions", [])
        return sorted(r.get("session_id") for r in rows if r.get("session_id"))


class TestSessionCreateReuseMatchingArch(_SessionReuseBase):
    """Preload request whose options match the existing session → reuse."""

    def test_matching_processor_reuses(self):
        # First create with metapc/64/little
        first = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        # Second create with the SAME preload options should reuse
        second = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertEqual(second["session"]["session_id"], first_sid)
        # The note field is the host's signal that the existing session was reused
        self.assertIn("Reusing", str(second.get("note") or ""))

    def test_matching_arm_reuses(self):
        first = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        second = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertEqual(second["session"]["session_id"], first_sid)

    def test_subset_of_existing_options_reuses(self):
        """Caller asks for a subset of the existing session's options."""
        first = self._create(processor="arm", bitness=64, endian="little", flags=["0x8000"])
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        # Caller only passes processor — should still reuse
        second = self._create(processor="arm")
        self.assertTrue(second.get("ok"))
        self.assertEqual(second["session"]["session_id"], first_sid)


class TestSessionCreateReuseConflict(_SessionReuseBase):
    """Preload request whose options DIFFER from the existing session → new session."""

    def test_different_processor_creates_new(self):
        first = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        # Different processor → must NOT reuse
        second = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertNotEqual(second["session"]["session_id"], first_sid)

    def test_different_bitness_creates_new(self):
        first = self._create(processor="metapc", bitness=32, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        second = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertNotEqual(second["session"]["session_id"], first_sid)

    def test_different_endian_creates_new(self):
        first = self._create(processor="metapc", bitness=64, endian="big")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        second = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertNotEqual(second["session"]["session_id"], first_sid)


class TestSessionCreateReuseNoPreload(_SessionReuseBase):
    """No preload options → always reuses (existing behavior)."""

    def test_no_preload_reuses(self):
        first = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        # No preload options at all
        second = self._create()
        self.assertTrue(second.get("ok"))
        self.assertEqual(second["session"]["session_id"], first_sid)


class TestSessionCreateReuseForceNew(_SessionReuseBase):
    """force_new=true bypasses reuse even when options match."""

    def test_force_new_creates_new(self):
        first = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        second = self._create(processor="arm", bitness=64, endian="little", force_new=True)
        self.assertTrue(second.get("ok"))
        self.assertNotEqual(second["session"]["session_id"], first_sid)
        # Should NOT have the "Reusing" note
        self.assertNotIn("Reusing", str(second.get("note") or ""))


class TestSessionCreateReuseNoExisting(_SessionReuseBase):
    """No existing session → creates a new one."""

    def test_no_existing_creates(self):
        result = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(result.get("ok"))
        self.assertIn("session", result)
        self.assertTrue(result["session"]["session_id"])

    def test_no_existing_no_preload_creates(self):
        result = self._create()
        self.assertTrue(result.get("ok"))
        self.assertIn("session", result)


class TestSessionCreateReuseIdempotent(_SessionReuseBase):
    """The original bug: 6 calls to create on the same binary produced 6 sessions.

    After the fix: should produce exactly 1 session when options match."""

    def test_six_calls_same_options_one_session(self):
        for _ in range(6):
            result = self._create(processor="arm", bitness=64, endian="little")
            self.assertTrue(result.get("ok"))
        sids = self._all_session_ids()
        self.assertEqual(len(sids), 1, f"Expected 1 session, got {len(sids)}: {sids}")


if __name__ == "__main__":
    unittest.main()
