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

from ida_pro_mcp.host.server.server_session import ServerSessionMixin
from tests._isolated_repo_loader import load_repo_module


class _IdbWaitHarness(ServerSessionMixin):
    """Minimal subclass that has the runtime attrs _wait_for_idb needs."""
    session_runtimes: dict = {}

    def __init__(self):
        self.session_runtimes = {}
        self._runtime_alive = lambda r: True

ida_mcp_stdio = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
IDAMCPServer = ida_mcp_stdio.IDAMCPServer
Session = ida_mcp_stdio.Session
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


class TestSessionCreateReuseFallsThroughToSpawn(_SessionReuseBase):
    """Reused session should fall through to spawn + _wait_for_idb."""

    def test_reused_session_returns_reuse_note_and_attempts_spawn(self):
        first = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(first.get("ok"))
        first_sid = first["session"]["session_id"]

        second = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(second.get("ok"))
        self.assertEqual(second["session"]["session_id"], first_sid)
        self.assertIn("Reusing", str(second.get("note") or ""))


class TestSessionCreateReuseMixedArch(_SessionReuseBase):
    """Multiple sessions for the same binary with DIFFERENT arch options.

    Regression test: the old find_session_by_path returned the first match
    (which could be metapc when the caller asked for arm). The new code picks
    the session whose recorded arch matches the request."""

    def _all_sessions_for_binary(self):
        rows = self.server.session_mgr.list_sessions(offset=0, limit=1000).get("sessions", [])
        return [
            r for r in rows
            if r.get("binary_path") == self.test_binary
        ]

    def test_reuse_arm_when_metapc_also_exists(self):
        # Create a metapc session first
        metapc = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(metapc.get("ok"))
        metapc_sid = metapc["session"]["session_id"]

        # Now create with arm — should NOT reuse metapc, should create new arm session
        arm = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(arm.get("ok"))
        arm_sid = arm["session"]["session_id"]
        self.assertNotEqual(arm_sid, metapc_sid)

        # Third call with arm — must reuse the arm session
        arm2 = self._create(processor="arm", bitness=64, endian="little")
        self.assertTrue(arm2.get("ok"))
        self.assertEqual(arm2["session"]["session_id"], arm_sid)

        # Fourth call with metapc — must reuse the metapc session
        metapc2 = self._create(processor="metapc", bitness=64, endian="little")
        self.assertTrue(metapc2.get("ok"))
        self.assertEqual(metapc2["session"]["session_id"], metapc_sid)

        # Total: exactly 2 sessions for this binary
        all_sids = sorted(r["session_id"] for r in self._all_sessions_for_binary())
        self.assertEqual(len(all_sids), 2, f"Expected 2 sessions, got {len(all_sids)}: {all_sids}")

    def test_many_arm_calls_with_metapc_present_no_explosion(self):
        # Seed a metapc session
        self._create(processor="metapc", bitness=64, endian="little")
        # Now hammer with arm
        for _ in range(6):
            self._create(processor="arm", bitness=64, endian="little")
        # Should be exactly 2 sessions (1 metapc + 1 arm), not 7
        all_sids = self._all_sessions_for_binary()
        self.assertEqual(len(all_sids), 2, f"Expected 2 sessions, got {len(all_sids)}")


class TestSessionCreateReuseIdempotent(_SessionReuseBase):
    """The original bug: 6 calls to create on the same binary produced 6 sessions.

    After the fix: should produce exactly 1 session when options match."""

    def test_six_calls_same_options_one_session(self):
        for _ in range(6):
            result = self._create(processor="arm", bitness=64, endian="little")
            self.assertTrue(result.get("ok"))
        sids = self._all_session_ids()
        self.assertEqual(len(sids), 1, f"Expected 1 session, got {len(sids)}: {sids}")


class TestFindSessionsByPath(unittest.TestCase):
    """Unit tests for SessionManager.find_sessions_by_path."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
        self.mgr = SessionManager(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_session(self, sid, binary_path, opts=None, last_accessed="2026-01-01T00:00:00"):
        s = Session(
            session_id=sid,
            binary_path=binary_path,
            idb_path=os.path.join(self.tmpdir, f"{sid}.i64"),
            analysis_options=opts or {},
            last_accessed=last_accessed,
            auto_name="test",
        )
        self.mgr.sessions[sid] = s
        return s

    def test_returns_all_matching_sessions_sorted_by_recency(self):
        self._make_session("AAAA1111", self.test_binary, {"processor": "arm"}, "2026-01-01T00:00:01")
        self._make_session("BBBB2222", self.test_binary, {"processor": "metapc"}, "2026-01-01T00:00:03")
        self._make_session("CCCC3333", self.test_binary, {"processor": "arm"}, "2026-01-01T00:00:02")
        self._make_session("ZZZZ0000", "/dev/null", {}, "2026-01-01T00:00:05")  # different path

        results = self.mgr.find_sessions_by_path(self.test_binary)
        self.assertEqual(len(results), 3)
        # Sorted by last_accessed descending → BBBB (03), CCCC (02), AAAA (01)
        self.assertEqual(results[0].session_id, "BBBB2222")
        self.assertEqual(results[1].session_id, "CCCC3333")
        self.assertEqual(results[2].session_id, "AAAA1111")

    def test_empty_when_no_match(self):
        self._make_session("AAAA1111", "/dev/null")
        results = self.mgr.find_sessions_by_path(self.test_binary)
        self.assertEqual(results, [])


class TestWaitForIdb(unittest.TestCase):
    """Unit tests for ServerSessionMixin._wait_for_idb."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
        from tests._isolated_repo_loader import load_repo_module
        ida_mcp_stdio = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
        self.Session = ida_mcp_stdio.Session
        self.harness = _IdbWaitHarness()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_returns_true_when_idb_already_exists(self):
        idb_path = os.path.join(self.tmpdir, "test.i64")
        with open(idb_path, "wb") as f:
            f.write(b"IDB")
        s = self.Session(session_id="W1", binary_path=self.test_binary, idb_path=idb_path)
        self.assertTrue(self.harness._wait_for_idb(s, timeout=1.0))

    def test_polls_until_idb_appears(self):
        idb_path = os.path.join(self.tmpdir, "test.i64")
        s = self.Session(session_id="W2", binary_path=self.test_binary, idb_path=idb_path)

        def writer():
            import time as _t
            _t.sleep(0.5)
            with open(idb_path, "wb") as f:
                f.write(b"IDB")

        import threading
        t = threading.Thread(target=writer, daemon=True)
        t.start()
        self.assertTrue(self.harness._wait_for_idb(s, timeout=5.0))
        t.join()

    def test_returns_false_on_timeout(self):
        idb_path = os.path.join(self.tmpdir, "missing.i64")
        s = self.Session(session_id="W3", binary_path=self.test_binary, idb_path=idb_path)
        self.assertFalse(self.harness._wait_for_idb(s, timeout=0.3))


if __name__ == "__main__":
    unittest.main()
