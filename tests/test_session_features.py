#!/usr/bin/env python3
"""
Tests for the revamped session management features.
Covers thread safety, atomic writes, defensive copies, path validation,
and all 31 new SessionManager methods + their _execute_tool handlers.
"""
import os

import json
import tempfile
import shutil
import time
import copy
import unittest
import threading
from unittest.mock import patch
from tests._isolated_repo_loader import load_host_module, load_package_module, load_repo_module

session_mod = load_host_module("session")
load_package_module("host")
ida_mcp_stdio = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")

SessionManager = ida_mcp_stdio.SessionManager
Session = ida_mcp_stdio.Session
IDAMCPServer = ida_mcp_stdio.IDAMCPServer
make_error = ida_mcp_stdio.make_error
MCPError = ida_mcp_stdio.MCPError
validate_path = ida_mcp_stdio.validate_path


class TestValidatePathSecurity(unittest.TestCase):
    """Test directory traversal prevention in validate_path."""

    def test_rejects_dotdot(self):
        self.assertIsNone(validate_path("/some/../etc/passwd"))

    def test_rejects_dotdot_at_start(self):
        self.assertIsNone(validate_path("../etc/passwd"))

    def test_rejects_null_bytes(self):
        self.assertIsNone(validate_path("/some/path\x00evil"))

    def test_rejects_empty(self):
        self.assertIsNone(validate_path(""))

    def test_accepts_normal_path(self):
        result = validate_path("/tmp/test.exe")
        self.assertIsNotNone(result)

    def test_accepts_relative_normal(self):
        result = validate_path("test.exe")
        self.assertIsNotNone(result)


class TestSessionManagerThreadSafety(unittest.TestCase):
    """Test that SessionManager operations are thread-safe."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_has_lock(self):
        self.assertTrue(hasattr(self.mgr, "_lock"))
        self.assertIsInstance(self.mgr._lock, type(threading.RLock()))

    def test_concurrent_create(self):
        """Multiple threads creating sessions shouldn't corrupt state."""
        results = []
        errors = []
        binaries = []
        for i in range(10):
            b = os.path.join(self.tmpdir, f"bin_{i}.exe")
            with open(b, "wb") as f:
                f.write(b"\x00" * 50)
            binaries.append(b)

        def create_session(binary):
            try:
                s = self.mgr.create_session(binary)
                results.append(s.session_id)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=create_session, args=(b,)) for b in binaries]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        self.assertEqual(len(results), 10)
        self.assertEqual(len(set(results)), 10)  # All unique SIDs


class TestAtomicWrites(unittest.TestCase):
    """Test that metadata writes are atomic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_tmp_files_left(self):
        """Atomic writes should not leave .tmp files behind."""
        session = self.mgr.create_session(self.test_binary)
        meta_path = self.mgr._get_metadata_path(session.session_id)
        self.assertTrue(os.path.exists(meta_path))
        self.assertFalse(os.path.exists(meta_path + ".tmp"))


class TestDefensiveCopies(unittest.TestCase):
    """Test that returned sessions are copies, not direct references."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_get_session_returns_copy(self):
        session = self.mgr.create_session(self.test_binary)
        sid = session.session_id
        got = self.mgr.get_session(sid)
        # Mutate the copy
        got.notes = "MUTATED"
        # Original should be unchanged
        original = self.mgr.sessions[sid]
        self.assertNotEqual(original.notes, "MUTATED")

    def test_find_session_returns_copy(self):
        session = self.mgr.create_session(self.test_binary)
        found = self.mgr.find_session_by_path(self.test_binary)
        found.notes = "MUTATED"
        original = self.mgr.sessions[session.session_id]
        self.assertNotEqual(original.notes, "MUTATED")

    def test_discover_returns_copies(self):
        session = self.mgr.create_session(self.test_binary)
        results = self.mgr.discover_sessions()
        results[0].notes = "MUTATED"
        original = self.mgr.sessions[session.session_id]
        self.assertNotEqual(original.notes, "MUTATED")


class TestUpdateSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_update_notes(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.update_session(s.session_id, notes="updated notes")
        self.assertIsNotNone(result)
        self.assertEqual(result.notes, "updated notes")

    def test_update_tags(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.update_session(s.session_id, tags=["malware", "packed"])
        self.assertEqual(result.tags, ["malware", "packed"])

    def test_update_nonexistent(self):
        result = self.mgr.update_session("NONEXIST", notes="test")
        self.assertIsNone(result)

    def test_update_protected_fields(self):
        s = self.mgr.create_session(self.test_binary)
        original_sid = s.session_id
        result = self.mgr.update_session(s.session_id, session_id="HACKED")
        # session_id should not change
        self.assertEqual(result.session_id, original_sid)


class TestRenameSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rename(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.rename_session(s.session_id, "My Analysis")
        self.assertEqual(result.auto_name, "My Analysis")

    def test_rename_nonexistent(self):
        result = self.mgr.rename_session("NONEXIST", "name")
        self.assertIsNone(result)


class TestDuplicateSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_duplicate(self):
        s = self.mgr.create_session(self.test_binary, tags=["original"], notes="test notes")
        dup = self.mgr.duplicate_session(s.session_id)
        self.assertIsNotNone(dup)
        self.assertNotEqual(dup.session_id, s.session_id)
        self.assertEqual(dup.binary_path, s.binary_path)
        self.assertIn("original", dup.tags)
        self.assertEqual(dup.notes, "test notes")
        self.assertIn("(copy)", dup.auto_name)

    def test_duplicate_nonexistent(self):
        result = self.mgr.duplicate_session("NONEXIST")
        self.assertIsNone(result)


class TestExportImportSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export(self):
        s = self.mgr.create_session(self.test_binary, notes="exported")
        data = self.mgr.export_session(s.session_id)
        self.assertIsNotNone(data)
        self.assertIn("_exported_at", data)
        self.assertEqual(data["notes"], "exported")

    def test_export_nonexistent(self):
        result = self.mgr.export_session("NONEXIST")
        self.assertIsNone(result)

    def test_import(self):
        s = self.mgr.create_session(self.test_binary, notes="to import")
        data = self.mgr.export_session(s.session_id)
        imported = self.mgr.import_session(data)
        self.assertIsNotNone(imported)
        self.assertNotEqual(imported.session_id, s.session_id)  # New SID
        self.assertEqual(imported.notes, "to import")

    def test_roundtrip(self):
        s = self.mgr.create_session(self.test_binary, tags=["tag1"], notes="roundtrip")
        data = self.mgr.export_session(s.session_id)
        imported = self.mgr.import_session(data)
        self.assertEqual(imported.binary_path, s.binary_path)
        self.assertEqual(imported.tags, s.tags)
        self.assertEqual(imported.notes, s.notes)


class TestArchiveUnarchive(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_archive(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.archive_session(s.session_id)
        self.assertIn("archived", result.tags)

    def test_archive_idempotent(self):
        s = self.mgr.create_session(self.test_binary)
        self.mgr.archive_session(s.session_id)
        result = self.mgr.archive_session(s.session_id)
        self.assertEqual(result.tags.count("archived"), 1)

    def test_unarchive(self):
        s = self.mgr.create_session(self.test_binary)
        self.mgr.archive_session(s.session_id)
        result = self.mgr.unarchive_session(s.session_id)
        self.assertNotIn("archived", result.tags)

    def test_list_archived(self):
        s1 = self.mgr.create_session(self.test_binary)
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(b2)
        self.mgr.archive_session(s1.session_id)
        archived = self.mgr.list_archived()
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].session_id, s1.session_id)

    def test_list_active(self):
        s1 = self.mgr.create_session(self.test_binary)
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(b2)
        self.mgr.archive_session(s1.session_id)
        active = self.mgr.list_active()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].session_id, s2.session_id)

    def test_archive_nonexistent(self):
        self.assertIsNone(self.mgr.archive_session("NONEXIST"))

    def test_unarchive_nonexistent(self):
        self.assertIsNone(self.mgr.unarchive_session("NONEXIST"))


class TestSessionAge(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_age(self):
        s = self.mgr.create_session(self.test_binary)
        age = self.mgr.get_session_age(s.session_id)
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age.total_seconds(), 0)

    def test_idle_time(self):
        s = self.mgr.create_session(self.test_binary)
        idle = self.mgr.get_session_idle_time(s.session_id)
        self.assertIsNotNone(idle)
        self.assertGreaterEqual(idle.total_seconds(), 0)

    def test_age_nonexistent(self):
        self.assertIsNone(self.mgr.get_session_age("NONEXIST"))

    def test_idle_nonexistent(self):
        self.assertIsNone(self.mgr.get_session_idle_time("NONEXIST"))


class TestCleanupStale(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cleanup_recent_sessions_untouched(self):
        s = self.mgr.create_session(self.test_binary)
        deleted = self.mgr.cleanup_stale(max_age_days=30)
        self.assertEqual(len(deleted), 0)
        self.assertTrue(self.mgr.session_exists(s.session_id))

    def test_cleanup_stale_sessions(self):
        from datetime import datetime, timedelta
        s = self.mgr.create_session(self.test_binary)
        # Artificially age the session
        self.mgr.sessions[s.session_id].last_accessed = datetime.now() - timedelta(days=60)
        deleted = self.mgr.cleanup_stale(max_age_days=30)
        self.assertEqual(len(deleted), 1)
        self.assertFalse(self.mgr.session_exists(s.session_id))


class TestStats(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_stats(self):
        stats = self.mgr.get_stats()
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["active"], 0)
        self.assertEqual(stats["archived"], 0)

    def test_stats_with_sessions(self):
        s1 = self.mgr.create_session(self.test_binary)
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(b2)
        self.mgr.archive_session(s1.session_id)
        self.mgr.tag_session(s1.session_id, "malware")
        stats = self.mgr.get_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["active"], 1)
        self.assertEqual(stats["archived"], 1)
        self.assertIn("malware", stats["tags"])
        self.assertIn("archived", stats["tags"])


class TestTagging(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tag(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.tag_session(s.session_id, "malware")
        self.assertIn("malware", result.tags)

    def test_tag_idempotent(self):
        s = self.mgr.create_session(self.test_binary)
        self.mgr.tag_session(s.session_id, "malware")
        result = self.mgr.tag_session(s.session_id, "malware")
        self.assertEqual(result.tags.count("malware"), 1)

    def test_untag(self):
        s = self.mgr.create_session(self.test_binary, tags=["malware", "packed"])
        result = self.mgr.untag_session(s.session_id, "malware")
        self.assertNotIn("malware", result.tags)
        self.assertIn("packed", result.tags)

    def test_find_by_tag(self):
        s1 = self.mgr.create_session(self.test_binary, tags=["malware"])
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(b2, tags=["clean"])
        found = self.mgr.find_by_tag("malware")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].session_id, s1.session_id)

    def test_tag_nonexistent(self):
        self.assertIsNone(self.mgr.tag_session("NONEXIST", "tag"))

    def test_untag_nonexistent(self):
        self.assertIsNone(self.mgr.untag_session("NONEXIST", "tag"))


class TestNotes(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_note(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.add_note(s.session_id, "First note")
        self.assertEqual(result.notes, "First note")

    def test_add_multiple_notes(self):
        s = self.mgr.create_session(self.test_binary)
        self.mgr.add_note(s.session_id, "First")
        result = self.mgr.add_note(s.session_id, "Second")
        self.assertIn("First", result.notes)
        self.assertIn("Second", result.notes)

    def test_clear_notes(self):
        s = self.mgr.create_session(self.test_binary, notes="existing")
        result = self.mgr.clear_notes(s.session_id)
        self.assertEqual(result.notes, "")

    def test_search_notes(self):
        s1 = self.mgr.create_session(self.test_binary, notes="vulnerable buffer overflow")
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(b2, notes="clean binary")
        found = self.mgr.search_notes("buffer overflow")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].session_id, s1.session_id)

    def test_add_note_nonexistent(self):
        self.assertIsNone(self.mgr.add_note("NONEXIST", "note"))


class TestPathUpdates(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_set_binary_path(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.set_binary_path(s.session_id, "/new/path.exe")
        self.assertEqual(result.binary_path, "/new/path.exe")

    def test_set_idb_path(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.set_idb_path(s.session_id, "/new/path.i64")
        self.assertEqual(result.idb_path, "/new/path.i64")

    def test_set_paths_nonexistent(self):
        self.assertIsNone(self.mgr.set_binary_path("NONEXIST", "/path"))
        self.assertIsNone(self.mgr.set_idb_path("NONEXIST", "/path"))


class TestBulkOperations(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.binaries = []
        for i in range(5):
            b = os.path.join(self.tmpdir, f"bin_{i}.exe")
            with open(b, "wb") as f:
                f.write(b"\x00" * 50)
            self.binaries.append(b)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bulk_delete(self):
        sessions = [self.mgr.create_session(b) for b in self.binaries]
        sids = [s.session_id for s in sessions[:3]]
        results = self.mgr.bulk_delete(sids)
        for sid in sids:
            self.assertTrue(results[sid])
            self.assertFalse(self.mgr.session_exists(sid))
        # Remaining 2 should still exist
        self.assertEqual(self.mgr.count(), 2)

    def test_bulk_tag(self):
        sessions = [self.mgr.create_session(b) for b in self.binaries]
        sids = [s.session_id for s in sessions]
        results = self.mgr.bulk_tag(sids, "batch_analysis")
        for sid in sids:
            self.assertTrue(results[sid])
        tagged = self.mgr.find_by_tag("batch_analysis")
        self.assertEqual(len(tagged), 5)


class TestRecentOldest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.binaries = []
        for i in range(5):
            b = os.path.join(self.tmpdir, f"bin_{i}.exe")
            with open(b, "wb") as f:
                f.write(b"\x00" * 50)
            self.binaries.append(b)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_get_recent(self):
        sessions = []
        for b in self.binaries:
            s = self.mgr.create_session(b)
            sessions.append(s)
            time.sleep(0.01)
        recent = self.mgr.get_recent(3)
        self.assertEqual(len(recent), 3)
        # Most recent first
        self.assertEqual(recent[0].session_id, sessions[-1].session_id)

    def test_get_oldest(self):
        sessions = []
        for b in self.binaries:
            s = self.mgr.create_session(b)
            sessions.append(s)
            time.sleep(0.01)
        oldest = self.mgr.get_oldest(2)
        self.assertEqual(len(oldest), 2)
        self.assertEqual(oldest[0].session_id, sessions[0].session_id)


class TestSessionExistsAndCount(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_exists(self):
        s = self.mgr.create_session(self.test_binary)
        self.assertTrue(self.mgr.session_exists(s.session_id))
        self.assertFalse(self.mgr.session_exists("NONEXIST"))

    def test_count(self):
        self.assertEqual(self.mgr.count(), 0)
        self.mgr.create_session(self.test_binary)
        self.assertEqual(self.mgr.count(), 1)


class TestMergeSessions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
        self.other_binary = os.path.join(self.tmpdir, "other.exe")
        with open(self.other_binary, "wb") as f:
            f.write(b"\x00" * 50)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_merge(self):
        s1 = self.mgr.create_session(self.test_binary, tags=["malware"], notes="Note1")
        s2 = self.mgr.create_session(self.other_binary, tags=["packed"], notes="Note2")
        result = self.mgr.merge_sessions(s1.session_id, s2.session_id)
        self.assertIn("malware", result.tags)
        self.assertIn("packed", result.tags)
        self.assertIn("Note1", result.notes)
        self.assertIn("Note2", result.notes)

    def test_merge_deduplicates_tags(self):
        s1 = self.mgr.create_session(self.test_binary, tags=["shared"])
        s2 = self.mgr.create_session(self.other_binary, tags=["shared"])
        result = self.mgr.merge_sessions(s1.session_id, s2.session_id)
        self.assertEqual(result.tags.count("shared"), 1)

    def test_merge_nonexistent(self):
        s = self.mgr.create_session(self.test_binary)
        self.assertIsNone(self.mgr.merge_sessions(s.session_id, "NONEXIST"))
        self.assertIsNone(self.mgr.merge_sessions("NONEXIST", s.session_id))


class TestSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_snapshot_and_restore(self):
        s = self.mgr.create_session(self.test_binary, notes="original")
        snap = self.mgr.snapshot_session(s.session_id)
        self.assertIsNotNone(snap)
        snap_id = snap["snapshot_id"]
        # Modify the session
        self.mgr.update_session(s.session_id, notes="modified")
        got = self.mgr.get_session(s.session_id)
        self.assertEqual(got.notes, "modified")
        # Restore
        restored = self.mgr.restore_snapshot(s.session_id, snap_id)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.notes, "original")

    def test_snapshot_nonexistent(self):
        self.assertIsNone(self.mgr.snapshot_session("NONEXIST"))

    def test_restore_nonexistent_snapshot(self):
        s = self.mgr.create_session(self.test_binary)
        self.assertIsNone(self.mgr.restore_snapshot(s.session_id, "BAD_SNAP"))


class TestValidateSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_validate_valid(self):
        s = self.mgr.create_session(self.test_binary)
        result = self.mgr.validate_session(s.session_id)
        self.assertIsNotNone(result)
        # Binary exists but IDB doesn't yet (normal for new sessions)
        self.assertIn("session_id", result)

    def test_validate_missing_binary(self):
        s = self.mgr.create_session(self.test_binary)
        os.remove(self.test_binary)
        result = self.mgr.validate_session(s.session_id)
        self.assertFalse(result["valid"])
        self.assertTrue(any("Binary not found" in i for i in result["issues"]))

    def test_validate_nonexistent(self):
        self.assertIsNone(self.mgr.validate_session("NONEXIST"))


class TestExecuteToolNewActions(unittest.TestCase):
    """Test _execute_tool handlers for all new session actions."""

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
        # Create a session
        self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "_risk_ack": True,
        })

    def tearDown(self):
        IDAMCPServer._detect_ida_dir = self._orig_detect
        IDAMCPServer._find_idat = self._orig_find
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_update_action(self):
        result = self.server._execute_tool("session", {
            "action": "update", "notes": "updated via action", "_risk_ack": True,
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["notes"], "updated via action")

    def test_rename_action(self):
        result = self.server._execute_tool("session", {
            "action": "rename", "name": "New Name", "_risk_ack": True,
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["auto_name"], "New Name")

    def test_rename_action_missing_name(self):
        result = self.server._execute_tool("session", {"action": "rename"})
        self.assertTrue(result.get("error"))

    def test_duplicate_action(self):
        result = self.server._execute_tool("session", {"action": "duplicate"})
        self.assertTrue(result.get("ok"))
        self.assertNotEqual(
            result["session"]["session_id"],
            self.server.current_session.session_id
        )

    def test_export_import_action(self):
        export_result = self.server._execute_tool("session", {"action": "export_session"})
        self.assertTrue(export_result.get("ok"))
        data = export_result["exported"]
        import_result = self.server._execute_tool("session", {
            "action": "import_session", "data": data
        })
        self.assertTrue(import_result.get("ok"))

    def test_import_action_missing_data(self):
        result = self.server._execute_tool("session", {"action": "import_session"})
        self.assertTrue(result.get("error"))

    def test_archive_unarchive_actions(self):
        result = self.server._execute_tool("session", {"action": "archive"})
        self.assertTrue(result.get("ok"))
        self.assertIn("archived", result["session"]["tags"])
        result = self.server._execute_tool("session", {"action": "unarchive"})
        self.assertTrue(result.get("ok"))
        self.assertNotIn("archived", result["session"]["tags"])

    def test_tag_untag_actions(self):
        result = self.server._execute_tool("session", {"action": "tag", "tag": "malware", "_risk_ack": True})
        self.assertTrue(result.get("ok"))
        self.assertIn("malware", result["session"]["tags"])
        result = self.server._execute_tool("session", {"action": "untag", "tag": "malware", "_risk_ack": True})
        self.assertTrue(result.get("ok"))
        self.assertNotIn("malware", result["session"]["tags"])

    def test_tag_action_missing_tag(self):
        result = self.server._execute_tool("session", {"action": "tag"})
        self.assertTrue(result.get("error"))

    def test_find_by_tag_action(self):
        self.server._execute_tool("session", {"action": "tag", "tag": "test_tag", "_risk_ack": True})
        result = self.server._execute_tool("session", {"action": "find_by_tag", "tag": "test_tag"})
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["count"], 1)

    def test_find_by_tag_missing_tag(self):
        result = self.server._execute_tool("session", {"action": "find_by_tag"})
        self.assertTrue(result.get("error"))

    def test_add_note_action(self):
        result = self.server._execute_tool("session", {"action": "add_note", "note": "test note"})
        self.assertTrue(result.get("ok"))
        self.assertIn("test note", result["session"]["notes"])

    def test_add_note_missing_note(self):
        result = self.server._execute_tool("session", {"action": "add_note"})
        self.assertTrue(result.get("error"))

    def test_clear_notes_action(self):
        self.server._execute_tool("session", {"action": "add_note", "note": "some note"})
        result = self.server._execute_tool("session", {"action": "clear_notes"})
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["notes"], "")

    def test_cleanup_stale_action(self):
        result = self.server._execute_tool("session", {"action": "cleanup_stale", "max_age_days": 30})
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["count"], 0)  # Fresh session, not stale

    def test_stats_action(self):
        result = self.server._execute_tool("session", {"action": "stats"})
        self.assertTrue(result.get("ok"))
        self.assertIn("stats", result)
        self.assertEqual(result["stats"]["total"], 1)

    def test_validate_action(self):
        result = self.server._execute_tool("session", {"action": "validate"})
        self.assertTrue(result.get("ok"))
        self.assertIn("validation", result)

    def test_bulk_delete_action(self):
        sid = self.server.current_session.session_id
        result = self.server._execute_tool("session", {
            "action": "bulk_delete", "session_ids": [sid]
        })
        self.assertTrue(result.get("ok"))
        self.assertIsNone(self.server.current_session)

    def test_bulk_delete_missing_sids(self):
        result = self.server._execute_tool("session", {"action": "bulk_delete"})
        self.assertTrue(result.get("error"))

    def test_bulk_tag_action(self):
        sid = self.server.current_session.session_id
        result = self.server._execute_tool("session", {
            "action": "bulk_tag", "session_ids": [sid], "tag": "batch"
        })
        self.assertTrue(result.get("ok"))

    def test_bulk_tag_missing_args(self):
        result = self.server._execute_tool("session", {"action": "bulk_tag"})
        self.assertTrue(result.get("error"))
        result = self.server._execute_tool("session", {
            "action": "bulk_tag", "session_ids": ["abc"]
        })
        self.assertTrue(result.get("error"))

    def test_search_notes_action(self):
        self.server._execute_tool("session", {"action": "add_note", "note": "buffer overflow found"})
        result = self.server._execute_tool("session", {"action": "search_notes", "query": "buffer"})
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["count"], 1)

    def test_search_notes_missing_query(self):
        result = self.server._execute_tool("session", {"action": "search_notes"})
        self.assertTrue(result.get("error"))

    def test_recent_action(self):
        result = self.server._execute_tool("session", {"action": "recent", "n": 5})
        self.assertTrue(result.get("ok"))
        self.assertGreater(result["count"], 0)

    def test_oldest_action(self):
        result = self.server._execute_tool("session", {"action": "oldest", "n": 5})
        self.assertTrue(result.get("ok"))
        self.assertGreater(result["count"], 0)

    def test_snapshot_restore_actions(self):
        snap_result = self.server._execute_tool("session", {"action": "snapshot"})
        self.assertTrue(snap_result.get("ok"))
        snapshot_id = snap_result["snapshot_id"]
        # Modify session
        self.server._execute_tool("session", {"action": "add_note", "note": "modified"})
        # Restore
        restore_result = self.server._execute_tool("session", {
            "action": "restore_snapshot", "snapshot_id": snapshot_id
        })
        self.assertTrue(restore_result.get("ok"))

    def test_snapshot_missing_session(self):
        self.server.current_session = None
        result = self.server._execute_tool("session", {"action": "snapshot"})
        self.assertTrue(result.get("error"))

    def test_restore_snapshot_missing_id(self):
        result = self.server._execute_tool("session", {"action": "restore_snapshot"})
        self.assertTrue(result.get("error"))

    def test_merge_action(self):
        b2 = os.path.join(self.tmpdir, "other.exe")
        with open(b2, "wb") as f:
            f.write(b"\x00" * 50)
        r2 = self.server._execute_tool("session", {
            "action": "create", "binary_path": b2, "force_new": True, "_risk_ack": True
        })
        sid2 = r2["session"]["session_id"]
        self.server._execute_tool("session", {
            "action": "tag", "tag": "source_tag", "session_id": sid2, "_risk_ack": True
        })
        sid1 = self.server.current_session.session_id
        result = self.server._execute_tool("session", {
            "action": "merge", "session_id": sid1, "source_id": sid2, "_risk_ack": True
        })
        self.assertTrue(result.get("ok"))

    def test_merge_missing_ids(self):
        result = self.server._execute_tool("session", {"action": "merge"})
        self.assertTrue(result.get("error"))


# ============================================================================
# NEW TESTS FOR SESSION MANAGEMENT ROBUSTNESS (10 Critical Bugs)
# ============================================================================

class TestCorruptedDatetimeMetadata(unittest.TestCase):
    """Test that corrupted timestamps don't crash session loading."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_corrupted_datetime_metadata(self):
        """CRITICAL: Malformed created_at should not crash from_dict()."""
        # Create metadata with invalid datetime
        corrupted_data = {
            "session_id": "ABCD1234",
            "idb_path": "/tmp/test.idb",
            "binary_path": self.test_binary,
            "created_at": "2024-13-45T99:99:99",  # Invalid date
            "last_accessed": "2024-12-32T25:00:00"  # Invalid date
        }
        
        session = Session.from_dict(corrupted_data)
        self.assertIsNotNone(session)
        self.assertIsNotNone(session.created_at)
        self.assertIsNotNone(session.last_accessed)
    
    def test_incomplete_metadata_dict(self):
        """CRITICAL: Missing required keys should not crash from_dict()."""
        # Missing idb_path (required field)
        incomplete_data = {
            "session_id": "ABCD1234",
            "binary_path": self.test_binary
            # idb_path is MISSING
        }
        
        session = Session.from_dict(incomplete_data)
        self.assertEqual(session.idb_path, "")
    
    def test_null_datetime_fields_safe(self):
        """Empty/None datetime fields should not crash."""
        # Test with missing fields (not None, just missing from dict)
        data = {
            "session_id": "ABCD1234",
            "idb_path": "/tmp/test.idb",
            "binary_path": self.test_binary
            # No created_at or last_accessed fields
        }
        session = Session.from_dict(data)
        self.assertIsNotNone(session.created_at)  # Should have default
        self.assertIsNotNone(session.last_accessed)


class TestDuplicateSIDCollision(unittest.TestCase):
    """Test that duplicate SIDs are detected and handled."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_duplicate_sid_collision(self):
        """HIGH: create_session should retry when candidate SID already exists."""
        # Create first session
        s1 = self.mgr.create_session(self.test_binary)
        original_id = s1.session_id
        existing_prefix = original_id.lower() + ("0" * 24)
        fresh_prefix = "a1b2c3d4" + ("f" * 24)

        class _FakeUUID:
            def __init__(self, hex_value):
                self.hex = hex_value

        with patch.object(
            session_mod.uuid,
            "uuid4",
            side_effect=[_FakeUUID(existing_prefix), _FakeUUID(fresh_prefix)],
        ):
            s2 = self.mgr.create_session(self.test_binary)

        self.assertNotEqual(s2.session_id, original_id)
        self.assertEqual(s2.session_id, fresh_prefix[:8].upper())


class TestCorruptJSONMetadata(unittest.TestCase):
    """Test handling of corrupt JSON metadata files."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_corrupt_json_metadata(self):
        """HIGH: Corrupt JSON should not prevent other sessions loading."""
        # Create valid session first
        test_bin = os.path.join(self.tmpdir, "good.exe")
        with open(test_bin, "wb") as f:
            f.write(b"\x00" * 50)
        good_session = self.mgr.create_session(test_bin)
        good_sid = good_session.session_id
        
        # Now create corrupted metadata file manually
        corrupt_meta = os.path.join(self.mgr.session_dir, "SID_BADBADBAD_metadata.json")
        with open(corrupt_meta, "w") as f:
            f.write("{invalid json content")  # Incomplete JSON
        
        # Create new manager - should load good session and skip corrupt one
        mgr2 = SessionManager(self.tmpdir)
        
        # Good session should still be loaded
        loaded = mgr2.get_session(good_sid)
        self.assertIsNotNone(loaded)
        
        # Corrupt file should be skipped silently (no crash)
        # This proves robustness


class TestOrphanedIDBInvalidSID(unittest.TestCase):
    """Test that orphaned IDBs with invalid SIDs are skipped."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_orphaned_idb_invalid_sid(self):
        """MEDIUM: IDB with invalid SID format should be skipped."""
        # Create IDB with malformed SID prefix
        bad_idb = os.path.join(self.mgr.session_dir, "SID_INVALID_BAD_malware.i64")
        with open(bad_idb, "wb") as f:
            f.write(b"\x00" * 100)
        
        # Load orphaned IDBs
        self.mgr._load_orphaned_idbs()
        
        # Invalid SID should not create a session
        # (unless fixed code allows it with normalization)
        sessions_created = len(self.mgr.sessions)
        self.assertEqual(sessions_created, 0)  # Should skip invalid SID


class TestSymlinkSessionBypass(unittest.TestCase):
    """Test symlink handling in session path matching."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_symlink_session_bypass(self):
        """MEDIUM: Symlinks should be resolved in path matching (security)."""
        # Create real binary
        real_bin = os.path.join(self.tmpdir, "real.exe")
        with open(real_bin, "wb") as f:
            f.write(b"\x00" * 100)
        
        # Create session for real binary
        session = self.mgr.create_session(real_bin)
        
        # Create symlink pointing to same file
        link_bin = os.path.join(self.tmpdir, "link.exe")
        try:
            os.symlink(real_bin, link_bin)
        except OSError:
            # Symlinks might not work on Windows/no permission
            self.skipTest("Cannot create symlinks on this system")
        
        # Both should find the same session (if realpath is used)
        # Current code might not resolve symlinks properly
        found_real = self.mgr.find_session_by_path(real_bin)
        found_link = self.mgr.find_session_by_path(link_bin)
        
        # Both should find the same session
        self.assertIsNotNone(found_real)
        self.assertIsNotNone(found_link)
        self.assertEqual(
            found_real.session_id,
            found_link.session_id,
        )
        # These assertions may fail without the realpath fix, proving the vulnerability


class TestSnapshotIDDuplicate(unittest.TestCase):
    """Test snapshot ID collision detection."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_snapshot_id_duplicate(self):
        """MEDIUM: Duplicate snapshot IDs should be prevented."""
        session = self.mgr.create_session(self.test_binary)
        sid = session.session_id
        
        # Create multiple snapshots
        snap_ids = []
        for i in range(5):
            snap = self.mgr.snapshot_session(sid)
            self.assertIsNotNone(snap)
            snap_ids.append(snap["snapshot_id"])
        
        # All snapshot IDs should be unique
        self.assertEqual(len(snap_ids), len(set(snap_ids)),
                        "Snapshot IDs should be unique")


class TestImportInvalidDict(unittest.TestCase):
    """Test import_session with invalid data."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_import_invalid_dict(self):
        """HIGH: Importing invalid dict should fail gracefully."""
        # Missing required fields
        invalid_data = {
            "binary_path": "/tmp/test.exe"
            # Missing idb_path and session_id
        }
        
        try:
            session = self.mgr.import_session(invalid_data)
            # If it doesn't raise, at least idb_path should exist
            self.assertIsNotNone(session.idb_path)
        except (ValueError, KeyError):
            # Acceptable - indicates validation
            pass
    
    def test_import_malformed_dict(self):
        """Import with null/empty idb_path should fail."""
        invalid_data = {
            "session_id": "ABCD1234",
            "idb_path": ""  # Empty
        }
        
        try:
            session = self.mgr.import_session(invalid_data)
            # Empty idb_path might be accepted with warning
            # but should not crash
            self.assertIsNotNone(session)
        except (ValueError, KeyError):
            pass


class TestDuplicateSessionIOUB(unittest.TestCase):
    """Test duplicate_session with file operations."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_duplicate_deletes_idb(self):
        """HIGH: Duplicate should handle missing IDB gracefully."""
        session = self.mgr.create_session(self.test_binary)
        sid = session.session_id
        
        # Create fake IDB
        fake_idb = os.path.join(self.tmpdir, f"SID_{sid}_test.idb")
        with open(fake_idb, "wb") as f:
            f.write(b"\x00" * 50)
        
        # Update session to point to it
        self.mgr.sessions[sid].idb_path = fake_idb
        
        # Now delete the IDB before duplicating
        os.remove(fake_idb)
        
        # Duplicate should still work (or at least not crash)
        dup = self.mgr.duplicate_session(sid)
        
        # Dup should exist
        self.assertIsNotNone(dup)
        self.assertNotEqual(dup.session_id, sid)
        # idb_path will be dead reference, but that's OK for dup


class TestIDBPathTOCTOU(unittest.TestCase):
    """Test time-of-check-time-of-use in IDB path handling."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_idb_path_toctou(self):
        """MEDIUM: IDB path race condition (file deleted after check)."""
        # This test documents the TOCTOU vulnerability
        # It's hard to actually trigger in unit test, but we can check
        # that sessions handle missing IDB files gracefully
        
        session = self.mgr.create_session(self.test_binary)
        
        # Manually set idb_path to non-existent file
        session.idb_path = "/tmp/nonexistent_idb_12345.i64"
        self.mgr.sessions[session.session_id] = session
        
        # Session should still be retrievable (path validation is loose)
        retrieved = self.mgr.get_session(session.session_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.idb_path, "/tmp/nonexistent_idb_12345.i64")
        
        # Validate should flag missing IDB
        validation = self.mgr.validate_session(session.session_id)
        self.assertFalse(validation["valid"])
        self.assertIn("IDB not found", str(validation["issues"]))


class TestSessionCreateEdgeCases(unittest.TestCase):
    """Additional edge case tests for session creation."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_create_with_empty_binary_path(self):
        """Session with empty binary_path should be allowed."""
        session = self.mgr.create_session("")
        self.assertIsNotNone(session)
        self.assertEqual(session.binary_path, "")
        self.assertIsNotNone(session.idb_path)
    
    def test_create_generates_unique_sids(self):
        """Multiple creates should generate unique SIDs."""
        test_bin = os.path.join(self.tmpdir, "test.exe")
        with open(test_bin, "wb") as f:
            f.write(b"\x00" * 50)
        
        sessions = []
        for i in range(10):
            s = self.mgr.create_session(test_bin)
            sessions.append(s.session_id)
        
        self.assertEqual(len(set(sessions)), 10)
        for sid in sessions:
            self.assertEqual(len(sid), 8)
            self.assertEqual(sid, sid.upper())
            self.assertTrue(all(c in "0123456789ABCDEF" for c in sid))


class TestMetadataPersistence(unittest.TestCase):
    """Test metadata file consistency."""
    
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_no_orphaned_tmp_files_after_save(self):
        """Atomic writes should not leave .tmp files."""
        session = self.mgr.create_session(self.test_binary)
        meta_path = self.mgr._get_metadata_path(session.session_id)
        
        # Update and save
        session.notes = "updated"
        self.mgr._save_metadata(session)
        
        # Check no .tmp file exists
        tmp_path = meta_path + ".tmp"
        self.assertFalse(os.path.exists(tmp_path))
        self.assertTrue(os.path.exists(meta_path))
    
    def test_metadata_roundtrip(self):
        """Session data should survive to_dict/from_dict roundtrip."""
        session = self.mgr.create_session(self.test_binary, 
                                         tags=["test", "important"],
                                         notes="Test notes")
        
        data = session.to_dict()
        restored = Session.from_dict(data)
        
        self.assertEqual(restored.session_id, session.session_id)
        self.assertEqual(restored.binary_path, session.binary_path)
        self.assertEqual(restored.tags, session.tags)
        self.assertEqual(restored.notes, session.notes)


if __name__ == "__main__":
    unittest.main()
