#!/usr/bin/env python3
"""
Tests for the revamped session management features.
Covers thread safety, atomic writes, defensive copies, path validation,
and all 31 new SessionManager methods + their _execute_tool handlers.
"""
import os
import sys
import json
import tempfile
import shutil
import time
import copy
import unittest
import threading

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import (
    SessionManager,
    Session,
    IDAMCPServer,
    make_error,
    MCPError,
    validate_path,
)


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
        snap_id = self.mgr.snapshot_session(s.session_id)
        self.assertIsNotNone(snap_id)
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
            "binary_path": self.test_binary
        })

    def tearDown(self):
        IDAMCPServer._detect_ida_dir = self._orig_detect
        IDAMCPServer._find_idat = self._orig_find
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_update_action(self):
        result = self.server._execute_tool("session", {
            "action": "update", "notes": "updated via action"
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["notes"], "updated via action")

    def test_rename_action(self):
        result = self.server._execute_tool("session", {
            "action": "rename", "name": "New Name"
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
        result = self.server._execute_tool("session", {"action": "tag", "tag": "malware"})
        self.assertTrue(result.get("ok"))
        self.assertIn("malware", result["session"]["tags"])
        result = self.server._execute_tool("session", {"action": "untag", "tag": "malware"})
        self.assertTrue(result.get("ok"))
        self.assertNotIn("malware", result["session"]["tags"])

    def test_tag_action_missing_tag(self):
        result = self.server._execute_tool("session", {"action": "tag"})
        self.assertTrue(result.get("error"))

    def test_find_by_tag_action(self):
        self.server._execute_tool("session", {"action": "tag", "tag": "test_tag"})
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
            "action": "create", "binary_path": b2, "force_new": True
        })
        sid2 = r2["session"]["session_id"]
        self.server._execute_tool("session", {
            "action": "tag", "tag": "source_tag", "session_id": sid2
        })
        sid1 = self.server.current_session.session_id
        result = self.server._execute_tool("session", {
            "action": "merge", "session_id": sid1, "source_id": sid2
        })
        self.assertTrue(result.get("ok"))

    def test_merge_missing_ids(self):
        result = self.server._execute_tool("session", {"action": "merge"})
        self.assertTrue(result.get("error"))


if __name__ == "__main__":
    unittest.main()
