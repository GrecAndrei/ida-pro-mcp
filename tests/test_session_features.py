#!/usr/bin/env python3
"""
Test suite for new session manager features.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import SessionManager, Session, CACHE_DIR


class TestSessionManagerRobustness(unittest.TestCase):
    """Test robustness improvements in SessionManager"""
    
    def setUp(self):
        """Create a temporary test directory"""
        self.test_dir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.test_dir)
    
    def tearDown(self):
        """Clean up test directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_uuid_collision_handling(self):
        """Test that create_session handles UUID collisions"""
        # Create many sessions - should not fail with collision
        sessions = []
        for i in range(100):
            binary_path = f"/tmp/test_binary_{i}.exe"
            session = self.mgr.create_session(binary_path)
            sessions.append(session.session_id)
        
        # All session IDs should be unique
        self.assertEqual(len(sessions), len(set(sessions)))
    
    def test_atomic_metadata_save(self):
        """Test that metadata saves are atomic"""
        session = self.mgr.create_session("/tmp/test.exe")
        
        # Verify temp file doesn't exist after successful save
        session_dir = self.mgr.session_dir
        temp_files = [f for f in os.listdir(session_dir) if ".tmp." in f]
        self.assertEqual(len(temp_files), 0)
    
    def test_thread_safe_operations(self):
        """Test thread-safe session operations"""
        import threading
        
        session = self.mgr.create_session("/tmp/test.exe")
        sid = session.session_id
        
        results = []
        
        def access_session():
            for _ in range(10):
                s = self.mgr.get_session(sid)
                if s:
                    results.append(s.access_count)
        
        threads = [threading.Thread(target=access_session) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have incremented access count safely
        final_session = self.mgr._get_session_internal(sid)
        self.assertGreater(final_session.access_count, 0)
    
    def test_session_copy_prevents_mutation(self):
        """Test that get_session returns copies to prevent external mutations"""
        session = self.mgr.create_session("/tmp/test.exe", tags=["original"])
        sid = session.session_id
        
        # Get session and modify the returned copy
        copy = self.mgr.get_session(sid)
        copy.tags.append("modified")
        copy.notes = "This is a modified copy"
        
        # Get session again - should not have the modifications
        fresh = self.mgr.get_session(sid)
        self.assertNotIn("modified", fresh.tags)
        self.assertNotEqual(fresh.notes, "This is a modified copy")
    
    def test_path_validation(self):
        """Test that path validation prevents directory traversal"""
        from ida_mcp_stdio import validate_path
        
        # Valid paths
        self.assertIsNotNone(validate_path("/tmp/test.exe"))
        self.assertIsNotNone(validate_path("test.exe", allow_create=True))
        
        # Invalid paths
        self.assertIsNone(validate_path(""))
        self.assertIsNone(validate_path("\x00"))
        self.assertIsNone(validate_path("../../../etc/passwd"))


class TestNewSessionFeatures(unittest.TestCase):
    """Test new session management features"""
    
    def setUp(self):
        """Create a temporary test directory"""
        self.test_dir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.test_dir)
    
    def tearDown(self):
        """Clean up test directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_update_session(self):
        """Test update_session method"""
        session = self.mgr.create_session("/tmp/test.exe")
        sid = session.session_id
        
        # Update various properties
        success = self.mgr.update_session(
            sid,
            tags=["updated"],
            notes="Updated notes",
            priority=5,
            status="active"
        )
        self.assertTrue(success)
        
        # Verify updates
        updated = self.mgr.get_session(sid)
        self.assertEqual(updated.tags, ["updated"])
        self.assertEqual(updated.notes, "Updated notes")
        self.assertEqual(updated.priority, 5)
        self.assertEqual(updated.status, "active")
    
    def test_search_with_filters(self):
        """Test discover_sessions with advanced filters"""
        # Create sessions with different properties
        s1 = self.mgr.create_session("/tmp/test1.exe", tags=["malware"], priority=5, notes="High priority malware")
        s2 = self.mgr.create_session("/tmp/test2.exe", tags=["benign"], priority=2, notes="Low priority benign")
        s3 = self.mgr.create_session("/tmp/test3.exe", tags=["malware", "ransomware"], priority=4)
        
        # Filter by tags
        malware_sessions = self.mgr.discover_sessions(tags=["malware"])
        self.assertEqual(len(malware_sessions), 2)
        
        # Filter by priority
        high_priority = self.mgr.discover_sessions(priority_min=4)
        self.assertEqual(len(high_priority), 2)
        
        # Filter by query
        benign_sessions = self.mgr.discover_sessions(query="benign")
        self.assertEqual(len(benign_sessions), 1)
    
    def test_statistics(self):
        """Test get_statistics method"""
        # Create sessions with different statuses
        s1 = self.mgr.create_session("/tmp/test1.exe", priority=5)
        s2 = self.mgr.create_session("/tmp/test2.exe", priority=3)
        s3 = self.mgr.create_session("/tmp/test3.exe", priority=3)
        
        # Access some sessions
        self.mgr.get_session(s1.session_id)
        self.mgr.get_session(s1.session_id)
        self.mgr.get_session(s2.session_id)
        
        stats = self.mgr.get_statistics()
        self.assertEqual(stats["total_sessions"], 3)
        self.assertIn("by_status", stats)
        self.assertIn("by_priority", stats)
        self.assertGreater(stats["total_accesses"], 0)
    
    def test_audit_log(self):
        """Test audit log functionality"""
        s1 = self.mgr.create_session("/tmp/test1.exe")
        s2 = self.mgr.create_session("/tmp/test2.exe")
        self.mgr.delete_session(s1.session_id)
        
        log = self.mgr.get_audit_log(limit=10)
        self.assertGreater(len(log), 0)
        
        # Check log entries have required fields
        for entry in log:
            self.assertIn("timestamp", entry)
            self.assertIn("action", entry)
            self.assertIn("session_id", entry)
    
    def test_cleanup_stale_sessions(self):
        """Test cleanup_stale_sessions method"""
        # Create an old session by manually setting last_accessed
        session = self.mgr.create_session("/tmp/test.exe")
        internal_session = self.mgr._get_session_internal(session.session_id)
        internal_session.last_accessed = datetime.now() - timedelta(days=35)
        self.mgr._save_metadata(internal_session)
        
        # Create a recent session
        recent = self.mgr.create_session("/tmp/recent.exe")
        
        # Cleanup sessions older than 30 days
        deleted = self.mgr.cleanup_stale_sessions(days=30)
        
        # Old session should be deleted, recent should remain
        self.assertIn(session.session_id, deleted)
        self.assertIsNotNone(self.mgr.get_session(recent.session_id))
        self.assertIsNone(self.mgr.get_session(session.session_id))
    
    def test_backup_session(self):
        """Test backup_session method"""
        session = self.mgr.create_session("/tmp/test.exe", notes="Test backup")
        
        backup_path = self.mgr.backup_session(session.session_id)
        self.assertIsNotNone(backup_path)
        
        # Verify metadata backup exists
        metadata_file = f"{backup_path}_metadata.json"
        self.assertTrue(os.path.exists(metadata_file))
        
        # Verify metadata content
        import json
        with open(metadata_file, 'r') as f:
            data = json.load(f)
            self.assertEqual(data["session_id"], session.session_id)
            self.assertEqual(data["notes"], "Test backup")
    
    def test_session_properties(self):
        """Test new session properties (priority, status, access_count)"""
        session = self.mgr.create_session(
            "/tmp/test.exe",
            tags=["test"],
            notes="Test session",
            priority=4
        )
        
        self.assertEqual(session.priority, 4)
        self.assertEqual(session.status, "created")
        self.assertEqual(session.access_count, 0)
        
        # Access the session
        self.mgr.get_session(session.session_id)
        
        # Check access count increased
        updated = self.mgr._get_session_internal(session.session_id)
        self.assertGreater(updated.access_count, 0)


class TestSessionPersistence(unittest.TestCase):
    """Test session persistence across manager restarts"""
    
    def setUp(self):
        """Create a temporary test directory"""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_session_survives_restart(self):
        """Test that sessions survive manager restart"""
        # Create manager and session
        mgr1 = SessionManager(self.test_dir)
        session = mgr1.create_session(
            "/tmp/test.exe",
            tags=["persistent"],
            notes="Test persistence",
            priority=5
        )
        sid = session.session_id
        
        # Destroy manager
        del mgr1
        
        # Create new manager - should load the session
        mgr2 = SessionManager(self.test_dir)
        loaded = mgr2.get_session(sid)
        
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, sid)
        self.assertEqual(loaded.tags, ["persistent"])
        self.assertEqual(loaded.notes, "Test persistence")
        self.assertEqual(loaded.priority, 5)
    
    def test_corrupted_metadata_recovery(self):
        """Test recovery from corrupted metadata"""
        # Create manager and session
        mgr1 = SessionManager(self.test_dir)
        session = mgr1.create_session("/tmp/test.exe")
        sid = session.session_id
        
        # Corrupt the metadata file
        metadata_path = mgr1._get_metadata_path(sid)
        with open(metadata_path, 'w') as f:
            f.write("{ invalid json }")
        
        # Create new manager - should handle corruption gracefully
        mgr2 = SessionManager(self.test_dir)
        
        # Corrupted session should not be loaded
        loaded = mgr2.get_session(sid)
        self.assertIsNone(loaded)
        
        # Corrupted file should be backed up
        backup_files = [f for f in os.listdir(self.test_dir + "/sessions") if ".corrupt." in f]
        self.assertGreater(len(backup_files), 0)


if __name__ == "__main__":
    unittest.main()
