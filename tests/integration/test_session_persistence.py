#!/usr/bin/env python3
"""
Simple test to verify session persistence works by checking server logs.
"""
import os
import sys
import time
import glob

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import SessionManager, CACHE_DIR

def test_session_persistence():
    print("=" * 60)
    print("Session Persistence Unit Test")
    print("=" * 60)
    
    # Create manager 1
    print("\n[1] Creating SessionManager instance 1...")
    mgr1 = SessionManager(CACHE_DIR)
    
    # Check if it loaded existing sessions
    existing = mgr1.discover_sessions()
    print(f"  Loaded {len(existing)} existing session(s)")
    for s in existing[:3]:
        print(f"    - {s.session_id}: {os.path.basename(s.binary_path)}")
    
    # Create a new session
    print("\n[2] Creating new session...")
    test_binary = os.path.abspath("tests/data/test_binary.exe")
    if not os.path.exists(test_binary):
        print(f"  ✗ Test binary not found: {test_binary}")
        return False
    
    session = mgr1.create_session(test_binary)
    print(f"  Created session: {session.session_id}")
    print(f"  IDB path: {session.idb_path}")
    
    # Verify metadata file was created
    meta_path = mgr1._get_metadata_path(session.session_id)
    if not os.path.exists(meta_path):
        print(f"  ✗ Metadata file not created: {meta_path}")
        return False
    print(f"  ✓ Metadata file created: {meta_path}")
    
    # Destroy manager 1
    session_id = session.session_id
    del mgr1
    print("\n[3] Destroyed SessionManager instance 1")
    
    # Create manager 2 - should auto-load the session
    print("\n[4] Creating SessionManager instance 2...")
    mgr2 = SessionManager(CACHE_DIR)
    
    # Check if session was loaded
    loaded = mgr2.get_session(session_id)
    if not loaded:
        print(f"  ✗ Session {session_id} was NOT loaded from metadata")
        return False
    
    print(f"  ✓ Session {session_id} was loaded from metadata!")
    print(f"    Binary: {loaded.binary_path}")
    print(f"    IDB: {loaded.idb_path}")
    print(f"    Created: {loaded.created_at}")
    print(f"    Last accessed: {loaded.last_accessed}")
    
    # Verify last_accessed was updated
    original_access = session.last_accessed
    new_access = loaded.last_accessed
    if new_access > original_access:
        print(f"  ✓ Last accessed timestamp was updated")
    
    # Cleanup
    print("\n[5] Cleaning up test session...")
    mgr2.delete_session(session_id)
    if not os.path.exists(meta_path):
        print(f"  ✓ Metadata file deleted")
    
    print("\n" + "=" * 60)
    print("✓ SESSION PERSISTENCE TEST PASSED")
    print("=" * 60)
    return True

if __name__ == "__main__":
    try:
        success = test_session_persistence()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ TEST FAILED WITH EXCEPTION:")
        print(f"  {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
