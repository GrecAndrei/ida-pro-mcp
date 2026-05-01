#!/usr/bin/env python3
"""
Test session persistence - verify sessions survive server restart.
"""

import json
import os
import subprocess
import sys
import time

def _extract_tool_result(resp):
    """Extract inner tool result from MCP content array."""
    if not resp or "result" not in resp:
        return None
    result = resp["result"]
    if isinstance(result, dict) and "content" in result:
        content = result["content"]
        if isinstance(content, list) and content:
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except Exception:
                return text
    return result


def send_request(proc, method, params):
    """Send JSON-RPC request and get response"""
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

    # Read response
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def _stop_server(proc):
    """Gracefully stop a stdin-based server subprocess."""
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def test_persistence():
    print("=" * 60)
    print("Session Persistence Test")
    print("=" * 60)

    # Start server instance 1
    print("\n[1] Starting server instance 1...")
    server_path = os.path.join(os.path.dirname(__file__), "..", "ida_mcp_stdio.py")
    proc1 = subprocess.Popen(
        [sys.executable, "-u", os.path.abspath(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)

    # Initialize
    print("[2] Initializing...")
    resp = send_request(proc1, "initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "persistence-test", "version": "1.0"}
    })

    if not resp or "result" not in resp:
        print("✗ Failed to initialize")
        _stop_server(proc1)
        return False

    # Create session
    print("[3] Creating session...")
    binary_path = os.path.abspath("tests/data/test_binary.exe")

    resp = send_request(proc1, "tools/call", {
        "name": "session",
        "arguments": {
            "action": "create",
            "binary_path": binary_path,
            "force_new": True,
        }
    })

    inner = _extract_tool_result(resp)
    if not inner or inner.get("error"):
        print("✗ Failed to create session")
        _stop_server(proc1)
        return False

    session_id = inner.get("session", {}).get("session_id")
    print(f"  Created session: {session_id}")

    # Terminate server 1 gracefully
    print("[4] Terminating server instance 1...")
    _stop_server(proc1)
    time.sleep(1)

    # Start server instance 2
    print("[5] Starting server instance 2...")
    proc2 = subprocess.Popen(
        [sys.executable, "-u", os.path.abspath(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)

    # Initialize server 2
    print("[6] Initializing server 2...")
    resp = send_request(proc2, "initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "persistence-test", "version": "1.0"}
    })

    if not resp or "result" not in resp:
        print("✗ Failed to initialize server 2")
        _stop_server(proc2)
        return False

    # List sessions - should include the one we created
    print("[7] Listing sessions...")
    resp = send_request(proc2, "tools/call", {
        "name": "session",
        "arguments": {
            "action": "list"
        }
    })

    inner = _extract_tool_result(resp)
    if not inner or inner.get("error"):
        print("✗ Failed to list sessions")
        _stop_server(proc2)
        return False

    sessions = inner.get("sessions", [])
    print(f"  Found {len(sessions)} session(s)")

    # Check if our session is there
    found = False
    for s in sessions:
        if s.get("session_id") == session_id:
            found = True
            print(f"  ✓ Session {session_id} persisted!")
            print(f"    Binary: {s.get('binary_path')}")
            print(f"    IDB: {s.get('idb_path')}")
            print(f"    Created: {s.get('created_at')}")
            print(f"    Last accessed: {s.get('last_accessed')}")
            break

    # Cleanup
    print("[8] Cleaning up...")
    if found:
        send_request(proc2, "tools/call", {
            "name": "session",
            "arguments": {
                "action": "close",
                "session_id": session_id
            }
        })

    _stop_server(proc2)

    print("\n" + "=" * 60)
    if found:
        print("✓ SESSION PERSISTENCE TEST PASSED")
    else:
        print("✗ SESSION PERSISTENCE TEST FAILED")
        print(f"  Session {session_id} was not found after restart")
    print("=" * 60)

    return found

if __name__ == "__main__":
    success = test_persistence()
    sys.exit(0 if success else 1)
