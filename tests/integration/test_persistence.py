#!/usr/bin/env python3
"""
Test session persistence - verify sessions survive server restart.
"""
import json
import os
import subprocess
import sys
import time
import pytest

# Check IDA availability without relative imports
_IDA_AVAILABLE = bool(
    os.path.isfile(os.path.join(os.environ.get("IDA_DIR") or os.environ.get("IDADIR") or "", "idat"))
)
pytestmark = pytest.mark.skipif(not _IDA_AVAILABLE, reason="IDA integration tests require licensed IDA Pro")


@pytest.mark.xfail(reason="Known flaky stdio startup in this integration harness")


def _extract_tool_result(resp):
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
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def _stop_server(proc):
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
    server_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ida_mcp_stdio.py")
    proc1 = None
    proc2 = None
    session_id = None

    try:
        proc1 = subprocess.Popen(
            [sys.executable, "-u", os.path.abspath(server_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(2)

        resp = send_request(proc1, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "persistence-test", "version": "1.0"},
        })
        assert resp and "result" in resp, "Failed to initialize server 1"

        binary_path = os.path.abspath("tests/data/test_binary.exe")
        resp = send_request(proc1, "tools/call", {
            "name": "session",
            "arguments": {"action": "create", "binary_path": binary_path, "force_new": True},
        })
        inner = _extract_tool_result(resp)
        assert inner and not inner.get("error"), f"Failed to create session: {inner}"
        session_id = inner.get("session", {}).get("session_id")
        assert session_id, "No session_id in response"

        _stop_server(proc1)
        proc1 = None
        time.sleep(1)

        proc2 = subprocess.Popen(
            [sys.executable, "-u", os.path.abspath(server_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(2)

        resp = send_request(proc2, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "persistence-test", "version": "1.0"},
        })
        assert resp and "result" in resp, "Failed to initialize server 2"

        resp = send_request(proc2, "tools/call", {
            "name": "session", "arguments": {"action": "list"},
        })
        inner = _extract_tool_result(resp)
        assert inner and not inner.get("error"), f"Failed to list sessions: {inner}"

        sessions = inner.get("sessions", [])
        found = any(s.get("session_id") == session_id for s in sessions)
        assert found, f"Session {session_id} was not found after server restart"

        if session_id:
            send_request(proc2, "tools/call", {
                "name": "session",
                "arguments": {"action": "close", "session_id": session_id},
            })

    finally:
        for p in (proc1, proc2):
            if p:
                _stop_server(p)
