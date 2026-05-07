#!/usr/bin/env python3
"""
Tests for the revamped session management, funcs, misc, and modify tools.
These tests run standalone without IDA Pro.
"""
import os
import sys
import json
import tempfile
import shutil
import unittest

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import (
    SessionManager,
    Session,
    IDAMCPServer,
    make_error,
    MCPError,
    truncate_response,
    continue_truncated,
)


class TestSessionManagerRevamp(unittest.TestCase):
    """Test revamped SessionManager functionality."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        # Create a dummy test binary
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_session(self):
        session = self.mgr.create_session(self.test_binary)
        self.assertIsNotNone(session)
        self.assertIn(session.session_id, self.mgr.sessions)
        self.assertEqual(session.binary_path, self.test_binary)

    def test_find_session_by_binary_path(self):
        session = self.mgr.create_session(self.test_binary)
        found = self.mgr.find_session_by_path(self.test_binary)
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, session.session_id)

    def test_find_session_by_idb_path(self):
        session = self.mgr.create_session(self.test_binary)
        found = self.mgr.find_session_by_path(session.idb_path)
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, session.session_id)

    def test_find_session_not_found(self):
        found = self.mgr.find_session_by_path("/nonexistent/path.exe")
        self.assertIsNone(found)

    def test_discover_sessions_no_filter(self):
        s1 = self.mgr.create_session(self.test_binary)
        other = os.path.join(self.tmpdir, "other.exe")
        with open(other, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(other)
        result = self.mgr.discover_sessions()
        self.assertEqual(len(result), 2)

    def test_discover_sessions_with_query(self):
        s1 = self.mgr.create_session(self.test_binary)
        other = os.path.join(self.tmpdir, "other.exe")
        with open(other, "wb") as f:
            f.write(b"\x00" * 50)
        s2 = self.mgr.create_session(other)
        result = self.mgr.discover_sessions("test.exe")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].session_id, s1.session_id)

    def test_delete_session(self):
        session = self.mgr.create_session(self.test_binary)
        sid = session.session_id
        self.assertTrue(self.mgr.delete_session(sid))
        self.assertNotIn(sid, self.mgr.sessions)

    def test_get_session_updates_access(self):
        session = self.mgr.create_session(self.test_binary)
        original_access = session.last_accessed
        import time
        time.sleep(0.01)
        loaded = self.mgr.get_session(session.session_id)
        self.assertGreaterEqual(loaded.last_accessed, original_access)

    def test_session_persistence(self):
        session = self.mgr.create_session(self.test_binary)
        sid = session.session_id
        # Create a new manager
        mgr2 = SessionManager(self.tmpdir)
        loaded = mgr2.get_session(sid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.binary_path, self.test_binary)

    def test_session_with_analysis_options(self):
        opts = {"processor": "arm", "bitness": 32, "endian": "le"}
        session = self.mgr.create_session(self.test_binary, analysis_options=opts)
        self.assertEqual(session.analysis_options, opts)
        self.assertFalse(session.analysis_applied)

    def test_create_session_with_idb_path_and_args(self):
        idb_path = os.path.join(self.tmpdir, "custom_idb")
        session = self.mgr.create_session(
            self.test_binary, idb_path=idb_path, ida_args=["-P+"]
        )
        self.assertTrue(session.idb_path.endswith(".i64"))
        self.assertEqual(session.ida_args, ["-P+"])
        self.assertFalse(session.analysis_applied)


class TestSessionExecuteTool(unittest.TestCase):
    """Test _execute_tool session actions (without IDA running)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)
        # Monkey-patch IDAMCPServer to skip IDA detection
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
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_session(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        self.assertTrue(result.get("ok"))
        self.assertIn("session", result)
        self.assertIsNotNone(self.server.current_session)

    def test_create_session_missing_binary(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": "/nonexistent/binary.exe"
        })
        self.assertTrue(result.get("error"))

    def test_create_session_no_path(self):
        result = self.server._execute_tool("session", {
            "action": "create"
        })
        self.assertTrue(result.get("error"))

    def test_create_session_reuses_existing(self):
        # First creation
        r1 = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        self.assertTrue(r1.get("ok"))
        sid1 = r1["session"]["session_id"]

        # Second creation with same binary - should reuse
        r2 = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        self.assertTrue(r2.get("ok"))
        self.assertEqual(r2["session"]["session_id"], sid1)
        self.assertIn("note", r2)

    def test_create_session_force_new(self):
        r1 = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        self.assertTrue(r1.get("ok"))
        r2 = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "force_new": True
        })
        self.assertTrue(r2.get("ok"))
        self.assertNotEqual(r2["session"]["session_id"], r1["session"]["session_id"])

    def test_create_session_rejects_idb_path_arg(self):
        idb_path = os.path.join(self.tmpdir, "existing.i64")
        with open(idb_path, "wb") as f:
            f.write(b"")
        result = self.server._execute_tool("session", {
            "action": "create",
            "idb_path": idb_path
        })
        self.assertTrue(result.get("error"))
        self.assertEqual(result.get("code"), MCPError.INVALID_ARGS)

    def test_create_session_with_ida_args(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "ida_args": ["-P+"]
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["ida_args"], ["-P+"])

    def test_get_session(self):
        r = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        sid = r["session"]["session_id"]
        result = self.server._execute_tool("session", {
            "action": "get",
            "session_id": sid
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["session_id"], sid)
        self.assertIn("is_running", result["session"])

    def test_get_session_not_found(self):
        result = self.server._execute_tool("session", {
            "action": "get",
            "session_id": "NONEXIST"
        })
        self.assertTrue(result.get("error"))

    def test_list_sessions_with_runtime_status(self):
        self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        result = self.server._execute_tool("session", {"action": "list"})
        self.assertTrue(result.get("ok"))
        self.assertGreater(len(result["sessions"]), 0)
        self.assertIn("is_running", result["sessions"][0])

    def test_switch_by_binary_path(self):
        self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        sid = self.server.current_session.session_id
        self.server.current_session = None

        result = self.server._execute_tool("session", {
            "action": "switch",
            "binary_path": self.test_binary
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["session"]["session_id"], sid)

    def test_status_with_runtime_info(self):
        self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        result = self.server._execute_tool("session", {"action": "status"})
        self.assertTrue(result.get("ok"))
        self.assertIsNotNone(result["session"])
        self.assertIn("total_sessions", result)

    def test_close_session(self):
        self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary
        })
        sid = self.server.current_session.session_id
        result = self.server._execute_tool("session", {
            "action": "close",
            "session_id": sid
        })
        self.assertTrue(result.get("ok"))
        self.assertIsNone(self.server.current_session)

    def test_session_with_arch_params(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "processor": "arm",
            "bitness": 32,
            "endian": "le"
        })
        self.assertTrue(result.get("ok"))
        session = result["session"]
        self.assertEqual(session["analysis_options"]["processor"], "arm")
        self.assertEqual(session["analysis_options"]["bitness"], 32)

    def test_session_create_architecture_block(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "architecture": {
                "processor": "arm",
                "bitness": 32,
                "endian": "little",
            },
        })
        self.assertTrue(result.get("ok"))
        opts = result["session"].get("analysis_options", {})
        self.assertEqual(opts.get("processor"), "arm")
        self.assertEqual(opts.get("bitness"), 32)
        self.assertEqual(opts.get("endian"), "little")

    def test_session_create_conflicting_arch_values_rejected(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "processor": "arm",
            "analysis_options": {"processor": "mipsl"},
        })
        self.assertTrue(result.get("error"))

    def test_session_create_with_arch_does_not_reuse_existing(self):
        first = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
        })
        self.assertTrue(first.get("ok"))
        sid1 = first["session"]["session_id"]

        second = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "processor": "arm",
            "bitness": 32,
        })
        self.assertTrue(second.get("ok"))
        sid2 = second["session"]["session_id"]
        self.assertNotEqual(sid1, sid2)

    def test_session_create_canonicalizes_processor_aliases(self):
        result = self.server._execute_tool("session", {
            "action": "create",
            "binary_path": self.test_binary,
            "processor": "aarch64",
        })
        self.assertTrue(result.get("ok"))
        opts = result["session"].get("analysis_options", {})
        self.assertEqual(opts.get("processor"), "arm")
        self.assertEqual(opts.get("bitness"), 64)

    def test_list_pagination(self):
        # Create multiple sessions
        for i in range(5):
            b = os.path.join(self.tmpdir, f"binary_{i}.exe")
            with open(b, "wb") as f:
                f.write(b"\x00" * 50)
            self.server._execute_tool("session", {
                "action": "create",
                "binary_path": b
            })

        result = self.server._execute_tool("session", {
            "action": "list",
            "limit": 2,
            "offset": 0
        })
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total"], 5)


class TestMiscReadWriteFile(unittest.TestCase):
    """Test misc tool read_file and write_file actions.
    
    These test the action routing in ida_mcp_stdio, not the IDA-side misc tool.
    Since read_file/write_file are added to the IDA-side misc.py, we verify
    the schema and action list are correctly updated.
    """

    def test_misc_actions_include_read_write(self):
        """Verify TOOL_ACTIONS for misc includes read_file and write_file."""
        from ida_mcp_stdio import TOOL_ACTIONS
        self.assertIn("read_file", TOOL_ACTIONS["misc"])
        self.assertIn("write_file", TOOL_ACTIONS["misc"])

    def test_misc_description_includes_read_write(self):
        """Verify TOOL_DESCRIPTIONS for misc mentions read_file/write_file."""
        from ida_mcp_stdio import TOOL_DESCRIPTIONS
        desc = TOOL_DESCRIPTIONS["misc"]
        self.assertIn("read_file", desc)
        self.assertIn("write_file", desc)

    def test_misc_schema_has_path_and_content(self):
        """Verify TOOL_ARG_SCHEMAS for misc has path and content params."""
        from ida_mcp_stdio import TOOL_ARG_SCHEMAS
        schema = TOOL_ARG_SCHEMAS["misc"]
        self.assertIn("path", schema)
        self.assertIn("content", schema)
        self.assertIn("encoding", schema)


class TestFuncsToolActions(unittest.TestCase):
    """Test that funcs tool registrations are correct."""

    def test_funcs_actions_include_rename(self):
        from ida_mcp_stdio import TOOL_ACTIONS
        self.assertIn("rename", TOOL_ACTIONS["funcs"])

    def test_funcs_description_mentions_regex(self):
        from ida_mcp_stdio import TOOL_DESCRIPTIONS
        desc = TOOL_DESCRIPTIONS["funcs"]
        self.assertIn("regex", desc)


class TestSessionToolActions(unittest.TestCase):
    """Test session tool action registrations."""

    def test_session_actions_include_get(self):
        from ida_mcp_stdio import TOOL_ACTIONS
        self.assertIn("get", TOOL_ACTIONS["session"])

    def test_session_description_updated(self):
        from ida_mcp_stdio import TOOL_DESCRIPTIONS
        desc = TOOL_DESCRIPTIONS["session"]
        self.assertIn("get", desc)
        self.assertIn("runtime", desc.lower())


class TestModifyToolDescription(unittest.TestCase):
    """Test modify tool description updates."""

    def test_modify_description_mentions_multi_line(self):
        from ida_mcp_stdio import TOOL_DESCRIPTIONS
        desc = TOOL_DESCRIPTIONS["modify"]
        self.assertIn("semicolons", desc)


class TestTruncationContinue(unittest.TestCase):
    def test_truncate_and_continue_list(self):
        payload = {"items": list(range(1000))}
        max_tokens = 500
        truncated = truncate_response(payload, max_tokens=max_tokens)
        self.assertTrue(truncated.get("_truncated"))
        token = truncated["_continue"]["token"]
        expected_offset = max(5, max_tokens // 200)
        cont = continue_truncated(token, field="items")
        self.assertTrue(cont.get("ok"))
        self.assertEqual(cont.get("offset"), expected_offset)
        count = cont.get("count", 0)
        self.assertEqual(cont.get("items"), list(range(expected_offset, expected_offset + count)))

    def test_truncate_and_continue_string(self):
        payload = {"text": "A" * 5000}
        max_tokens = 500
        truncated = truncate_response(payload, max_tokens=max_tokens)
        self.assertTrue(truncated.get("_truncated"))
        token = truncated["_continue"]["token"]
        expected_offset = max_tokens
        cont = continue_truncated(token, field="text")
        self.assertTrue(cont.get("ok"))
        self.assertEqual(cont.get("offset"), expected_offset)
        self.assertEqual(len(cont.get("text", "")), cont.get("count"))


if __name__ == "__main__":
    unittest.main()
