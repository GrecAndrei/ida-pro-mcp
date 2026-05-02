#!/usr/bin/env python3
"""
Comprehensive tests for the 100+ bug fixes and improvements.
Tests error codes, session tags/notes, tool registration, validation, truncation.
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
# Add error_handling module path directly (avoid __init__.py zeromcp import)
_eh_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "ida_pro_mcp", "ida_mcp")
if _eh_dir not in sys.path:
    sys.path.insert(0, _eh_dir)

from ida_mcp_stdio import (
    SessionManager,
    Session,
    BookmarkManager,
    IDAMCPServer,
    make_error,
    MCPError,
    TOOLS,
    TOOL_ACTIONS,
    TOOL_DESCRIPTIONS,
    TOOL_ARG_SCHEMAS,
    build_input_schema,
    truncate_response,
    continue_truncated,
)


# =============================================================================
# 1. MCPError codes and ERROR_HINTS (error_handling.py)
# =============================================================================


class TestMCPErrorCodes(unittest.TestCase):
    """Test that all expected error codes exist."""

    def test_host_error_codes_exist(self):
        self.assertEqual(MCPError.FILE_NOT_FOUND, "FILE_NOT_FOUND")
        self.assertEqual(MCPError.SESSION_REQUIRED, "SESSION_REQUIRED")
        self.assertEqual(MCPError.ACTION_NOT_FOUND, "ACTION_NOT_FOUND")
        self.assertEqual(MCPError.SESSION_NOT_FOUND, "SESSION_NOT_FOUND")
        self.assertEqual(MCPError.BATCH_EMPTY, "BATCH_EMPTY")
        self.assertEqual(MCPError.BATCH_TOO_LARGE, "BATCH_TOO_LARGE")
        self.assertEqual(MCPError.BOOKMARK_NOT_FOUND, "BOOKMARK_NOT_FOUND")
        self.assertEqual(MCPError.TRUNCATION_TOKEN_EXPIRED, "TRUNCATION_TOKEN_EXPIRED")
        self.assertEqual(MCPError.TRUNCATION_TOKEN_INVALID, "TRUNCATION_TOKEN_INVALID")
        self.assertEqual(MCPError.RPC_CONNECTION_ERROR, "RPC_CONNECTION_ERROR")

    def test_tool_side_100_plus_codes(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))
        from error_handling import MCPError as ToolMCPError, ERROR_HINTS
        codes = [attr for attr in dir(ToolMCPError)
                 if not attr.startswith('_') and isinstance(getattr(ToolMCPError, attr), str)]
        self.assertGreaterEqual(len(codes), 100,
                                f"Expected 100+ error codes, got {len(codes)}")

    def test_all_codes_have_hints(self):
        from error_handling import MCPError as ToolMCPError, ERROR_HINTS
        codes = [attr for attr in dir(ToolMCPError)
                 if not attr.startswith('_') and isinstance(getattr(ToolMCPError, attr), str)]
        for attr in codes:
            code = getattr(ToolMCPError, attr)
            self.assertIn(code, ERROR_HINTS,
                         f"Error code {code} missing from ERROR_HINTS")

    def test_hints_are_actionable(self):
        from error_handling import ERROR_HINTS
        for code, hint in ERROR_HINTS.items():
            self.assertIsInstance(hint, str)
            self.assertGreater(len(hint), 10,
                              f"Hint for {code} too short: '{hint}'")

    def test_tool_mcp_error_references_exist(self):
        import re
        from pathlib import Path
        from error_handling import MCPError as ToolMCPError

        repo_root = Path(__file__).resolve().parents[1]
        tool_dir = repo_root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"
        self.assertTrue(tool_dir.is_dir(), f"Tool directory not found: {tool_dir}")
        # MCPError constants are intentionally represented as uppercase string values.
        defined = {
            attr for attr in dir(ToolMCPError)
            if not attr.startswith('_') and isinstance(getattr(ToolMCPError, attr), str)
        }
        referenced = set()
        for path in tool_dir.glob("*.py"):
            referenced.update(re.findall(r"MCPError\.([A-Z_]+)", path.read_text(encoding="utf-8")))

        missing = sorted(referenced - defined)
        self.assertEqual(missing, [], f"Undefined MCPError constants referenced in tools: {missing}")


class TestMakeErrorWithHints(unittest.TestCase):
    def test_auto_hint(self):
        err = make_error(MCPError.FILE_NOT_FOUND, "Test file missing")
        self.assertIn("hint", err)

    def test_custom_hint(self):
        err = make_error(MCPError.FILE_NOT_FOUND, "msg", hint="Custom")
        self.assertEqual(err["hint"], "Custom")

    def test_tool_make_error_auto_hint(self):
        from error_handling import make_error as tool_make_error, MCPError as ToolMCPError
        err = tool_make_error(ToolMCPError.ADDRESS_INVALID, "Bad address")
        self.assertIn("hint", err)


# =============================================================================
# 2. Validation helpers
# =============================================================================


class TestValidationHelpers(unittest.TestCase):
    def test_parse_address_none(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe(None)
        self.assertIsNone(ea)
        self.assertEqual(err["code"], "MISSING_REQUIRED_ARG")

    def test_parse_address_empty(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe("")
        self.assertIsNone(ea)

    def test_parse_address_negative(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe(-1)
        self.assertIsNone(ea)
        self.assertIn("Negative", err["message"])

    def test_parse_address_hex(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe("0x401000")
        self.assertEqual(ea, 0x401000)
        self.assertIsNone(err)

    def test_parse_address_decimal(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe("12345")
        self.assertEqual(ea, 12345)

    def test_parse_address_float(self):
        from error_handling import parse_address_safe
        ea, err = parse_address_safe(1.0)
        self.assertEqual(ea, 1)

    def test_validate_action_valid(self):
        from error_handling import validate_action
        self.assertIsNone(validate_action("create", ["create", "delete"]))

    def test_validate_action_invalid(self):
        from error_handling import validate_action
        result = validate_action("creat", ["create", "delete"], "test")
        self.assertEqual(result["code"], "ACTION_NOT_FOUND")
        self.assertIn("create", result["hint"])

    def test_validate_count_valid(self):
        from error_handling import validate_count
        self.assertIsNone(validate_count(10))
        self.assertIsNone(validate_count(None))

    def test_validate_count_negative(self):
        from error_handling import validate_count
        result = validate_count(-1)
        self.assertEqual(result["code"], "INVALID_ARG_VALUE")

    def test_validate_count_too_large(self):
        from error_handling import validate_count
        result = validate_count(100000, max_count=1000)
        self.assertEqual(result["code"], "SIZE_LIMIT_EXCEEDED")

    def test_require_arg(self):
        from error_handling import require_arg
        self.assertIsNotNone(require_arg(None, "addr"))
        self.assertIsNotNone(require_arg("  ", "addr"))
        self.assertIsNone(require_arg("0x401000", "addr"))

    def test_require_one_of(self):
        from error_handling import require_one_of
        self.assertIsNotNone(require_one_of(a=None, b=None))
        self.assertIsNone(require_one_of(a="x", b=None))

    def test_validate_path_null_bytes(self):
        from error_handling import validate_path_safe
        path, err = validate_path_safe("test\x00file")
        self.assertIsNone(path)


# =============================================================================
# 3. Session improvements
# =============================================================================


class TestSessionImprovements(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.test_binary = os.path.join(self.tmpdir, "test.exe")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00" * 100)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_auto_name(self):
        s = self.mgr.create_session(self.test_binary)
        self.assertEqual(s.auto_name, "test.exe")

    def test_tags(self):
        s = self.mgr.create_session(self.test_binary, tags=["malware", "pe"])
        self.assertEqual(s.tags, ["malware", "pe"])

    def test_notes(self):
        s = self.mgr.create_session(self.test_binary, notes="VT sample")
        self.assertEqual(s.notes, "VT sample")

    def test_tags_persist(self):
        s = self.mgr.create_session(self.test_binary, tags=["test"])
        mgr2 = SessionManager(self.tmpdir)
        loaded = mgr2.get_session(s.session_id)
        self.assertEqual(loaded.tags, ["test"])

    def test_discover_by_tags(self):
        s1 = self.mgr.create_session(self.test_binary, tags=["malware"])
        other = os.path.join(self.tmpdir, "other.dll")
        with open(other, "wb") as f:
            f.write(b"\x00" * 50)
        self.mgr.create_session(other, tags=["clean"])
        result = self.mgr.discover_sessions("malware")
        self.assertEqual(len(result), 1)

    def test_discover_by_notes(self):
        self.mgr.create_session(self.test_binary, notes="suspicious ransomware")
        result = self.mgr.discover_sessions("ransomware")
        self.assertEqual(len(result), 1)

    def test_auto_name_from_idb(self):
        s = Session("AB12", "/tmp/SID_AB12_calc.exe.i64", "")
        self.assertEqual(s.auto_name, "calc.exe")

    def test_auto_name_fallback(self):
        s = Session("AB12", "", "")
        self.assertEqual(s.auto_name, "session_AB12")


class TestSessionCreateViaTool(unittest.TestCase):
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
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_with_tags_list(self):
        r = self.server._execute_tool("session", {
            "action": "create", "binary_path": self.test_binary,
            "tags": ["malware", "pe"],
        })
        self.assertTrue(r.get("ok"))
        self.assertEqual(r["session"]["tags"], ["malware", "pe"])

    def test_create_with_tags_string(self):
        r = self.server._execute_tool("session", {
            "action": "create", "binary_path": self.test_binary,
            "tags": "malware, pe", "force_new": True,
        })
        self.assertEqual(r["session"]["tags"], ["malware", "pe"])

    def test_create_with_notes(self):
        r = self.server._execute_tool("session", {
            "action": "create", "binary_path": self.test_binary,
            "notes": "From VT", "force_new": True,
        })
        self.assertEqual(r["session"]["notes"], "From VT")

    def test_auto_name(self):
        r = self.server._execute_tool("session", {
            "action": "create", "binary_path": self.test_binary,
            "force_new": True,
        })
        self.assertEqual(r["session"]["auto_name"], "test.exe")


# =============================================================================
# 4. Tool registration consistency
# =============================================================================


class TestToolRegistration(unittest.TestCase):
    def test_all_tools_have_descriptions(self):
        for t in TOOLS:
            self.assertIn(t, TOOL_DESCRIPTIONS)

    def test_all_tools_have_actions(self):
        for t in TOOLS:
            self.assertIn(t, TOOL_ACTIONS)

    def test_no_orphan_actions(self):
        for t in TOOL_ACTIONS:
            self.assertIn(t, TOOLS)

    def test_no_orphan_descriptions(self):
        for t in TOOL_DESCRIPTIONS:
            self.assertIn(t, TOOLS)

    def test_plugins_registered(self):
        self.assertIn("plugins", TOOLS)
        self.assertIn("plugins", TOOL_ACTIONS)
        self.assertIn("plugins", TOOL_DESCRIPTIONS)

    def test_batch_registered(self):
        self.assertIn("batch", TOOLS)
        self.assertIn("batch", TOOL_ACTIONS)
        self.assertIn("batch", TOOL_DESCRIPTIONS)

    def test_total_tool_count(self):
        self.assertGreaterEqual(len(TOOLS), 61)

    def test_schemas_build(self):
        for t in TOOLS:
            schema = build_input_schema(t)
            self.assertEqual(schema["type"], "object")


# =============================================================================
# 5. Error improvements
# =============================================================================


class TestImprovedErrors(unittest.TestCase):
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
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_session_not_found_hint(self):
        r = self.server._execute_tool("session", {"action": "get", "session_id": "X"})
        self.assertEqual(r["code"], "SESSION_NOT_FOUND")
        self.assertIn("hint", r)

    def test_invalid_action_hint(self):
        r = self.server._execute_tool("session", {"action": "nonexistent"})
        self.assertEqual(r["code"], "ACTION_NOT_FOUND")
        self.assertIn("hint", r)

    def test_no_session_hint(self):
        r = self.server._execute_tool("bookmarks", {"action": "list"})
        self.assertEqual(r["code"], "SESSION_REQUIRED")
        self.assertIn("hint", r)

    def test_bookmark_not_found_code(self):
        self.server._execute_tool("session", {"action": "create", "binary_path": self.test_binary})
        r = self.server._execute_tool("bookmarks", {"action": "delete", "id": 9999})
        self.assertEqual(r["code"], "BOOKMARK_NOT_FOUND")

    def test_truncation_invalid_token(self):
        r = self.server._execute_tool("truncation", {"action": "continue", "token": "BAD"})
        self.assertEqual(r["code"], "TRUNCATION_TOKEN_INVALID")

    def test_batch_empty(self):
        r = self.server._handle_batch({"calls": []})
        self.assertEqual(r["code"], "BATCH_EMPTY")

    def test_batch_too_large(self):
        r = self.server._handle_batch({"calls": [{"name": "session", "arguments": {"action": "status"}}] * 51})
        self.assertEqual(r["code"], "BATCH_TOO_LARGE")

    def test_batch_invalid_tool(self):
        r = self.server._handle_batch({"calls": [{"name": "nonexistent_tool"}]})
        self.assertTrue(r["results"][0]["result"].get("error"))

    def test_batch_error_messages_avoid_quoted_field_names(self):
        r = self.server._handle_batch({"calls": "not-a-list"})
        self.assertEqual(r.get("code"), "INVALID_ARGS")
        self.assertNotIn("'calls'", r.get("message", ""))

        r = self.server._handle_batch({"calls": [{"arguments": {}}]})
        msg = r["results"][0]["result"].get("message", "")
        self.assertNotIn("'name'", msg)

        r = self.server._handle_batch({"calls": [{"name": "wiki", "arguments": "x"}]})
        msg = r["results"][0]["result"].get("message", "")
        self.assertNotIn("'arguments'", msg)


# =============================================================================
# 6. Truncation improvements
# =============================================================================


class TestTruncationImprovements(unittest.TestCase):
    def test_hint_includes_token(self):
        payload = {"items": list(range(1000))}
        truncated = truncate_response(payload, max_tokens=500)
        token = truncated["_continue"]["token"]
        self.assertIn(token, truncated["_continue"]["hint"])

    def test_note_mentions_continuation(self):
        payload = {"items": list(range(1000))}
        truncated = truncate_response(payload, max_tokens=500)
        self.assertIn("truncation", truncated.get("items_note", "").lower())


# =============================================================================
# 7. Query/Edit consistency
# =============================================================================


class TestQueryEditActions(unittest.TestCase):
    def test_query_actions(self):
        expected = {"data", "search", "idb", "code", "types", "imports_deep", "symbols", "patterns"}
        self.assertEqual(set(TOOL_ACTIONS["query"]), expected)

    def test_modify_actions(self):
        expected = {"rename", "comment", "set_type", "patch_asm"}
        self.assertEqual(set(TOOL_ACTIONS["modify"]), expected)


# =============================================================================
# 8. Session switch/close/rebuild errors
# =============================================================================


class TestSessionSwitchCloseRebuild(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
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

    def test_switch_nonexistent(self):
        r = self.server._execute_tool("session", {"action": "switch", "session_id": "X"})
        self.assertEqual(r["code"], "SESSION_NOT_FOUND")

    def test_close_no_active(self):
        r = self.server._execute_tool("session", {"action": "close"})
        self.assertIn("hint", r)

    def test_rebuild_nonexistent(self):
        r = self.server._execute_tool("session", {"action": "rebuild", "session_id": "X"})
        self.assertEqual(r["code"], "SESSION_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
