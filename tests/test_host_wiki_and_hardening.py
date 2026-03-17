#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import IDAMCPServer, MCPError, SessionManager  # noqa: E402


class TestHostWikiTool(unittest.TestCase):
    def setUp(self):
        self._old_wiki_env = os.environ.get("IDA_MCP_WIKI_DIR")
        self.tmpdir = tempfile.mkdtemp(prefix="wiki-test-")
        wiki_tools = Path(self.tmpdir) / "docs" / "wiki" / "tools"
        wiki_workflows = Path(self.tmpdir) / "docs" / "wiki" / "workflows"
        wiki_tools.mkdir(parents=True, exist_ok=True)
        wiki_workflows.mkdir(parents=True, exist_ok=True)
        (wiki_tools / "demo.md").write_text(
            "# DEMO Tool Manual\n\n## What It Does\nDemo analysis helper.\n\n## Failure Modes\nNone.\n",
            encoding="utf-8",
        )
        (wiki_tools / "trace.md").write_text(
            "# TRACE Tool Manual\n\n## What It Does\nTrace execution and summarize flow.\n",
            encoding="utf-8",
        )
        (wiki_workflows / "ForensicProtocol.md").write_text(
            "# Forensic Protocol\n\n## Steps\nCollect, verify, and report.\n",
            encoding="utf-8",
        )
        os.environ["IDA_MCP_WIKI_DIR"] = str(Path(self.tmpdir) / "docs" / "wiki")
        self.server = IDAMCPServer()

    def tearDown(self):
        if self._old_wiki_env is None:
            os.environ.pop("IDA_MCP_WIKI_DIR", None)
        else:
            os.environ["IDA_MCP_WIKI_DIR"] = self._old_wiki_env
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_list_topics_without_session(self):
        res = self.server._execute_tool("wiki", {"action": "list_topics"})
        self.assertTrue(res.get("ok"))
        self.assertIn("tools", res.get("categories", {}))
        self.assertIn("demo", res["categories"]["tools"])

    def test_read_rejects_path_traversal(self):
        res = self.server._execute_tool(
            "wiki", {"action": "read", "topic": "../etc/passwd"}
        )
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)

    def test_generated_fallback_when_no_wiki_dir(self):
        self.server._resolve_wiki_root = lambda: ""
        res = self.server._execute_tool(
            "wiki", {"action": "read", "topic": "tools/wiki"}
        )
        self.assertTrue(res.get("ok"))
        self.assertIn("WIKI Tool Manual", res.get("content", ""))

    def test_search_supports_category_and_ranking(self):
        res = self.server._execute_tool(
            "wiki",
            {
                "action": "search",
                "query": "trace",
                "category": "tools",
                "max_results": 5,
                "fuzzy": True,
            },
        )
        self.assertTrue(res.get("ok"))
        self.assertGreaterEqual(res.get("count", 0), 1)
        self.assertEqual(res["matches"][0]["topic"], "tools/trace")

    def test_read_missing_topic_returns_suggestions(self):
        res = self.server._execute_tool(
            "wiki", {"action": "read", "topic": "trce", "strict_topic": True}
        )
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.FILE_NOT_FOUND)
        suggestions = res.get("details", {}).get("suggestions", [])
        self.assertTrue(any("tools/trace" == s for s in suggestions))

    def test_read_includes_related_topics(self):
        res = self.server._execute_tool(
            "wiki", {"action": "read", "topic": "tools/demo", "include_related": True}
        )
        self.assertTrue(res.get("ok"))
        self.assertIn("related_topics", res)
        self.assertIn("tools/trace", res["related_topics"])


class TestHostHardening(unittest.TestCase):
    def setUp(self):
        self.server = IDAMCPServer()

    def test_session_invalid_id_format(self):
        res = self.server._execute_tool(
            "session", {"action": "get", "session_id": "../../../bad"}
        )
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)

    def test_batch_rejects_non_object_arguments(self):
        res = self.server._handle_batch(
            {"calls": [{"name": "wiki", "arguments": "not-an-object"}]}
        )
        self.assertTrue(res.get("ok"))
        self.assertTrue(res["results"][0]["result"].get("error"))
        self.assertEqual(res["results"][0]["result"].get("code"), MCPError.INVALID_ARGS)

    def test_batch_rejects_nested_batch(self):
        res = self.server._handle_batch({"calls": [{"name": "batch", "arguments": {}}]})
        self.assertTrue(res.get("ok"))
        self.assertTrue(res["results"][0]["result"].get("error"))
        self.assertEqual(res["results"][0]["result"].get("code"), MCPError.INVALID_ARGS)

    def test_tools_list_keeps_wiki_tool_slot(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
        tools_payload = res["result"]["tools"]
        tools = {t["name"] for t in tools_payload}
        self.assertLessEqual(len(tools_payload), 30)
        self.assertIn("wiki", tools)
        self.assertIn("misc", tools)
        self.assertNotIn("plugins", tools)
        self.assertNotIn("xfer_analysis", tools)
        self.assertNotIn("xref_analysis", tools)

        misc_tool = next(t for t in tools_payload if t["name"] == "misc")
        misc_actions = misc_tool["inputSchema"]["properties"]["action"]["enum"]
        self.assertIn("plugin_list", misc_actions)
        self.assertIn("plugin_run", misc_actions)
        self.assertIn("health", misc_actions)

        project_tool = next(t for t in tools_payload if t["name"] == "project")
        project_actions = project_tool["inputSchema"]["properties"]["action"]["enum"]
        self.assertNotIn("read", project_actions)
        self.assertNotIn("write", project_actions)
        self.assertNotIn("sessions", project_actions)
        self.assertNotIn("batch", project_actions)

    def test_tools_list_ultra_routes_docs_to_wiki_and_keeps_schema_tiny(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
        self.assertEqual(res["result"]["mode"], "ultra")
        tools_payload = res["result"]["tools"]

        funcs_tool = next(t for t in tools_payload if t["name"] == "funcs")
        self.assertEqual(funcs_tool["description"], "Use wiki(topic='tools/funcs') for usage.")
        funcs_props = funcs_tool["inputSchema"]["properties"]
        self.assertIn("action", funcs_props)
        self.assertIn("idb", funcs_props)
        self.assertNotIn("source_action", funcs_props)
        self.assertNotIn("next_token", funcs_props)

        wiki_tool = next(t for t in tools_payload if t["name"] == "wiki")
        self.assertEqual(wiki_tool["description"], "Wiki index + docs. Start with wiki(action='index').")

    def test_misc_health_requires_no_session(self):
        res = self.server._execute_tool("misc", {"action": "health"})
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("action"), "health")
        self.assertIn("runtime", res)
        self.assertIn("ida", res)

    def test_batch_allows_legacy_plugins_alias_resolution(self):
        res = self.server._handle_batch(
            {"calls": [{"name": "plugins", "arguments": "not-an-object"}]}
        )
        self.assertTrue(res.get("ok"))
        self.assertTrue(res["results"][0]["result"].get("error"))
        # If alias resolution failed, this would have been Unknown tool.
        self.assertEqual(res["results"][0]["result"].get("code"), MCPError.INVALID_ARGS)

    def test_batch_supports_shorthand_calls(self):
        res = self.server._handle_batch({"calls": ["session:status"]})
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["summary"]["total"], 1)
        self.assertEqual(res["summary"]["errors"], 0)
        self.assertEqual(res["results"][0]["name"], "session")

    def test_call_tool_accepts_session_and_sid_idb_refs(self):
        tempdir = tempfile.mkdtemp()
        try:
            self.server.session_mgr = SessionManager(tempdir)
            session = self.server.session_mgr.create_session("/tmp/demo.bin")
            session.idb_path = os.path.join(tempdir, f"SID_{session.session_id}_demo.i64")
            self.server.session_mgr.sessions[session.session_id] = session
            self.assertFalse(os.path.exists(session.idb_path))
            self.assertEqual(
                self.server._resolve_session_from_idb_ref(session.session_id).session_id,
                session.session_id,
            )
            self.assertEqual(
                self.server._resolve_session_from_idb_ref(os.path.basename(session.idb_path)).session_id,
                session.session_id,
            )
            self.assertEqual(
                self.server._resolve_session_from_idb_ref(session.idb_path).session_id,
                session.session_id,
            )
            self.assertEqual(
                self.server._resolve_session_from_idb_ref(session.binary_path).session_id,
                session.session_id,
            )
        finally:
            shutil.rmtree(tempdir, ignore_errors=True)

    def test_wrapper_source_action_defaults_to_list_when_available(self):
        action, err = self.server._wrapper_source_action("funcs", {"action": "head"}, "head")
        self.assertIsNone(err)
        self.assertEqual(action, "list")

    def test_wrapper_source_action_requires_source_when_no_list_action(self):
        action, err = self.server._wrapper_source_action("code", {"action": "head"}, "head")
        self.assertIsNone(action)
        self.assertTrue(err.get("error"))
        self.assertEqual(err.get("code"), MCPError.INVALID_ARGS)

    def test_grep_pattern_alias_not_forwarded_to_source_action(self):
        captured = {}

        def fake_execute(tool_name, args):
            captured["tool"] = tool_name
            captured["args"] = dict(args)
            return {"functions": "sub_main"}

        self.server._execute_tool = fake_execute
        res = IDAMCPServer._handle_tool_grep_action(
            self.server,
            "funcs",
            {"action": "grep", "source_action": "list", "pattern": "sub_main"},
        )
        self.assertTrue(res.get("ok"))
        self.assertNotIn("pattern", captured["args"])


class TestResponseCompaction(unittest.TestCase):
    def setUp(self):
        self.server = IDAMCPServer()
        self.tmpdir = tempfile.mkdtemp(prefix="resp-compaction-")
        self.server.session_mgr = SessionManager(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tools_call_uses_compact_mode_by_default(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "session", "arguments": {"action": "status"}},
        }
        resp = self.server.handle_request(req)
        text = resp["result"]["content"][0]["text"]
        payload = json.loads(text)
        self.assertEqual(payload, {"total_sessions": 0})
        self.assertNotIn("\n", text)

    def test_tools_call_full_mode_preserves_verbose_shape(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "session",
                "arguments": {"action": "status", "_response_mode": "full"},
            },
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("ok", payload)
        self.assertIn("session", payload)
        self.assertIn("total_sessions", payload)

    def test_batch_compacts_envelope_in_default_mode(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "batch",
                "arguments": {
                    "calls": [{"name": "session", "arguments": {"action": "status"}}]
                },
            },
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("results", payload)
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["ok"], 1)
        self.assertEqual(payload["summary"]["errors"], 0)
        self.assertFalse(payload["summary"].get("stopped_on_error", False))
        self.assertEqual(payload["results"][0]["tool"], "session")
        self.assertTrue(payload["results"][0]["ok"])
        self.assertEqual(payload["results"][0]["data"], {"total_sessions": 0})


if __name__ == "__main__":
    unittest.main()
