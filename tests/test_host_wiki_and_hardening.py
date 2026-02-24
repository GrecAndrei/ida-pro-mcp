#!/usr/bin/env python3
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import IDAMCPServer, MCPError  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
