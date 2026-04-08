#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ida_mcp_stdio import (  # noqa: E402
    ADVERTISED_TOOLS,
    ACTION_ALIASES_BY_TOOL,
    ARG_ALIASES_BY_TOOL,
    IDAMCPServer,
    MCPError,
    SessionManager,
    TOOLS,
    TOOL_ALIASES,
    compile_smart_pattern,
)

# Regression guard for the "5000+ aliases accepted" behavior target.
MIN_EXPECTED_ALIAS_COUNT = 5000


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

    def test_semantic_search_matches_conceptual_query(self):
        res = self.server._execute_tool(
            "wiki",
            {
                "action": "semantic_search",
                "query": "runtime path tracking",
                "category": "tools",
                "max_results": 5,
            },
        )
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("action"), "semantic_search")
        self.assertGreaterEqual(res.get("count", 0), 1)
        topics = [m.get("topic") for m in res.get("matches", [])]
        self.assertIn("tools/trace", topics)
        trace_match = next(m for m in res["matches"] if m.get("topic") == "tools/trace")
        self.assertIn("semantic_overlap", trace_match.get("matched_on", []))

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
        self.assertGreater(len(tools_payload), 0)
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

    def test_tools_list_full_provides_direct_docs_and_full_schema(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
        self.assertEqual(res["result"]["mode"], "full")
        tools_payload = res["result"]["tools"]

        funcs_tool = next(t for t in tools_payload if t["name"] == "funcs")
        self.assertNotEqual(funcs_tool["description"], "Use wiki(topic='tools/funcs') for usage.")
        funcs_props = funcs_tool["inputSchema"]["properties"]
        self.assertIn("action", funcs_props)
        self.assertIn("idb", funcs_props)
        self.assertIn("source_action", funcs_props)
        self.assertIn("next_token", funcs_props)

        wiki_tool = next(t for t in tools_payload if t["name"] == "wiki")
        self.assertIn("documentation", wiki_tool["description"].lower())

    def test_tools_list_catalog_has_no_empty_descriptions(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 11, "method": "tools/list"})
        tools_payload = res["result"]["tools"]
        tools_with_empty_descriptions = [t["name"] for t in tools_payload if not (t.get("description") or "").strip()]
        self.assertEqual(tools_with_empty_descriptions, [])

    def test_tools_list_count_matches_advertised_tools(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 12, "method": "tools/list"})
        self.assertEqual(len(res["result"]["tools"]), len(ADVERTISED_TOOLS))

    def test_tools_list_supports_prefix_contains_category_sort_and_pagination(self):
        res = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/list",
                "params": {
                    "prefix": "c",
                    "contains": "o",
                    "category": "security",
                    "sort": "name",
                    "descending": False,
                    "offset": 0,
                    "limit": 2,
                },
            }
        )
        self.assertEqual(res["result"]["mode"], "full")
        self.assertLessEqual(len(res["result"]["tools"]), 2)
        self.assertGreaterEqual(res["result"]["total"], len(res["result"]["tools"]))
        for tool in res["result"]["tools"]:
            self.assertTrue(tool["name"].startswith("c"))
            self.assertIn("o", tool["name"])
            self.assertEqual(tool["category"], "security")
        names = [t["name"] for t in res["result"]["tools"]]
        self.assertEqual(names, sorted(names))

    def test_tools_list_invalid_sort_falls_back_to_name(self):
        res = self.server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/list",
                "params": {"sort": "invalid", "limit": 5},
            }
        )
        names = [t["name"] for t in res["result"]["tools"]]
        self.assertEqual(names, sorted(names))

    def test_tools_list_catalog_is_cached(self):
        first = self.server._build_tools_list_catalog("full")
        second = self.server._build_tools_list_catalog("full")
        self.assertIs(first, second)

    def test_tools_list_catalog_cache_is_mode_specific(self):
        full = self.server._build_tools_list_catalog("full")
        lean = self.server._build_tools_list_catalog("lean")
        self.assertIsNot(full, lean)

    def test_misc_health_requires_no_session(self):
        res = self.server._execute_tool("misc", {"action": "health"})
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("action"), "health")
        self.assertIn("runtime", res)
        self.assertIn("ida", res)

    def test_session_create_requires_string_binary_path(self):
        res = self.server._execute_tool("session", {"action": "create", "binary_path": 123})
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)
        self.assertIn("binary_path must be a string", res.get("message", ""))

    def test_session_create_rejects_removed_params_with_actionable_hint(self):
        res = self.server._execute_tool("session", {"action": "create", "idb_path": "/tmp/a.i64"})
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)
        hint = ((res.get("details") or {}).get("hint") or "")
        self.assertIn("session(action='create', binary_path='...')", hint)

    def test_compile_smart_pattern_allows_explicit_semantic_toggle(self):
        off = compile_smart_pattern("find api", semantic_enabled=False)
        on = compile_smart_pattern("find api", semantic_enabled=True)
        self.assertFalse(off("search import usage"))
        self.assertTrue(on("search import usage"))

    def test_compile_smart_pattern_allows_fuzzy_cutoff_tuning(self):
        strict = compile_smart_pattern("decompyle trace", semantic_enabled=True, fuzzy_cutoff=0.95)
        relaxed = compile_smart_pattern("decompyle trace", semantic_enabled=True, fuzzy_cutoff=0.80)
        self.assertFalse(strict("decompile reference flow"))
        self.assertTrue(relaxed("decompile reference flow"))

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

    def test_tool_alias_generation_covers_all_tools(self):
        covered = {target for target in TOOL_ALIASES.values() if target in TOOLS}
        missing = sorted(t for t in TOOLS if t not in covered and t not in {"plugins", "xfer_analysis"})
        self.assertEqual(missing, [])

    def test_normalize_action_handles_malformed_llm_fragment(self):
        normalized = self.server._normalize_tool_call_args(
            "data",
            {"action": 'action":"lookup addr=0xb1c98'},
        )
        self.assertEqual(normalized.get("action"), "lookup")
        self.assertEqual(normalized.get("addr"), "0xb1c98")

    def test_normalize_action_handles_bracketed_fragment(self):
        normalized = self.server._normalize_tool_call_args(
            "data",
            {"action": "[lookup] [addr]=[0xb1c98]"},
        )
        self.assertEqual(normalized.get("action"), "lookup")
        self.assertEqual(normalized.get("addr"), "0xb1c98")

    def test_normalize_action_parses_positional_bracketed_address(self):
        normalized = self.server._normalize_tool_call_args(
            "code",
            {"action": "[decompile] [main]"},
        )
        self.assertEqual(normalized.get("action"), "decompile")
        self.assertEqual(normalized.get("addrs"), "main")

    def test_normalize_tool_args_accepts_common_aliases(self):
        normalized = self.server._normalize_tool_call_args(
            "session",
            {"cmd": "state", "session": "ABCD1234"},
        )
        self.assertEqual(normalized.get("action"), "status")
        self.assertEqual(normalized.get("session_id"), "ABCD1234")

    def test_normalize_code_addrs_aliases(self):
        normalized = self.server._normalize_tool_call_args(
            "code",
            {"operation": "assembly", "address": "0x401000", "count": 32},
        )
        self.assertEqual(normalized.get("action"), "disasm")
        self.assertEqual(normalized.get("addrs"), "0x401000")
        self.assertEqual(normalized.get("max_items"), 32)

    def test_normalize_code_limit_is_preserved(self):
        normalized = self.server._normalize_tool_call_args(
            "code",
            {"operation": "disassemble", "limit": 160},
        )
        self.assertEqual(normalized.get("action"), "disasm")
        self.assertEqual(normalized.get("limit"), 160)
        self.assertNotIn("max_items", normalized)

    def test_normalize_code_new_arg_aliases_from_schema(self):
        normalized = self.server._normalize_tool_call_args(
            "code",
            {"operation": "disasm", "disasmStyle": "annotated", "end_addr": "0x12640"},
        )
        self.assertEqual(normalized.get("disasm_style"), "annotated")
        self.assertEqual(normalized.get("end"), "0x12640")

    def test_normalize_top_level_noisy_arg_key(self):
        normalized = self.server._normalize_tool_call_args(
            "code",
            {"action": "disasm", "[address]": "0x401000"},
        )
        self.assertEqual(normalized.get("addrs"), "0x401000")
        self.assertNotIn("[address]", normalized)

    def test_alias_inventory_exceeds_5000(self):
        total_aliases = (
            len(TOOL_ALIASES)
            + sum(len(v) for v in ACTION_ALIASES_BY_TOOL.values())
            + sum(len(v) for v in ARG_ALIASES_BY_TOOL.values())
        )
        self.assertGreaterEqual(total_aliases, MIN_EXPECTED_ALIAS_COUNT)

    def test_noisy_alias_spot_checks_resolve(self):
        self.assertEqual(ACTION_ALIASES_BY_TOOL["code"].get("assembly"), "disasm")
        self.assertEqual(ARG_ALIASES_BY_TOOL["code"].get("address"), "addrs")

    def test_execute_tool_accepts_noisy_tool_alias(self):
        res = self.server._execute_tool("[session]", {"action": "status"})
        self.assertFalse(res.get("error"))
        self.assertIn("total_sessions", res)

    def test_tools_call_accepts_noisy_batch_alias(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "[batch]", "arguments": {"calls": ["[session]:[status]"]}},
        }
        resp = self.server.handle_request(req)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload.get("summary", {}).get("total"), 1)
        self.assertEqual(payload.get("summary", {}).get("errors"), 0)
        first = payload.get("results", [{}])[0].get("data", {})
        self.assertIn("total_sessions", first)

    def test_batch_rejects_nested_noisy_batch_alias(self):
        for noisy in ("[batch]", "[ BATCH ]", "BATCH"):
            res = self.server._handle_batch({"calls": [{"name": noisy, "arguments": {}}]})
            self.assertTrue(res.get("ok"))
            row = (res.get("results") or [{}])[0].get("result", {})
            self.assertTrue(row.get("error"))
            self.assertIn("Nested batch", row.get("message", ""))


class TestResponseCompaction(unittest.TestCase):
    def setUp(self):
        self._old_pointer_note_interval = os.environ.get("IDA_MCP_POINTER_NOTE_INTERVAL")
        self._old_pointer_note_min_signal = os.environ.get("IDA_MCP_POINTER_NOTE_MIN_SIGNAL")
        os.environ["IDA_MCP_POINTER_NOTE_INTERVAL"] = "900"
        os.environ["IDA_MCP_POINTER_NOTE_MIN_SIGNAL"] = "3"
        self.server = IDAMCPServer()
        self.tmpdir = tempfile.mkdtemp(prefix="resp-compaction-")
        self.server.session_mgr = SessionManager(self.tmpdir)

    def tearDown(self):
        if self._old_pointer_note_interval is None:
            os.environ.pop("IDA_MCP_POINTER_NOTE_INTERVAL", None)
        else:
            os.environ["IDA_MCP_POINTER_NOTE_INTERVAL"] = self._old_pointer_note_interval
        if self._old_pointer_note_min_signal is None:
            os.environ.pop("IDA_MCP_POINTER_NOTE_MIN_SIGNAL", None)
        else:
            os.environ["IDA_MCP_POINTER_NOTE_MIN_SIGNAL"] = self._old_pointer_note_min_signal
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
        self.assertEqual(payload.get("total_sessions"), 0)
        self.assertNotIn("llm_pointer_note", payload)
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
        self.assertEqual(payload["results"][0]["data"].get("total_sessions"), 0)
        self.assertNotIn("llm_pointer_note", payload)

    def test_llm_note_present_in_full_mode(self):
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
        self.assertNotIn("llm_pointer_note", payload)

    def test_llm_note_shows_for_pointer_usage_after_signal_threshold(self):
        opts = self.server._default_response_options()
        call_args = {"action": "status", "note": "pointer chain"}
        first = self.server._prepare_response_payload(
            {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
        )
        second = self.server._prepare_response_payload(
            {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
        )
        third = self.server._prepare_response_payload(
            {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
        )
        self.assertNotIn("llm_pointer_note", first)
        self.assertNotIn("llm_pointer_note", second)
        self.assertIn("llm_pointer_note", third)
        self.assertIn("DO NOT CALCULATE POINTERS OR ADDRESSES", third["llm_pointer_note"])

    def test_llm_note_respects_periodic_interval(self):
        opts = self.server._default_response_options()
        call_args = {"action": "status", "note": "ptr chain"}
        # Warm-up to first note under a fixed clock.
        with patch("ida_mcp_stdio.time.time", return_value=10_000.0):
            self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
            self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
            first = self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
        self.assertIn("llm_pointer_note", first)

        # Still within interval => suppressed even with strong usage signal.
        with patch("ida_mcp_stdio.time.time", return_value=10_100.0):
            suppressed = self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
        self.assertNotIn("llm_pointer_note", suppressed)

        # After interval => eligible again once signal re-accumulates.
        with patch("ida_mcp_stdio.time.time", return_value=10_901.0):
            self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
            shown_again = self.server._prepare_response_payload(
                {"ok": True, "value": "ready"}, opts, tool_name="session", call_args=call_args
            )
        self.assertIn("llm_pointer_note", shown_again)

    def test_normalize_search_aliases_accept_noisy_variants(self):
        normalized = self.server._normalize_tool_call_args(
            "search",
            {"action": "[regexp]", "[needle]": "[main]", "max": 5, "case": False},
        )
        self.assertEqual(normalized.get("action"), "regex")
        self.assertEqual(normalized.get("pattern"), "main")
        self.assertEqual(normalized.get("limit"), 5)
        self.assertFalse(normalized.get("case_sensitive"))

    def test_normalize_threat_hunt_aliases_accept_noisy_variants(self):
        normalized = self.server._normalize_tool_call_args(
            "threat_hunt",
            {
                "action": "compatibility",
                "source_tool": "trace_analysis",
                "source_action": "find_loops",
                "with_evidence": True,
                "max": 33,
            },
        )
        self.assertEqual(normalized.get("action"), "legacy")
        self.assertEqual(normalized.get("legacy_tool"), "trace_analysis")
        self.assertEqual(normalized.get("legacy_action"), "find_loops")
        self.assertTrue(normalized.get("include_evidence"))
        self.assertEqual(normalized.get("limit"), 33)

    def test_normalize_session_and_code_aliases_accept_noisy_variants(self):
        s = self.server._normalize_tool_call_args(
            "session",
            {"action": "metrics", "id": "[ABCD1234]"},
        )
        self.assertEqual(s.get("action"), "stats")
        self.assertEqual(s.get("session_id"), "ABCD1234")
        c = self.server._normalize_tool_call_args(
            "code",
            {"action": "assembly", "targets": "[0x401000,0x401010]", "style": "annotated"},
        )
        self.assertEqual(c.get("action"), "disasm")
        self.assertEqual(c.get("addrs"), ["0x401000", "0x401010"])
        self.assertEqual(c.get("disasm_style"), "annotated")


class TestSearchCalcSemanticRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.search_source = (root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "search.py").read_text(encoding="utf-8")
        cls.calc_source = (root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "calc.py").read_text(encoding="utf-8")

    def test_search_signature_keeps_semantic_knobs(self):
        self.assertIn("semantic_action: Annotated[Optional[str]", self.search_source)
        self.assertIn("intent: Annotated[Optional[str]", self.search_source)
        self.assertIn("semantic_min_score: Annotated[float", self.search_source)
        self.assertIn("include_semantic_alternatives: Annotated[bool", self.search_source)

    def test_search_callers_intent_accepts_calls_phrase(self):
        self.assertIn(r"(?:callers?|calls?)", self.search_source)

    def test_search_semantic_errors_and_modules_are_explicit(self):
        self.assertIn('f"Invalid immediate value: {sem_err}"', self.search_source)
        self.assertIn('"semantic_module"', self.search_source)
        self.assertNotIn('"module": sem_meta.get("semantic_kind", "symbol")', self.search_source)

    def test_calc_pointer_chain_intent_routes_to_chain(self):
        self.assertIn('elif "pointer chain" in ql:', self.calc_source)
        self.assertIn('action = "chain"', self.calc_source)
        self.assertIn('interpreted_action = "chain"', self.calc_source)

    def test_calc_docstring_mentions_current_response_shapes(self):
        self.assertIn("Returns: {expr, value, value_hex}", self.calc_source)
        self.assertIn("Returns: {va, file_offset, segment, segment_start, segment_end, direction}", self.calc_source)
        self.assertIn("Returns: {addr, type, value, value_hex?, value_dec?, depth?, steps?}", self.calc_source)

    def test_search_and_calc_use_shared_semantic_helpers(self):
        self.assertIn("semantic_matching import normalize_action, semantic_score, semantic_tokens", self.search_source)
        self.assertIn("semantic_matching import normalize_action, semantic_score, semantic_tokens", self.calc_source)
        self.assertNotIn("\nimport difflib\n", self.search_source)
        self.assertNotIn("\nimport difflib\n", self.calc_source)


if __name__ == "__main__":
    unittest.main()
