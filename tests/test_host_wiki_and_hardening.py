#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
import tempfile
import os
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

    def test_tools_call_enforces_strict_blackboard_policy_then_allows_after_refresh(self):
        set_policy = self.server._execute_tool(
            "blackboard",
            {
                "action": "policy_set",
                "strict_mode": True,
                "max_staleness_calls": 4,
                "require_working_set": True,
                "require_decision_or_write": True,
                "enforce_phases": ["scout", "prove", "commit", "finalize"],
            },
        )
        self.assertTrue(set_policy.get("ok"))

        blocked_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "wiki", "arguments": {"action": "list_topics"}},
        }
        blocked_resp = self.server.handle_request(blocked_req)
        blocked_payload = json.loads(blocked_resp["result"]["content"][0]["text"])
        self.assertTrue(blocked_payload.get("error"))
        self.assertIn(
            "Strict blackboard policy gate failed before tool execution",
            str(blocked_payload.get("message") or ""),
        )

        self.server._execute_tool("blackboard", {"action": "working_set"})
        self.server._execute_tool(
            "blackboard",
            {"action": "write", "title": "fresh intent", "category": "wm_now"},
        )

        allow_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "wiki", "arguments": {"action": "list_topics"}},
        }
        allow_resp = self.server.handle_request(allow_req)
        allow_payload = json.loads(allow_resp["result"]["content"][0]["text"])
        self.assertTrue(allow_payload.get("ok"))
        self.assertIn("categories", allow_payload)


class TestHostHardening(unittest.TestCase):
    def setUp(self):
        self._orig_policy_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        os.environ["IDA_MCP_POLICY_MODE"] = "permissive"
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
        self.assertNotIn("plugin_run", misc_actions)
        self.assertNotIn("health", misc_actions)

        session_tool = next(t for t in tools_payload if t["name"] == "session")
        session_actions = session_tool["inputSchema"]["properties"]["action"]["enum"]
        self.assertIn("health", session_actions)

        analysis_tool = next(t for t in tools_payload if t["name"] == "analysis")
        analysis_actions = analysis_tool["inputSchema"]["properties"]["action"]["enum"]
        self.assertIn("plugin_run", analysis_actions)

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

    def test_tools_list_includes_getting_started_bootstrap_hints(self):
        res = self.server.handle_request({"jsonrpc": "2.0", "id": 120, "method": "tools/list"})
        starter = res["result"].get("getting_started", {})
        self.assertIn("first_calls", starter)
        first_calls = starter["first_calls"]
        self.assertIn("llm_helpers(action='bootstrap')", first_calls)
        self.assertIn("llm_helpers(action='cheatsheet')", first_calls)

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

    def test_session_health_requires_no_session(self):
        res = self.server._execute_tool("session", {"action": "health"})
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

    def test_llm_helpers_quickstart_alias_maps_to_bootstrap(self):
        normalized = self.server._normalize_tool_call_args(
            "llm_helpers", {"action": "quickstart"}
        )
        self.assertEqual(normalized.get("action"), "bootstrap")

    def test_session_create_infers_raw_architecture_profile(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write((0x20002000).to_bytes(4, "little"))
            tf.write((0x08000101).to_bytes(4, "little"))
            tf.write(b"\x00" * 64)
            path = tf.name
        try:
            res = self.server._execute_tool(
                "session", {"action": "create", "binary_path": path}
            )
            self.assertTrue(res.get("ok"), res)
            arch_profile = res.get("architecture_profile", {})
            inferred = arch_profile.get("inferred_profile", {})
            # Raw profile inference should populate processor defaults.
            self.assertEqual(inferred.get("processor"), "arm")
            self.assertEqual(inferred.get("bitness"), 32)
            self.assertTrue(arch_profile.get("inference_applied"))
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def test_session_create_ambiguous_raw_applies_top_candidate(self):
        # Raw binary with weak x86 signal: new policy always applies top ranked candidate
        # rather than leaving IDA's metapc/64 default in place.
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write((b"\xe8" + (b"\x00" * 63)) * 8)
            path = tf.name
        try:
            res = self.server._execute_tool(
                "session", {"action": "create", "binary_path": path}
            )
            self.assertTrue(res.get("ok"), res)
            arch_profile = res.get("architecture_profile", {})
            inferred = arch_profile.get("inferred_profile", {})
            opts = (res.get("session") or {}).get("analysis_options", {}) or {}
            candidates = inferred.get("candidates", [])
            if candidates:
                # Top candidate must be applied to analysis_options for raw binaries.
                top = candidates[0] if isinstance(candidates[0], dict) else {}
                if top.get("processor") and inferred.get("file_kind") == "raw":
                    self.assertIn("processor", opts)
                    self.assertTrue(arch_profile.get("inference_applied"))
            recs = res.get("architecture_recommendations", [])
            self.assertGreaterEqual(len(recs), 1)
            self.assertEqual(recs[0].get("tool"), "analysis")
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

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
        # `funcs` no longer owns a `list` action (it lives on `data`).
        # `segments` still has a `list` action and is the canonical fit for
        # this check.
        action, err = self.server._wrapper_source_action("segments", {"action": "head"}, "head")
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
        missing = sorted(t for t in TOOLS if t not in covered and t not in {"plugins", "xfer_analysis", "xref_analysis"})
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

    def tearDown(self):
        if self._orig_policy_mode is None:
            os.environ.pop("IDA_MCP_POLICY_MODE", None)
        else:
            os.environ["IDA_MCP_POLICY_MODE"] = self._orig_policy_mode


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

    def test_llm_address_calculation_injected_for_hex_addresses(self):
        opts = self.server._default_response_options()
        session_id = "test_session_id"
        self.server.session_runtimes = {
            session_id: {"imagebase": 0x140000000}
        }
        class DummySession:
            session_id = "test_session_id"
            analysis_options = {}
            idb_path = "dummy.idb"
        self.server.current_session = DummySession()

        payload = {"ok": True, "address": "0x140001080"}
        out = self.server._prepare_response_payload(
            payload, opts, tool_name="session", call_args={"action": "status"}
        )
        self.assertNotIn("llm_pointer_note", out)
        self.assertIn("llm_address_calculation", out)
        calc = out["llm_address_calculation"]
        self.assertIn("0x140001080", calc)
        self.assertEqual(calc["0x140001080"]["decimal"], 0x140001080)
        self.assertEqual(calc["0x140001080"]["offset"], 0x1080)
        self.assertEqual(calc["0x140001080"]["relative_to_imagebase"], "imagebase + 0x1080")
        self.assertEqual(calc["0x140001080"]["alignment"]["aligned_4"], True)

    def test_execution_directive_injected_for_required_mcp_call(self):
        opts = self.server._default_response_options()
        payload = {
            "must_call_before_answer": True,
            "required_followup_call": {"tool": "code", "action": "callers", "addr": "0x401000"},
        }
        out = self.server._prepare_response_payload(payload, opts, tool_name="session", call_args={"action": "status"})
        self.assertIn("llm_execution_directive", out)
        self.assertIn("MCP_REQUIRED_CALL", out["llm_execution_directive"])
        self.assertIn("code.callers", out["llm_execution_directive"])

    def test_execution_directive_recommended_when_only_followup_call_present(self):
        directive = self.server._build_llm_execution_directive(
            {"required_followup_call": {"tool": "code", "action": "callees", "addr": "0x401020"}}
        )
        self.assertIsNotNone(directive)
        self.assertIn("MCP_RECOMMENDED_CALL", directive)
        self.assertIn("code.callees", directive)

    def test_response_injects_blackboard_required_call_when_strict_policy_is_stale(self):
        self.server._handle_blackboard(
            {
                "action": "policy_set",
                "strict_mode": True,
                "max_staleness_calls": 4,
                "require_working_set": True,
                "require_decision_or_write": True,
            }
        )
        opts = self.server._default_response_options()
        out = self.server._prepare_response_payload(
            {"ok": True, "value": "ready"},
            opts,
            tool_name="session",
            call_args={"action": "status"},
        )
        self.assertIn("must_call_before_answer", out)
        self.assertTrue(out["must_call_before_answer"])
        self.assertEqual(out.get("required_followup_call", {}).get("tool"), "blackboard")
        self.assertIn(out.get("required_followup_call", {}).get("action"), {"working_set", "decision_card"})
        self.assertIn("llm_execution_directive", out)
        self.assertIn("MCP_REQUIRED_CALL", out["llm_execution_directive"])

    def test_response_injects_phase_followup_in_prove_phase(self):
        self.server._handle_blackboard({"action": "phase_set", "phase": "prove"})
        opts = self.server._default_response_options()
        out = self.server._prepare_response_payload(
            {"ok": True, "value": "ready"},
            opts,
            tool_name="session",
            call_args={"action": "status"},
        )
        self.assertTrue(out.get("must_call_before_answer"))
        req = out.get("required_followup_call", {})
        self.assertEqual(req.get("tool"), "blackboard")
        self.assertEqual(req.get("action"), "decision_card")
        gate = out.get("blackboard_phase_gate", {})
        self.assertEqual(gate.get("phase"), "prove")

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
        fw = self.server._normalize_tool_call_args(
            "session",
            {"action": "create", "binary_path": "fw.bin", "load_base": "0x120000"},
        )
        self.assertEqual(fw.get("baseaddr"), 0x120000)
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
        search_pkg = root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "search"
        if search_pkg.is_dir():
            parts = []
            for f in sorted(search_pkg.glob("*.py")):
                parts.append(f.read_text(encoding="utf-8"))
            cls.search_source = "\n".join(parts)
        else:
            cls.search_source = (root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "search.py").read_text(encoding="utf-8")
        cls.calc_source = (root / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "calc.py").read_text(encoding="utf-8")
        cls.stdio_source = (root / "ida_mcp_stdio.py").read_text(encoding="utf-8")
        cls.schemas_source = (root / "src" / "ida_pro_mcp" / "host" / "schemas.py").read_text(encoding="utf-8")
        cls.server_source = (root / "src" / "ida_pro_mcp" / "host" / "server.py").read_text(encoding="utf-8")

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

    def test_search_exposes_semantic_instruction_actions(self):
        self.assertIn('"mnemonic"', self.search_source)
        self.assertIn('"instruction"', self.search_source)
        self.assertIn('elif action == "mnemonic":', self.search_source)
        self.assertIn('elif action == "instruction":', self.search_source)

    def test_search_semantic_ranking_is_bounded(self):
        self.assertIn("ranked_heap = []", self.search_source)
        self.assertIn("_FIND_INSTRUCTION_LIMIT_MULTIPLIER", self.search_source)
        self.assertIn("heapq.heapreplace", self.search_source)

    def test_execute_tool_legacy_bridge_does_not_capture_search(self):
        for line in self.server_source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotIn("legacy_threat_tools = {", stripped)


    def test_decompilation_tools_expose_advanced_action_sets(self):
        for action_name in ("semantic_decompile", "decomp_dataflow"):
            self.assertIn(f'"{action_name}"', self.schemas_source)
        for action_name in ("dominance_map", "var_dependency_graph"):
            self.assertIn(f'"{action_name}"', self.schemas_source)
        self.assertIn('"def_use_graph"', self.schemas_source)
class TestGadgetSemanticIndex(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="gadget-semantic-test-")
        self.server = IDAMCPServer()
        self.server.session_mgr = SessionManager(self.tmpdir)
        binary_path = os.path.join(self.tmpdir, "sample.bin")
        with open(binary_path, "wb") as f:
            f.write(b"\x90" * 16)
        self.session = self.server.session_mgr.create_session(binary_path=binary_path)
        Path(self.session.idb_path).write_bytes(b"")
        self.server.current_session = self.session

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_semantic_find_builds_index_and_returns_ranked_matches(self):
        def fake_call_tool(tool_name, idb_path, **kwargs):
            self.assertEqual(tool_name, "gadgets")
            action = kwargs.get("action")
            if action == "rop":
                return {
                    "ok": True,
                    "action": "rop",
                    "gadgets": [
                        {
                            "addr": "0x401000",
                            "insns": 2,
                            "gadget": "pop rax ; ret",
                        }
                    ],
                }
            if action == "stack_pivot":
                return {
                    "ok": True,
                    "action": "stack_pivot",
                    "gadgets": [
                        {
                            "addr": "0x402000",
                            "insns": 2,
                            "gadget": "xchg rsp, rax ; ret",
                        }
                    ],
                }
            return {"ok": True, "action": action, "gadgets": []}

        self.server.call_tool = fake_call_tool
        res = self.server._execute_tool(
            "gadgets",
            {
                "action": "semantic_find",
                "query": "xchg rsp",
                "source_actions": ["rop", "stack_pivot"],
                "source_limit": 20,
                "_risk_ack": True,
            },
        )
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("action"), "semantic_find")
        self.assertGreaterEqual(res.get("count", 0), 1)
        self.assertEqual(res["matches"][0]["source_action"], "stack_pivot")
        self.assertIn("index_refresh", res)
        self.assertTrue(os.path.exists(res["index"]["db_path"]))

    def test_semantic_find_reuses_existing_index_without_remote_calls(self):
        calls = {"count": 0}

        def fake_call_tool(tool_name, idb_path, **kwargs):
            calls["count"] += 1
            action = kwargs.get("action")
            return {
                "ok": True,
                "action": action,
                "gadgets": [
                    {"addr": "0x500000", "insns": 2, "gadget": "mov rax, rbx ; ret"}
                ],
            }

        self.server.call_tool = fake_call_tool
        first = self.server._execute_tool(
            "gadgets",
            {"action": "semantic_find", "query": "move register", "source_actions": ["rop"], "_risk_ack": True},
        )
        self.assertTrue(first.get("ok"))
        self.assertEqual(calls["count"], 1)

        def fail_call_tool(*_args, **_kwargs):
            raise AssertionError("semantic_find unexpectedly rebuilt the cache")

        self.server.call_tool = fail_call_tool
        second = self.server._execute_tool(
            "gadgets",
            {"action": "semantic_find", "query": "move register", "source_actions": ["rop"], "_risk_ack": True},
        )
        self.assertTrue(second.get("ok"))
        self.assertNotIn("index_refresh", second)

    def test_semantic_find_rejects_invalid_source_actions(self):
        res = self.server._execute_tool(
            "gadgets",
            {
                "action": "semantic_find",
                "query": "xchg",
                "source_actions": ["not_real_action"],
            },
        )
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), MCPError.INVALID_ARGS)


if __name__ == "__main__":
    unittest.main()
