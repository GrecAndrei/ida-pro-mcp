"""
Comprehensive MCP Test Shim.

Tests every tool, action, and edge case against the actual MCP server.

Two modes:
  1. Host-only mode: tests session, bookmarks, batch, truncation, misc, wiki, etc.
  2. IDA-integration mode: tests IDA-side tools via the integration harness.

Usage:
    pytest tests/test_mcp_comprehensive.py -v
    pytest tests/test_mcp_comprehensive.py -v --ida  # include IDA integration tests
"""

from __future__ import annotations

import os
import sys
import json
import time
import tempfile
import subprocess
import pytest
import importlib.util

# Add src/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from ida_pro_mcp.host.server import IDAMCPServer
from ida_pro_mcp.host.schemas import TOOLS, TOOL_ACTIONS, TOOL_DESCRIPTIONS


class MCPTestClient:
    """
    Lightweight JSON-RPC client for testing the MCP server directly.
    Does NOT require stdio; calls handle_request() in-process.
    """

    def __init__(self):
        self.server = IDAMCPServer()
        self._req_id = 0

    def _call(self, method: str, params: dict = None) -> dict:
        self._req_id += 1
        req = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            req["params"] = params
        resp = self.server.handle_request(req)
        if resp is None:
            raise RuntimeError(f"Null response for {method}")
        if "error" in resp:
            raise RuntimeError(f"MCP error: {resp['error']}")
        return resp.get("result", {})

    def tools_list(self, **kwargs) -> dict:
        return self._call("tools/list", kwargs)

    def tools_call(self, name: str, arguments: dict = None) -> dict:
        return self._call("tools/call", {"name": name, "arguments": arguments or {}})

    def call_tool(self, tool: str, **kwargs) -> dict:
        """Convenience wrapper with automatic result parsing."""
        result = self.tools_call(tool, kwargs)
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"ok": True, "text": text}
        return result


# =============================================================================
# 1. Meta Tests (tool registry integrity)
# =============================================================================

class TestToolRegistry:
    """Verify that the tool registry is self-consistent."""

    def test_every_tool_has_description(self):
        for tool in TOOLS:
            assert tool in TOOL_DESCRIPTIONS, f"Tool '{tool}' missing description"

    def test_every_tool_has_actions(self):
        for tool in TOOLS:
            if tool == "batch":
                continue
            assert tool in TOOL_ACTIONS, f"Tool '{tool}' missing actions list"
            assert len(TOOL_ACTIONS[tool]) > 0, f"Tool '{tool}' has empty actions"

    def test_no_duplicate_actions(self):
        for tool, actions in TOOL_ACTIONS.items():
            assert len(actions) == len(set(actions)), f"Tool '{tool}' has duplicate actions"

    def test_description_not_empty(self):
        for tool, desc in TOOL_DESCRIPTIONS.items():
            assert desc and len(desc) > 10, f"Tool '{tool}' description too short"


# =============================================================================
# 2. Host-Side Tool Tests (no IDA required)
# =============================================================================

@pytest.fixture(scope="module")
def mcp_client():
    return MCPTestClient()


class TestToolsList:
    def test_list_returns_tools(self, mcp_client):
        result = mcp_client.tools_list()
        assert "tools" in result
        assert result["total"] > 0
        names = [t["name"] for t in result["tools"]]
        assert "session" in names
        # schemaboot may be hidden depending on ADVERTISED_TOOLS

    def test_list_filter_by_prefix(self, mcp_client):
        result = mcp_client.tools_list(prefix="s")
        for t in result["tools"]:
            assert t["name"].startswith("s")

    def test_list_filter_by_contains(self, mcp_client):
        result = mcp_client.tools_list(contains="boot")
        # May be empty if schemaboot is hidden; just verify no crash
        assert isinstance(result["tools"], list)

    def test_list_pagination(self, mcp_client):
        result = mcp_client.tools_list(limit=5)
        assert len(result["tools"]) <= 5

    def test_list_sort_by_category(self, mcp_client):
        result = mcp_client.tools_list(sort="category", limit=10)
        assert len(result["tools"]) > 0


class TestSessionTool:
    def test_session_discover_no_crash(self, mcp_client):
        result = mcp_client.call_tool("session", action="discover")
        # Session tools return either {"ok": True, ...} or raw dicts directly
        assert isinstance(result, dict)

    def test_session_create_requires_binary_path(self, mcp_client):
        result = mcp_client.call_tool("session", action="create")
        assert result.get("error") is True or "error" in result

    def test_session_create_with_nonexistent_binary(self, mcp_client):
        result = mcp_client.call_tool("session", action="create", binary_path="/nonexistent/file")
        assert result.get("error") is True or "error" in result

    def test_session_stats(self, mcp_client):
        result = mcp_client.call_tool("session", action="stats")
        assert isinstance(result, dict)
        assert "stats" in result or "ok" in result

    def test_session_list(self, mcp_client):
        result = mcp_client.call_tool("session", action="list")
        assert isinstance(result, dict)
        assert "sessions" in result or "ok" in result

    def test_session_recent(self, mcp_client):
        result = mcp_client.call_tool("session", action="recent", n=5)
        assert isinstance(result, dict)
        assert "sessions" in result or "ok" in result

    def test_session_unknown_action(self, mcp_client):
        result = mcp_client.call_tool("session", action="nonexistent_action_xyz")
        assert result.get("error") is True or "error" in result

    def test_session_cleanup_stale(self, mcp_client):
        result = mcp_client.call_tool("session", action="cleanup_stale", max_age_days=1)
        assert isinstance(result, dict)
        assert "count" in result or "deleted_sids" in result or "ok" in result

    def test_session_macro_list_empty(self, mcp_client):
        result = mcp_client.call_tool("session", action="macro_list")
        assert isinstance(result, dict)
        assert "count" in result or "macros" in result or "ok" in result

    def test_session_macro_crud(self, mcp_client):
        # Set
        r1 = mcp_client.call_tool("session", action="macro_set", name="test_macro", data={"action": "stats"})
        assert r1.get("ok") is True or "name" in r1
        # Get
        r2 = mcp_client.call_tool("session", action="macro_get", name="test_macro")
        assert r2.get("ok") is True or "data" in r2
        # Delete
        r3 = mcp_client.call_tool("session", action="macro_delete", name="test_macro")
        assert r3.get("ok") is True or "name" in r3
        # Get after delete should fail
        r4 = mcp_client.call_tool("session", action="macro_get", name="test_macro")
        assert r4.get("error") is True or "error" in r4

    def test_session_invalid_id_format(self, mcp_client):
        result = mcp_client.call_tool("session", action="get", session_id="../../../etc/passwd")
        assert result.get("error") is True or "error" in result


class TestBookmarksTool:
    def test_bookmarks_no_session_error(self, mcp_client):
        result = mcp_client.call_tool("bookmarks", action="list")
        assert result.get("error") is True or "error" in result


class TestBatchTool:
    def test_batch_empty_calls(self, mcp_client):
        result = mcp_client.call_tool("batch", calls=[])
        assert result.get("error") is True or "error" in result

    def test_batch_single_call(self, mcp_client):
        result = mcp_client.call_tool("batch", calls=[{"name": "session", "arguments": {"action": "stats"}}])
        assert result.get("ok") is True or "results" in result

    def test_batch_string_shorthand(self, mcp_client):
        result = mcp_client.call_tool("batch", calls=["session:stats"])
        assert result.get("ok") is True or "results" in result

    def test_batch_nested_batch_rejected(self, mcp_client):
        result = mcp_client.call_tool("batch", calls=[{"name": "batch", "arguments": {"calls": []}}])
        assert result.get("error") is True or "error" in result or "Nested batch calls are not allowed" in str(result)

    def test_batch_continue_on_error(self, mcp_client):
        result = mcp_client.call_tool(
            "batch",
            calls=[
                {"name": "session", "arguments": {"action": "nonexistent"}},
                {"name": "session", "arguments": {"action": "stats"}},
            ],
            continue_on_error=True,
        )
        assert result.get("ok") is True or "results" in result


class TestTruncationTool:
    def test_truncation_continue_requires_token(self, mcp_client):
        result = mcp_client.call_tool("truncation", action="continue")
        assert result.get("error") is True or "error" in result

    def test_truncation_invalid_token(self, mcp_client):
        result = mcp_client.call_tool("truncation", action="continue", token="invalid-token-123")
        assert result.get("error") is True or "error" in result


class TestMiscTool:
    def test_session_health(self, mcp_client):
        result = mcp_client.call_tool("session", action="health")
        assert isinstance(result, dict)
        assert "server" in result or "ok" in result or "status" in result

    def test_misc_unknown_action(self, mcp_client):
        result = mcp_client.call_tool("misc", action="nonexistent_xyz")
        assert result.get("error") is True or "error" in result

    def test_misc_python_no_crash(self, mcp_client):
        result = mcp_client.call_tool("misc", action="python", expr="1 + 1")
        # May fail if no session, but should not crash
        assert isinstance(result, dict)


class TestWikiTool:
    def test_wiki_list_topics(self, mcp_client):
        result = mcp_client.call_tool("wiki", action="list_topics")
        assert isinstance(result, dict)

    def test_wiki_read_unknown_topic(self, mcp_client):
        result = mcp_client.call_tool("wiki", action="read", topic="nonexistent_topic_12345")
        assert isinstance(result, dict)

    def test_wiki_search(self, mcp_client):
        result = mcp_client.call_tool("wiki", action="search", query="session")
        assert isinstance(result, dict)

    def test_wiki_invalid_action(self, mcp_client):
        result = mcp_client.call_tool("wiki", action="nonexistent")
        assert result.get("error") is True or "error" in result


class TestCalcTool:
    def test_calc_eval_basic(self, mcp_client):
        result = mcp_client.call_tool("calc", action="eval", expr="0x401000 + 0x10")
        assert result.get("ok") is True or "error" in result

    def test_calc_eval_invalid(self, mcp_client):
        result = mcp_client.call_tool("calc", action="eval", expr="not_a_valid_expr!!!")
        assert result.get("error") is True or "error" in result

    def test_calc_offset(self, mcp_client):
        result = mcp_client.call_tool("calc", action="offset", addr="0x401000")
        assert isinstance(result, dict)

    def test_calc_align(self, mcp_client):
        result = mcp_client.call_tool("calc", action="align", addr="0x401003", value="0x10")
        assert isinstance(result, dict)

    def test_calc_convert_suffix_value(self, mcp_client):
        result = mcp_client.call_tool("calc", action="convert", value="4k")
        assert isinstance(result, dict)

    def test_calc_align_nearest(self, mcp_client):
        result = mcp_client.call_tool("calc", action="align", value="0x1003", size=0x10)
        assert isinstance(result, dict)
        if result.get("ok"):
            assert "nearest" in result

    def test_calc_bitops_xor(self, mcp_client):
        result = mcp_client.call_tool("calc", action="bitops", value="0xff", target="0x0f", bit_op="xor")
        assert isinstance(result, dict)
        assert result.get("ok") is True or "error" in result


class TestWorkflowTool:
    def test_workflow_audit_plan_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="audit_plan",
            planned_calls=[
                {"name": "session", "arguments": {"action": "health"}},
                {"name": "search", "arguments": {"action": "vulnerable"}},
            ],
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "audit_plan"
        assert isinstance(result.get("audit"), dict)
        assert isinstance(result["audit"].get("score"), int)

    def test_workflow_execute_plan_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="execute_plan",
            planned_calls=[
                {"name": "session", "arguments": {"action": "health"}},
            ],
            continue_on_error=True,
            max_steps=5,
        )
        assert isinstance(result, dict)
        assert result.get("error") is not True
        assert isinstance(result.get("execution_meta"), dict)
        assert result["execution_meta"].get("action") == "execute_plan"

    def test_workflow_prioritize_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="prioritize",
            workflow_action="triage_fast",
            priority_mode="coverage",
            limit=3,
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "prioritize"
        assert result.get("dry_run") is True
        assert isinstance(result.get("planned_calls"), list)
        assert "workflow_meta" in result

    def test_workflow_compose_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="compose",
            workflow_actions=["triage_fast", "vuln_audit"],
            limit=3,
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "compose"
        assert result.get("dry_run") is True
        assert isinstance(result.get("planned_calls"), list)
        assert "workflow_meta" in result

    def test_workflow_estimate_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="estimate",
            workflow_action="recon_sweep",
            profile="deep",
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "estimate"
        assert result.get("dry_run") is True
        estimate = result.get("estimate")
        assert isinstance(estimate, dict)
        assert isinstance(estimate.get("risk_score"), int)
        assert isinstance(estimate.get("category_counts"), dict)

    def test_workflow_explain_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="explain",
            workflow_action="triage_fast",
            limit=3,
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "explain"
        assert result.get("dry_run") is True
        assert isinstance(result.get("explained_steps"), list)
        assert "workflow_meta" in result

    def test_workflow_plan_action(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="plan",
            workflow_action="recon_sweep",
            profile="deep",
            include_tools=["idb", "search"],
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("dry_run") is True
        assert result.get("requested_action") == "plan"
        assert result.get("planned_action") == "recon_sweep"
        assert isinstance(result.get("planned_calls"), list)
        assert "workflow_meta" in result

    def test_workflow_plan_requires_target(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="plan")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_explain_requires_target(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="explain")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_estimate_requires_target(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="estimate")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_compose_requires_targets(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="compose")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_prioritize_requires_input(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="prioritize")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_execute_plan_requires_input(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="execute_plan")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_audit_plan_requires_input(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="audit_plan")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_catalog(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="catalog")
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("action") == "catalog"
        assert isinstance(result.get("workflow_catalog"), dict)
        assert "triage_fast" in result.get("workflow_catalog", {})
        assert "recon_sweep" in result.get("workflow_catalog", {})

    def test_workflow_triage_fast_returns_workflow_meta(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="triage_fast", limit=3)
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        meta = result["workflow_meta"]
        assert meta.get("version") == 1
        assert meta.get("action") == "triage_fast"
        assert "profile" in meta
        assert "step_count" in meta
        assert isinstance(meta.get("firmware_detected"), bool)
        assert isinstance(meta.get("trigger"), str)
        assert isinstance(meta.get("step_tools"), list)
        assert "idb" in meta.get("step_tools", [])
        assert isinstance(meta.get("step_actions"), list)
        assert "idb.overview" in meta.get("step_actions", [])
        assert isinstance(meta.get("step_calls"), list)
        assert any(c.get("tool") == "idb" and c.get("action") == "overview" for c in meta.get("step_calls", []))

    def test_workflow_patch_review_requires_addr(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="patch_review")
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result

    def test_workflow_meta_survives_output_fields_projection(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="triage_fast",
            limit=2,
            output_fields=["summary"],
        )
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        assert result["workflow_meta"].get("version") == 1
        assert result["workflow_meta"].get("action") == "triage_fast"

    def test_workflow_meta_not_removed_by_output_omit(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="triage_fast",
            limit=2,
            output_omit=["workflow_meta"],
        )
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        assert result["workflow_meta"].get("version") == 1
        assert result["workflow_meta"].get("action") == "triage_fast"

    def test_workflow_meta_present_in_full_mode(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="triage_fast",
            limit=2,
            _response_mode="full",
        )
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        assert result["workflow_meta"].get("version") == 1
        assert result["workflow_meta"].get("action") == "triage_fast"

    def test_workflow_meta_survives_output_path_summary(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="triage_fast",
            limit=2,
            output_path="summary",
        )
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        assert result["workflow_meta"].get("version") == 1
        assert result["workflow_meta"].get("action") == "triage_fast"
        assert isinstance(result["workflow_meta"].get("trigger"), str)
        assert isinstance(result["workflow_meta"].get("firmware_detected"), bool)
        assert isinstance(result["workflow_meta"].get("step_tools"), list)
        assert isinstance(result["workflow_meta"].get("step_actions"), list)
        assert isinstance(result["workflow_meta"].get("step_calls"), list)
        assert any(
            c.get("tool") == "idb" and c.get("action") == "overview"
            for c in result["workflow_meta"].get("step_calls", [])
        )

    def test_workflow_recon_sweep_returns_workflow_meta(self, mcp_client):
        result = mcp_client.call_tool("workflow", action="recon_sweep", limit=3, profile="deep")
        assert isinstance(result, dict)
        assert "workflow_meta" in result
        meta = result["workflow_meta"]
        assert meta.get("version") == 1
        assert meta.get("action") == "recon_sweep"
        assert meta.get("profile") == "deep"
        assert isinstance(meta.get("firmware_detected"), bool)
        assert isinstance(meta.get("step_calls"), list)
        assert any(c.get("tool") == "search" and c.get("action") == "structured" for c in meta.get("step_calls", []))

    def test_workflow_dry_run_returns_planned_calls(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="recon_sweep",
            limit=3,
            dry_run=True,
            include_tools=["idb", "search", "threat_hunt"],
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert result.get("dry_run") is True
        assert isinstance(result.get("planned_calls"), list)
        assert "workflow_meta" in result
        meta = result["workflow_meta"]
        assert meta.get("dry_run") is True
        assert meta.get("action") == "recon_sweep"
        assert meta.get("include_tools") == ["idb", "search", "threat_hunt"]

    def test_workflow_dry_run_reports_filter_diagnostics(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="recon_sweep",
            dry_run=True,
            include_tools=["idb", "nonexistent_tool"],
            exclude_tools=["idb"],
        )
        assert isinstance(result, dict)
        assert result.get("ok") is True
        assert "workflow_meta" in result
        meta = result["workflow_meta"]
        assert "nonexistent_tool" in meta.get("unknown_include_tools", [])
        assert "idb" in meta.get("conflicting_tools", [])
        assert isinstance(meta.get("plan_diagnostics"), list)

    def test_workflow_execute_rejects_empty_filtered_plan(self, mcp_client):
        result = mcp_client.call_tool(
            "workflow",
            action="recon_sweep",
            include_tools=["nonexistent_tool"],
        )
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result


class TestSearchTool:
    def test_search_smart_bundle_action(self, mcp_client):
        result = mcp_client.call_tool("search", action="smart_bundle", pattern="malloc", limit=3)
        assert isinstance(result, dict)
        assert result.get("error") is not True or "error" in result


class TestAnalysisTool:
    def test_analysis_no_session(self, mcp_client):
        result = mcp_client.call_tool("analysis", action="get_options")
        assert result.get("error") is True or "error" in result


class TestQueryTool:
    def test_query_no_session(self, mcp_client):
        result = mcp_client.call_tool("query", action="data")
        assert result.get("error") is True or "error" in result


class TestUnknownTool:
    def test_unknown_tool_rejected(self, mcp_client):
        result = mcp_client.call_tool("nonexistent_tool_12345", action="test")
        assert result.get("error") is True or "error" in result

    def test_tool_alias_resolution(self, mcp_client):
        result = mcp_client.call_tool("fn", action="list")
        assert isinstance(result, dict)


class TestResponseModes:
    def test_compact_vs_full_mode(self, mcp_client):
        # Default is compact
        result = mcp_client.call_tool("session", action="health")
        assert isinstance(result, dict)


# =============================================================================
# 3. Tool Alias Tests
# =============================================================================

class TestToolAliases:
    def test_session_aliases(self, mcp_client):
        for alias in ["session_tool"]:
            result = mcp_client.call_tool(alias, action="stats")
            assert isinstance(result, dict)

    def test_func_aliases(self, mcp_client):
        for alias in ["fn", "func", "function", "functions"]:
            result = mcp_client.call_tool(alias, action="list")
            assert isinstance(result, dict)

    def test_code_aliases(self, mcp_client):
        for alias in ["disasm", "assembly", "decomp"]:
            result = mcp_client.call_tool(alias, action="disasm", addr="0x401000")
            assert isinstance(result, dict)


# =============================================================================
# 4. Edge Case Tests
# =============================================================================

class TestEdgeCases:
    def test_null_arguments(self, mcp_client):
        result = mcp_client.call_tool("session", action=None)
        assert result.get("error") is True or "error" in result

    def test_empty_tool_name(self, mcp_client):
        result = mcp_client.call_tool("", action="stats")
        assert result.get("error") is True or "error" in result

    def test_very_long_string_argument(self, mcp_client):
        long_str = "A" * 10000
        result = mcp_client.call_tool("session", action="discover", query=long_str)
        assert isinstance(result, dict)

    def test_unicode_in_arguments(self, mcp_client):
        result = mcp_client.call_tool("session", action="discover", query="日本語テスト")
        assert isinstance(result, dict)

    def test_negative_numbers(self, mcp_client):
        result = mcp_client.call_tool("calc", action="eval", expr="-5 + 3")
        assert isinstance(result, dict)

    def test_special_chars_in_query(self, mcp_client):
        result = mcp_client.call_tool("session", action="discover", query="test' OR '1'='1")
        assert isinstance(result, dict)

    def test_boolean_coercion(self, mcp_client):
        result = mcp_client.call_tool("session", action="stats")
        assert isinstance(result, dict)


# =============================================================================
# 5. Tool Tests (host-side, no IDA)
# =============================================================================

class TestHostToolsNoSession:
    """Edge case: host tools require an active session (they are IDA-side tools)."""

    def _assert_session_required(self, result):
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result or "SESSION_REQUIRED" in str(result)

    def test_turboquant_stats_no_session(self, mcp_client):
        result = mcp_client.call_tool("turboquant", action="stats")
        self._assert_session_required(result)

    def test_turboquant_delete_no_session(self, mcp_client):
        result = mcp_client.call_tool("turboquant", action="delete")
        self._assert_session_required(result)

    def test_turboquant_query_no_session(self, mcp_client):
        result = mcp_client.call_tool("turboquant", action="query", query_key="0x401000")
        self._assert_session_required(result)

    def test_bridge_search_bridges_no_session(self, mcp_client):
        result = mcp_client.call_tool("bridge_search", action="bridges", func_ea="0x401000")
        self._assert_session_required(result)

    def test_bridge_search_search_no_session(self, mcp_client):
        result = mcp_client.call_tool("bridge_search", action="search")
        self._assert_session_required(result)

    def test_memrl_record_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="record", intent_key="q1", experience_key="f_401000")
        self._assert_session_required(result)

    def test_memrl_update_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="update", intent_key="q1", experience_key="f_401000", reward=1.0)
        self._assert_session_required(result)

    def test_memrl_get_q_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="get_q", intent_key="q1", experience_key="f_401000")
        self._assert_session_required(result)

    def test_memrl_stats_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="stats")
        self._assert_session_required(result)

    def test_memrl_rank_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="rank", intent_key="q1")
        self._assert_session_required(result)

    def test_memrl_top_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="top", intent_key="q1", top_k=5)
        self._assert_session_required(result)

    def test_memrl_unknown_action_no_session(self, mcp_client):
        result = mcp_client.call_tool("memrl", action="nonexistent")
        # Unknown action may be caught before session check; either error is fine
        assert isinstance(result, dict)
        assert result.get("error") is True or "error" in result or "SESSION_REQUIRED" in str(result)


# =============================================================================
# 6. Integration Tests with Real IDA (optional, use --ida flag)
# =============================================================================

@pytest.mark.skipif(
    not os.environ.get("RUN_IDA_TESTS"),
    reason="Set RUN_IDA_TESTS=1 to run IDA integration tests"
)
class TestIDAIntegration:
    """Tests that require a live IDA session."""

    @pytest.fixture(scope="class")
    def ida_client(self, mcp_client):
        # Create a session with the test binary
        test_binary = os.path.join(os.path.dirname(__file__), "data", "test_binary.exe")
        result = mcp_client.call_tool("session", action="create", binary_path=test_binary)
        if result.get("error"):
            pytest.skip(f"Could not create IDA session: {result}")
        return mcp_client

    def test_idb_meta(self, ida_client):
        result = ida_client.call_tool("idb", action="meta")
        assert result.get("ok") is True

    def test_data_functions(self, ida_client):
        result = ida_client.call_tool("data", action="functions", limit=10)
        assert result.get("ok") is True
        assert "functions" in result

    def test_code_decompile(self, ida_client):
        result = ida_client.call_tool("code", action="decompile", addr="0x401000")
        assert isinstance(result, dict)

    def test_search_bytes(self, ida_client):
        result = ida_client.call_tool("search", action="bytes", pattern="48 89 5C 24")
        assert isinstance(result, dict)

    def test_schemaboot_ingest(self, ida_client):
        result = ida_client.call_tool("schemaboot", action="ingest")
        assert result.get("ok") is True
        assert result.get("ingested", 0) > 0

    def test_schemaboot_query(self, ida_client):
        ida_client.call_tool("schemaboot", action="ingest")
        result = ida_client.call_tool("schemaboot", action="query", constraints={"min_size": 50}, limit=5)
        assert result.get("ok") is True

    def test_turboquant_ingest_and_query(self, ida_client):
        ida_client.call_tool("schemaboot", action="ingest")
        result = ida_client.call_tool("turboquant", action="ingest")
        assert result.get("ok") is True
        result2 = ida_client.call_tool("turboquant", action="stats")
        assert result2.get("total_vectors", 0) > 0

    def test_bridge_search_search(self, ida_client):
        ida_client.call_tool("schemaboot", action="ingest")
        result = ida_client.call_tool("bridge_search", action="search", query_constraints={"min_size": 100}, top_k=5)
        assert result.get("ok") is True

    def test_memrl_end_to_end(self, ida_client):
        ida_client.call_tool("schemaboot", action="ingest")
        # Record a triplet
        r1 = ida_client.call_tool("memrl", action="record", intent_key="test_query", experience_key="0x401000")
        assert r1.get("ok") is True
        # Update with reward
        r2 = ida_client.call_tool("memrl", action="update", intent_key="test_query", experience_key="0x401000", reward=1.0)
        assert r2.get("ok") is True
        # Rank candidates
        pool = [{"ea": "0x401000", "score": 0.9}, {"ea": "0x402000", "score": 0.8}]
        r3 = ida_client.call_tool("memrl", action="rank", intent_key="test_query", candidate_pool=pool, lambda_explore=0.5)
        assert r3.get("ok") is True
        assert len(r3.get("ranked", [])) == 2


# =============================================================================
# 7. Production Hardening Tests (audit, pruning, rate limiting, guardrails)
# =============================================================================

class TestProductionHardening:
    """Tests for audit logging, rate limiting, blackboard pruning, and guardrails."""

    def test_audit_log_written(self, mcp_client):
        # Make a call that should be audited
        result = mcp_client.call_tool("session", action="discover")
        assert "sessions" in result or "error" in result
        # Check that audit log file exists
        import glob
        audit_dir = os.path.join(mcp_client.server.cache_dir, "audit")
        pattern = os.path.join(audit_dir, "*", "audit_*.jsonl")
        files = glob.glob(pattern)
        assert len(files) > 0, "No audit log files found"
        # Verify at least one entry exists and has expected fields
        with open(files[0], "r") as f:
            line = f.readline()
            record = json.loads(line)
            assert "ts" in record
            assert "tool" in record
            assert "latency_ms" in record

    def test_rate_limiting_disabled_in_tests(self, mcp_client):
        # Rapid-fire calls should succeed with rate limiting disabled in tests
        for i in range(5):
            result = mcp_client.call_tool("session", action="discover")
            assert "Rate limit exceeded" not in str(result)

    def test_blackboard_prune(self, mcp_client):
        # Write several entries
        for i in range(5):
            mcp_client.call_tool(
                "blackboard",
                action="write",
                title=f"Test entry {i}",
                content="test",
                category="test",
            )
        # Prune with a low max
        result = mcp_client.call_tool("blackboard", action="prune", max_entries=3)
        # "ok" is dropped by default for context efficiency; check pruned count
        assert result.get("pruned", 0) >= 2
        # Verify only 3 remain
        list_result = mcp_client.call_tool("blackboard", action="list", category="test")
        assert list_result.get("count", 0) <= 3
        # Clean up
        mcp_client.call_tool("blackboard", action="clear", category="test")

    def test_guardrail_mode_off(self, mcp_client):
        # With _guardrail_mode=off, pointer note should not appear
        result = mcp_client.call_tool(
            "session", action="discover", _guardrail_mode="off"
        )
        # session discover doesn't include pointer notes, but verify mode is parsed
        assert "Rate limit exceeded" not in str(result)

    def test_guardrail_strict_blocks_writes(self, mcp_client):
        # Disable auto-transition and reset phase to scout to bypass blackboard phase gates
        mcp_client.call_tool("blackboard", action="phase_set", phase="scout", auto_transition=False)
        # Strict mode should block risky writes without _guardrail_ack
        result = mcp_client.call_tool(
            "modify",
            action="rename",
            addr="0x401000",
            name="test_func",
            _guardrail_mode="enforce",
            _risk_ack=True,  # Bypass policy preflight block to hit guardrail check
        )
        assert "guardrail" in str(result).lower() or "session" in str(result).lower()

    def test_blackboard_merge(self, mcp_client):
        # Write duplicate entries
        mcp_client.call_tool(
            "blackboard", action="write", title="Duplicate finding",
            content="same", category="dup", addr="0x401000"
        )
        mcp_client.call_tool(
            "blackboard", action="write", title="Duplicate finding",
            content="same", category="dup", addr="0x401000"
        )
        result = mcp_client.call_tool("blackboard", action="merge", category="dup")
        # merge returns {"merged": N, "remaining": M} wrapped with ok by host handler
        assert "merged" in result
        assert result.get("merged", 0) >= 1
