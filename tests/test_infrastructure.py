"""
Tests for new infrastructure features:
- MCP Resources (resources/list, resources/read)
- Universal output filtering (output_grep, head, tail, skip, path, pluck)
- Batch macro DSL mode
- Search query_lang action
- Blackboard and filter tools
"""

import json
import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.host.schemas import TOOLS, TOOL_ACTIONS
from ida_pro_mcp.host.server import IDAMCPServer
from ida_pro_mcp.host.resources import list_resources, ResourceResolver


# =============================================================================
# MCP Resources
# =============================================================================

class TestMCPResources:
    def test_resources_list(self):
        resources = list_resources()
        assert isinstance(resources, list)
        assert len(resources) > 0
        uris = [r["uri"] for r in resources]
        assert "ida://meta" in uris
        assert "ida://functions" in uris
        assert "ida://strings" in uris

    def test_resources_list_via_server(self):
        server = IDAMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {},
        })
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert "result" in resp
        assert "resources" in resp["result"]
        assert len(resp["result"]["resources"]) > 0

    def test_resources_read_not_found(self):
        server = IDAMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "ida://nonexistent"},
        })
        assert "error" in resp
        assert "not found" in resp["error"]["message"].lower() or "unknown" in resp["error"]["message"].lower()

    def test_initialize_advertises_resources(self):
        server = IDAMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })
        caps = resp["result"]["capabilities"]
        assert "resources" in caps
        assert "tools" in caps


# =============================================================================
# Universal Output Filtering
# =============================================================================

class TestUniversalOutputFiltering:
    def test_output_grep(self):
        server = IDAMCPServer()
        payload = ["hello world", "foo bar", "hello again", "baz qux"]
        opts = server._default_response_options()
        opts["output_grep"] = "hello"
        result = server._apply_output_filters(payload, opts)
        assert result == ["hello world", "hello again"]

    def test_output_head(self):
        server = IDAMCPServer()
        payload = [1, 2, 3, 4, 5]
        opts = server._default_response_options()
        opts["output_head"] = 3
        result = server._apply_output_filters(payload, opts)
        assert result == [1, 2, 3]

    def test_output_tail(self):
        server = IDAMCPServer()
        payload = [1, 2, 3, 4, 5]
        opts = server._default_response_options()
        opts["output_tail"] = 2
        result = server._apply_output_filters(payload, opts)
        assert result == [4, 5]

    def test_output_skip(self):
        server = IDAMCPServer()
        payload = [1, 2, 3, 4, 5]
        opts = server._default_response_options()
        opts["output_skip"] = 2
        result = server._apply_output_filters(payload, opts)
        assert result == [3, 4, 5]

    def test_output_path(self):
        server = IDAMCPServer()
        payload = {"functions": [{"name": "main"}, {"name": "foo"}]}
        opts = server._default_response_options()
        opts["output_path"] = "functions.0.name"
        result = server._apply_output_filters(payload, opts)
        assert result == "main"

    def test_output_pluck(self):
        server = IDAMCPServer()
        payload = [{"name": "a", "size": 10}, {"name": "b", "size": 20}]
        opts = server._default_response_options()
        opts["output_pluck"] = "name"
        result = server._apply_output_filters(payload, opts)
        assert result == ["a", "b"]

    def test_combined_filters(self):
        server = IDAMCPServer()
        payload = [{"name": "main", "size": 100}, {"name": "foo", "size": 50}, {"name": "bar", "size": 200}]
        opts = server._default_response_options()
        opts["output_grep"] = "a"
        opts["output_head"] = 1
        opts["output_pluck"] = "name"
        result = server._apply_output_filters(payload, opts)
        # grep "a" matches "main" and "bar", head(1) gives "main", pluck gives "main"
        assert result == ["main"]

    def test_filter_params_stripped_from_args(self):
        server = IDAMCPServer()
        args = {
            "action": "functions",
            "output_grep": "main",
            "output_head": 5,
        }
        cleaned, opts = server._extract_response_options(args)
        assert "output_grep" not in cleaned
        assert "output_head" not in cleaned
        assert opts["output_grep"] == "main"
        assert opts["output_head"] == 5


# =============================================================================
# Compatibility Normalization
# =============================================================================

class TestCompatibilityNormalization:
    def test_query_wrapper_noise_removed_for_direct_actions(self):
        server = IDAMCPServer()
        normalized = server._normalize_tool_call_args(
            "query",
            {
                "action": "data",
                "subaction": "functions",
                "source_action": "list",
                "grep": "malloc",
                "token": "abc",
                "args": {"count": 1},
            },
        )
        assert normalized["action"] == "data"
        assert normalized["subaction"] == "functions"
        assert "source_action" not in normalized
        assert "grep" not in normalized
        assert "token" not in normalized

    def test_query_wrapper_fields_preserved_for_wrapper_action(self):
        server = IDAMCPServer()
        normalized = server._normalize_tool_call_args(
            "query",
            {
                "action": "grep",
                "source_action": "data",
                "grep": "malloc",
                "grep_field": "matches",
            },
        )
        assert normalized["action"] == "grep"
        assert normalized["source_action"] == "data"
        assert normalized["grep"] == "malloc"

    def test_calc_direct_action_strips_wrapper_meta_fields(self):
        server = IDAMCPServer()
        normalized = server._normalize_tool_call_args(
            "calc",
            {
                "action": "eval",
                "expr": "0x10+1",
                "source_action": "",
                "grep": "",
                "token": "",
                "head_n": 0,
            },
        )
        assert normalized["action"] == "eval"
        assert normalized["expr"] == "0x10+1"
        assert "source_action" not in normalized
        assert "grep" not in normalized
        assert "token" not in normalized
        assert "head_n" not in normalized

    def test_search_arg_aliases_normalize_to_canonical_fields(self):
        server = IDAMCPServer()
        normalized = server._normalize_tool_call_args(
            "search",
            {"action": "find", "ea": "0x401000", "needle": "malloc"},
        )
        assert normalized["addr"] == "0x401000"
        assert normalized["pattern"] == "malloc"

    def test_funcs_wrapper_noise_removed_for_direct_action(self):
        server = IDAMCPServer()
        normalized = server._normalize_tool_call_args(
            "funcs",
            {"action": "info", "addr": "0x401000", "source_action": "list", "token": "abc"},
        )
        assert normalized["action"] == "info"
        assert normalized["addr"] == "0x401000"
        assert "source_action" not in normalized
        assert "token" not in normalized


# =============================================================================
# Telemetry Activity Recording
# =============================================================================

class TestActivityRecording:
    def test_record_activity_logs_to_session_manager(self):
        server = IDAMCPServer()

        class StubSessionMgr:
            def __init__(self):
                self.calls = []

            def log_activity(self, sid, tool, action, result):
                self.calls.append(
                    {
                        "sid": sid,
                        "tool": tool,
                        "action": action,
                        "result": result,
                    }
                )

        stub = StubSessionMgr()
        server.session_mgr = stub
        server._record_activity(
            "search",
            {"action": "find", "session_id": "ABCD1234", "query": "malloc"},
            {"ok": True, "matches": "hit at 0x401000 and 0x401020"},
        )

        assert len(stub.calls) == 1
        call = stub.calls[0]
        assert call["sid"] == "ABCD1234"
        assert call["tool"] == "search"
        assert call["action"] == "find"
        assert "0x401000" in call["result"]


# =============================================================================
# Auto-nudge Rerouting Safety
# =============================================================================

class TestAutoNudgeReroutes:
    def test_memory_read_u32_is_not_rerouted(self):
        from ida_pro_mcp.host.auto_nudge import get_reroute

        reroute = get_reroute(
            "memory",
            "read",
            {"addr": "0x401000", "type": "u32", "size": 16},
        )
        assert reroute is None

    def test_memory_read_bytes_with_disasm_intent_is_rerouted(self):
        from ida_pro_mcp.host.auto_nudge import get_reroute

        reroute = get_reroute(
            "memory",
            "read",
            {"addr": "0x401000", "type": "bytes", "size": 32, "disasm": True},
        )
        assert reroute is not None
        tool_name, new_args = reroute
        assert tool_name == "code"
        assert new_args.get("action") == "disasm"


# =============================================================================
# Batch Macro DSL
# =============================================================================

class TestBatchMacroDSL:
    @pytest.mark.skip(reason="Requires full package context with _common module")
    def test_dry_run(self):
        pass

    @pytest.mark.skip(reason="Requires full package context with _common module")
    def test_simple_expression(self):
        pass

    @pytest.mark.skip(reason="Requires full package context with _common module")
    def test_pipes(self):
        pass


# =============================================================================
# Search query_lang
# =============================================================================

class TestSearchQueryLang:
    def test_query_lang_registered_in_search_actions(self):
        assert "query_lang" in TOOL_ACTIONS["search"]

    def _load_query_lang(self):
        import importlib.util
        path = os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "support", "query_lang.py")
        spec = importlib.util.spec_from_file_location("query_lang", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["query_lang"] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_query_parser(self):
        mod = self._load_query_lang()
        parser = mod.QueryParser()
        plan = parser.parse('MATCH function * WHERE size > 100 LIMIT 10')
        assert plan is not None
        assert plan["target"] == "function"
        assert plan["identifier"] == "*"
        assert plan["limit"] == 10
        assert len(plan["conditions"]) == 1
        assert plan["conditions"][0]["key"] == "size"

    def test_query_parser_with_sort(self):
        mod = self._load_query_lang()
        parser = mod.QueryParser()
        plan = parser.parse('MATCH function * WHERE size > 100 SORT BY size DESC')
        assert plan["sort_key"] == "size"
        assert plan["sort_order"] == "DESC"

    def test_query_parser_contains(self):
        mod = self._load_query_lang()
        parser = mod.QueryParser()
        plan = parser.parse('MATCH function * WHERE apis contains "malloc"')
        assert len(plan["conditions"]) == 1
        assert plan["conditions"][0]["op"] == "contains"
        assert plan["conditions"][0]["value"] == "malloc"

    def test_query_parser_regex(self):
        mod = self._load_query_lang()
        parser = mod.QueryParser()
        plan = parser.parse('MATCH string * WHERE value ~ "http[s]?://"')
        assert len(plan["conditions"]) == 1
        assert plan["conditions"][0]["op"] == "~"
        assert plan["conditions"][0]["value"] == "http[s]?://"


# =============================================================================
# Blackboard
# =============================================================================

class TestBlackboard:
    def _load_blackboard(self):
        import importlib.util
        path = os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools", "blackboard.py")
        spec = importlib.util.spec_from_file_location("blackboard", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["blackboard"] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_write_and_read(self):
        mod = self._load_blackboard()
        blackboard = mod.blackboard
        result = blackboard(action="write", title="Test finding", content="Buffer overflow", category="vuln", confidence=0.9)
        assert result["ok"] is True
        assert "entry_id" in result
        eid = result["entry_id"]

        read_result = blackboard(action="read", entry_id=eid)
        assert read_result["ok"] is True
        assert read_result["entry"]["title"] == "Test finding"
        assert read_result["entry"]["confidence"] == 0.9

        # Cleanup
        blackboard(action="clear")

    def test_list_and_filter(self):
        mod = self._load_blackboard()
        blackboard = mod.blackboard
        blackboard(action="clear")
        blackboard(action="write", title="A", category="vuln")
        blackboard(action="write", title="B", category="info")
        blackboard(action="write", title="C", category="vuln")

        result = blackboard(action="list", category="vuln")
        assert result["ok"] is True
        assert result["count"] == 2

        blackboard(action="clear")

    def test_stats(self):
        mod = self._load_blackboard()
        blackboard = mod.blackboard
        blackboard(action="clear")
        blackboard(action="write", title="A", category="vuln")
        blackboard(action="write", title="B", category="info")

        result = blackboard(action="stats")
        assert result["ok"] is True
        assert result["total_entries"] == 2
        assert result["categories"] == 2

        blackboard(action="clear")


# =============================================================================
# Filter tool
# =============================================================================

class TestFilterTool:
    def _load_filter(self):
        import importlib.util
        path = os.path.join(os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "ida_mcp", "tools", "filter.py")
        spec = importlib.util.spec_from_file_location("filter_mod", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["filter_mod"] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_identity(self):
        mod = self._load_filter()
        data = {"functions": [{"name": "main", "size": 100}]}
        result = mod.filter(data=data, query=".")
        assert result["ok"] is True
        assert result["filtered"] == data

    def test_path_extraction(self):
        mod = self._load_filter()
        data = {"functions": [{"name": "main", "size": 100}, {"name": "foo", "size": 50}]}
        result = mod.filter(data=data, query=".functions")
        assert result["ok"] is True
        assert len(result["filtered"]) == 2

    def test_array_filter(self):
        mod = self._load_filter()
        data = {"functions": [{"name": "main", "size": 100}, {"name": "foo", "size": 50}]}
        result = mod.filter(data=data, query=".functions[?size > 75]")
        assert result["ok"] is True
        assert len(result["filtered"]) == 1
        assert result["filtered"][0]["name"] == "main"

    def test_pipes(self):
        mod = self._load_filter()
        data = {"functions": [{"name": "main", "size": 100}, {"name": "foo", "size": 50}, {"name": "bar", "size": 200}]}
        result = mod.filter(data=data, query=".functions | sort(-size) | first(2) | pluck(name)")
        assert result["ok"] is True
        assert result["filtered"] == ["bar", "main"]

    def test_slice(self):
        mod = self._load_filter()
        data = {"items": [1, 2, 3, 4, 5]}
        result = mod.filter(data=data, query=".items[0:3]")
        assert result["ok"] is True
        assert result["filtered"] == [1, 2, 3]

    def test_group_by(self):
        mod = self._load_filter()
        data = {"functions": [{"name": "a", "seg": ".text"}, {"name": "b", "seg": ".data"}, {"name": "c", "seg": ".text"}]}
        result = mod.filter(data=data, query=".functions | group_by(seg)")
        assert result["ok"] is True
        assert ".text" in result["filtered"]
        assert ".data" in result["filtered"]
        assert len(result["filtered"][".text"]) == 2


# =============================================================================
# Tool Registry Integrity
# =============================================================================

class TestRegistryIntegrity:
    def test_no_duplicate_tools(self):
        assert len(TOOLS) == len(set(TOOLS)), f"Duplicate tools: {[t for t in TOOLS if TOOLS.count(t) > 1]}"

    def test_all_tools_have_actions(self):
        # batch is action-less by design: it takes a 'calls' array of tool
        # invocations, not an action enum.
        action_less = {"batch"}
        for t in TOOLS:
            assert t in TOOL_ACTIONS, f"Tool '{t}' missing from TOOL_ACTIONS"
            if t in action_less:
                continue
            assert len(TOOL_ACTIONS[t]) > 0, f"Tool '{t}' has no actions"

    def test_blackboard_and_filter_registered(self):
        assert "blackboard" in TOOLS
        assert "filter" in TOOLS
        assert "batch" in TOOLS
        assert "search" in TOOLS

    def test_no_standalone_macro_or_query_lang(self):
        assert "macro" not in TOOLS, "macro should be merged into batch"
        assert "query_lang" not in TOOLS, "query_lang should be merged into search"
