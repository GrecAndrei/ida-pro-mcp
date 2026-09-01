"""Broad live coverage for the legacy ``tool(action=...)`` compatibility API.

The public contract is the action-specific ``ida_*`` surface, but existing
clients still use the compatibility backend.  The existing legacy suite
covered detector, memory-search, globals, vulnerability, and emulation
smoke paths.  This module drives the real root stdio server through the rest
of the compatibility categories against a deterministic ELF fixture.

These tests are intentionally opt-in because they launch a licensed IDA
process.  They do not mock IDA or call implementation functions directly:
every assertion crosses JSON-RPC, the host dispatcher, and the IDA-side
handler.

    IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
      pytest -q tests/integration/test_legacy_surface_live.py
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from typing import Any

import pytest

# Importing the shared integration helpers keeps fixture construction and
# session readiness identical to the original legacy live tests.
from tests.integration.test_ida_live_integration import (  # noqa: E402
    MCPIntegrationClient,
    _build_fixture,
    _parse_result,
    _require_session,
    _wait_session_ready,
)

LIVE_FLAG = "IDA_MCP_LIVE_TEST"
pytestmark = [
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get(LIVE_FLAG) != "1",
        reason=f"set {LIVE_FLAG}=1 to run tests against a licensed IDA installation",
    ),
    pytest.mark.timeout(180),
]


@dataclass
class LegacyContext:
    client: MCPIntegrationClient
    binary: str
    session_id: str | None

    def raw(self, tool: str, **args: Any) -> dict:
        result = self.client.call_tool(tool, **args)
        assert isinstance(result, dict), f"{tool} returned a non-object envelope: {result!r}"
        return result

    def call(self, tool: str, **args: Any) -> dict:
        result = self.raw(tool, **args)
        payload = _parse_result(result)
        assert isinstance(payload, dict), (
            f"{tool} returned no structured JSON payload: {result!r}"
        )
        return payload

    def ok(self, tool: str, **args: Any) -> dict:
        payload = self.call(tool, **args)
        assert payload.get("error") is not True, f"{tool} failed: {payload}"
        assert payload.get("ok") is True, f"{tool} did not report ok: {payload}"
        return payload

    def coded_or_ok(self, tool: str, **args: Any) -> dict:
        """Require a real structured response, including for optional features."""
        payload = self.call(tool, **args)
        if payload.get("error") is True:
            assert isinstance(payload.get("code"), str) and payload["code"], payload
        else:
            assert payload.get("ok") is True, payload
        return payload

    @staticmethod
    def text(payload: dict) -> str:
        return json.dumps(payload, sort_keys=True, default=str)


@pytest.fixture(scope="module")
def legacy_ctx(tmp_path_factory: pytest.TempPathFactory) -> LegacyContext:
    """Start one real legacy stdio server and one analyzed IDA session."""
    binary = _build_fixture()
    if not binary:
        pytest.skip("No compiler and IDA_MCP_TEST_BINARY is unset")

    # These are test-only process settings.  They make the run deterministic
    # without changing the user's shell or the production defaults.
    old_env = {
        key: os.environ.get(key)
        for key in (
            "IDA_MCP_STRUCTURED_CONTENT",
            "IDA_MCP_TOOL_SURFACE",
            "IDA_MCP_DISABLE_RATE_LIMIT",
            "IDA_MCP_DISABLE_STUCK_DETECTION",
        )
    }
    os.environ["IDA_MCP_STRUCTURED_CONTENT"] = "1"
    os.environ["IDA_MCP_TOOL_SURFACE"] = "legacy"
    os.environ["IDA_MCP_DISABLE_RATE_LIMIT"] = "1"
    os.environ["IDA_MCP_DISABLE_STUCK_DETECTION"] = "1"

    client = MCPIntegrationClient(
        timeout=int(os.environ.get("IDA_MCP_LIVE_CALL_TIMEOUT", "45"))
    )
    try:
        if not client.start():
            pytest.fail("The real legacy stdio server did not become ready")
        session_id = _require_session(client, binary)
        _wait_session_ready(client, session_id, timeout=60.0)
        yield LegacyContext(client=client, binary=binary, session_id=session_id)
    finally:
        with contextlib.suppress(Exception):
            client.close()
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ---------------------------------------------------------------------------
# JSON-RPC and session lifecycle
# ---------------------------------------------------------------------------


def test_legacy_tools_list_advertises_compatibility_surface(legacy_ctx: LegacyContext):
    response = legacy_ctx.client.request("tools/list", {})
    tools = response.get("tools")
    assert isinstance(tools, list) and tools, response
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    assert {"session", "data", "code", "search", "memory"} <= names
    assert "ida_decompile" not in names


def test_legacy_unknown_tool_is_a_coded_result(legacy_ctx: LegacyContext):
    payload = legacy_ctx.call("not_a_real_legacy_tool", action="status")
    assert payload.get("error") is True
    assert isinstance(payload.get("code"), str)


def test_legacy_unknown_action_is_a_coded_result(legacy_ctx: LegacyContext):
    payload = legacy_ctx.call("data", action="not_a_real_action")
    assert payload.get("error") is True
    assert isinstance(payload.get("code"), str)


def test_legacy_session_identity_health_and_state(legacy_ctx: LegacyContext):
    listed = legacy_ctx.ok("session", action="list", limit=50)
    assert legacy_ctx.session_id in legacy_ctx.text(listed)
    health = legacy_ctx.ok("session", action="health")
    assert health.get("healthy") is not False
    state = legacy_ctx.ok("session", action="state")
    assert isinstance(state.get("state"), dict), state
    status = legacy_ctx.ok("session", action="status")
    assert status.get("analysis_complete") is True or "session" in status, status
    got = legacy_ctx.ok("session", action="get", session_id=legacy_ctx.session_id)
    assert legacy_ctx.session_id in legacy_ctx.text(got)


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("logs", {"limit": 10}),
        ("dashboard", {}),
        ("search_notes", {"query": "fixture", "limit": 10}),
        ("list_skills", {}),
        ("get_phase", {}),
        ("suggest_triage", {"limit": 5}),
        ("suggest_strategy", {"limit": 5}),
    ],
)
def test_legacy_session_read_actions_are_structured(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    legacy_ctx.coded_or_ok("session", action=action, **extra)


# ---------------------------------------------------------------------------
# IDB/data discovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "extra", "required"),
    [
        ("meta", {}, ("processor", "bitness")),
        ("summary", {}, ("functions", "segments")),
        ("overview", {}, ("meta", "summary")),
        ("architecture_profile", {}, ("current",)),
        ("segments", {"count": 20}, ("segments",)),
        ("entrypoints", {}, ("entrypoints",)),
        # Empty list fields are compacted away by the legacy postprocessor;
        # count is the stable signal for those responses.
        ("bookmarks", {}, ("count",)),
        ("state", {}, ("analysis", "database")),
        ("events", {"limit": 10}, ("count", "limit")),
        ("registers", {}, ("registers",)),
    ],
)
def test_legacy_idb_actions_return_real_metadata(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any], required: tuple[str, ...]
):
    payload = legacy_ctx.ok("idb", action=action, **extra)
    for key in required:
        assert key in payload, (action, payload)


@pytest.mark.parametrize(
    ("action", "extra", "required"),
    [
        ("functions", {"count": 20, "include_xrefs": True}, ("functions", "total")),
        ("annotations", {"count": 20}, ("annotations", "total")),
        ("globals", {"count": 20, "include_xrefs": True}, ("globals", "total")),
        ("strings", {"query": "RICH_FIXTURE", "count": 20}, ("strings",)),
        ("imports", {"count": 20}, ("imports",)),
        ("exports", {"count": 20}, ("exports",)),
        ("lookup", {"query": "rich_entry"}, ("addr", "name")),
        (
            "bulk_query",
            {
                "items": [
                    {"kind": "functions", "count": 3},
                    {"kind": "strings", "query": "RICH_FIXTURE", "count": 3},
                    {"kind": "imports", "count": 3},
                ]
            },
            ("results",),
        ),
        ("capability_matrix", {}, ("matrix", "top_categories")),
        ("string_xrefs", {}, ("top_strings", "total_strings_scanned")),
        ("read_bytes", {"addr": "0x400000", "size": 16}, ("hex", "dump")),
    ],
)
def test_legacy_data_actions_return_fixture_evidence(
    legacy_ctx: LegacyContext,
    action: str,
    extra: dict[str, Any],
    required: tuple[str, ...],
):
    payload = legacy_ctx.ok("data", action=action, **extra)
    for key in required:
        assert key in payload, (action, payload)


# ---------------------------------------------------------------------------
# Code, CTree, graph, and function helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "extra", "required"),
    [
        # The rich entry function intentionally contains a taint path; the
        # dedicated vulnerability suite covers that deep scan.  Keep this
        # smart-summary contract test on a small function so the live matrix
        # remains bounded while still exercising the expensive enrichment path.
        ("smart_decompile", {"addr": "rich_tiny"}, ("pseudocode",)),
        ("decompile", {"addr": "rich_entry"}, ("code",)),
        ("disasm", {"addr": "rich_entry", "limit": 30}, ("disasm",)),
        ("blocks", {"addr": "rich_entry"}, ("blocks",)),
        ("callgraph", {"addr": "rich_entry", "format": "json"}, ("nodes",)),
        ("xrefs_to", {"addr": "rich_xor_blend"}, ("xrefs",)),
        ("xrefs_from", {"addr": "rich_entry"}, ("xrefs",)),
        ("callees", {"addr": "rich_entry"}, ("callees",)),
        ("callers", {"addr": "rich_xor_blend"}, ("callers",)),
        ("strings_in_func", {"addr": "rich_use_strings"}, ("strings",)),
        ("decomp_dataflow", {"addr": "rich_entry"}, ("dataflow",)),
        ("explain", {"addr": "rich_entry"}, ("summary",)),
    ],
)
def test_legacy_code_actions_follow_fixture_call_graph(
    legacy_ctx: LegacyContext,
    action: str,
    extra: dict[str, Any],
    required: tuple[str, ...],
):
    payload = legacy_ctx.coded_or_ok("code", action=action, **extra)
    if payload.get("error") is True:
        pytest.fail(f"code/{action} failed on the analyzed rich fixture: {payload}")
    for key in required:
        assert key in payload, (action, payload)


@pytest.mark.parametrize("action", [
    "get", "traverse", "find_calls", "find_vars", "find_strings",
    "find_conditions", "get_logic_flow", "dominance_map", "var_dependency_graph",
])
def test_legacy_ctree_actions_are_real_or_coded(legacy_ctx: LegacyContext, action: str):
    payload = legacy_ctx.coded_or_ok("ctree", action=action, addr="rich_entry")
    if payload.get("error") is False:
        assert legacy_ctx.text(payload), payload


@pytest.mark.parametrize("action", ["callgraph", "cfg", "dominators", "xref_graph"])
def test_legacy_graph_actions_are_real_or_coded(legacy_ctx: LegacyContext, action: str):
    payload = legacy_ctx.coded_or_ok("graph", action=action, addr="rich_entry", depth=3)
    if payload.get("error") is False:
        assert legacy_ctx.text(payload), payload


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("list", {"count": 10}),
        ("info", {"addr": "rich_entry", "include_prototype": True}),
        ("metrics", {"addr": "rich_entry"}),
        ("suggest_names", {"addr": "rich_entry"}),
        ("find_similar", {"addr": "rich_entry", "limit": 5}),
    ],
)
def test_legacy_function_actions_have_a_response(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    legacy_ctx.coded_or_ok("funcs", action=action, **extra)


# ---------------------------------------------------------------------------
# Raw memory and search modes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "extra", "required"),
    [
        ("read", {"addr": "0x400000", "type": "bytes", "size": 16}, ("value",)),
        ("read", {"addr": "0x400000", "type": "u8"}, ("value",)),
        ("hexdump", {"addr": "0x400000", "size": 32}, ("hexdump",)),
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "7f 45 4c 46"}, ()),
        ("compare", {"addr1": "0x400000", "addr2": "0x400000", "size": 16}, ()),
        ("pointers", {"addr": "0x400000", "end_addr": "0x401000"}, ("pointers",)),
        ("entropy", {"addr": "0x400000", "end_addr": "0x401000"}, ("entropy",)),
        ("strings", {"addr": "0x400000", "end_addr": "0x401000"}, ("strings",)),
        ("histogram", {"addr": "0x400000", "end_addr": "0x401000"}, ("histogram",)),
    ],
)
def test_legacy_memory_actions_read_real_ida_bytes(
    legacy_ctx: LegacyContext,
    action: str,
    extra: dict[str, Any],
    required: tuple[str, ...],
):
    payload = legacy_ctx.ok("memory", action=action, **extra)
    for key in required:
        assert key in payload, (action, payload)


SEARCH_CASES = [
    ("find", {"pattern": "rich_entry"}),
    ("name", {"pattern": "rich_entry"}),
    ("symbol", {"pattern": "rich_entry"}),
    ("symbol_info", {"pattern": "rich_entry"}),
    ("string", {"pattern": "RICH_FIXTURE_STRING_ONE"}),
    ("xrefs_to_string", {"pattern": "RICH_FIXTURE_STRING_ONE"}),
    ("bytes", {"pattern": "7f 45 4c 46", "start": "0x400000", "end": "0x401000"}),
    ("regex", {"pattern": "rich_.*", "start": "0x400000", "end": "0x405000"}),
    ("text", {"pattern": "rich_entry"}),
    ("operand", {"pattern": "0x"}),
    ("mnemonic", {"pattern": "call"}),
    ("instruction", {"pattern": "call"}),
    ("comment", {"pattern": "RICH"}),
    ("data_ref", {"pattern": "RICH_FIXTURE_STRING_ONE"}),
    ("code_ref", {"pattern": "puts"}),
    ("decompiled", {"pattern": "rich_entry"}),
    ("constants", {"pattern": "7"}),
    ("immediate", {"pattern": "7"}),
    ("summary", {"pattern": "rich"}),
    ("query_lang", {"query": "functions with size > 10 LIMIT 5"}),
    ("outlier", {"metric": "size", "limit": 5}),
    ("neighborhood", {"addr": "rich_entry", "radius": 3, "limit": 5}),
    ("path", {"src": "rich_entry", "dst": "rich_xor_blend", "max_depth": 5}),
    ("reach", {"root": "rich_entry", "depth": 4, "limit": 10}),
    ("noreach", {"depth": 2, "limit": 10}),
    ("func_by_sig", {"pattern": "rich_entry"}),
    ("type", {"pattern": "int"}),
    ("export", {"pattern": "main"}),
    ("demangle", {"pattern": "rich_entry"}),
    ("xrefs_to_string", {"pattern": "RICH_FIXTURE_STRING_TWO"}),
    ("data_value", {"value": "RICH_FIXTURE_STRING_ONE"}),
]


@pytest.mark.parametrize("action,extra", SEARCH_CASES)
def test_legacy_search_actions_never_leave_the_protocol(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    # Some searches legitimately return NO_RESULTS on a compiler/version
    # combination.  The important live invariant for this matrix is that the
    # action reaches IDA and returns either a usable result or a coded error,
    # never an empty/non-JSON/protocol-level response.
    search_args = {"limit": 10, **extra}
    legacy_ctx.coded_or_ok("search", action=action, **search_args)


# ---------------------------------------------------------------------------
# Analysis, governance, annotations, imports, and diagnostics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "action", "extra"),
    [
        ("analysis", "get_options", {}),
        ("analysis", "state", {}),
        ("analysis", "auto_wait", {"timeout_ms": 1000}),
        ("annotation", "summary", {}),
        ("annotation", "validate", {"value": "a short analyst note"}),
        ("annotation", "export_md", {"limit": 10}),
        ("governance", "list_rules", {}),
        ("governance", "stats", {}),
        ("governance", "redact", {"proposed_value": "email test@example.com"}),
        ("governance", "check", {"operation_type": "comment", "addr": "rich_entry", "proposed_value": "live"}),
        ("misc", "health", {"verbose": True}),
        ("misc", "cache_stats", {}),
        ("misc", "list_sigs", {}),
        ("misc", "plugin_list", {}),
        ("misc", "python", {"expr": "40 + 2"}),
        ("misc", "idc", {"expr": "1 + 1"}),
        ("misc", "read_file", {"path": "PLACEHOLDER_BINARY"}),
    ],
)
def test_legacy_diagnostics_and_utilities_are_live(
    legacy_ctx: LegacyContext, tool: str, action: str, extra: dict[str, Any]
):
    if extra.get("path") == "PLACEHOLDER_BINARY":
        extra = {**extra, "path": legacy_ctx.binary}
    payload = legacy_ctx.coded_or_ok(tool, action=action, **extra)
    if tool == "misc" and action == "python" and payload.get("error") is not True:
        assert payload.get("result") == 42, payload


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("thunks", {}),
        ("delay", {}),
        ("forwarded", {}),
        ("ordinal", {}),
        ("api_sets", {}),
        ("resolve", {}),
    ],
)
def test_legacy_deep_import_actions_are_structured(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    legacy_ctx.coded_or_ok("imports_deep", action=action, **extra)


@pytest.mark.parametrize(
    "action",
    ["frame", "buffers", "canary", "alignment", "spills", "usage", "variables", "arrays", "uninitialized", "summary"],
)
def test_legacy_stack_analysis_actions_are_structured(legacy_ctx: LegacyContext, action: str):
    legacy_ctx.coded_or_ok("stack_analysis", action=action, addr="rich_entry")


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("status", {}),
        ("list", {"limit": 10}),
        ("stats", {}),
        ("coverage", {}),
        ("workspace_brief", {"limit": 10}),
        ("state_health", {}),
        ("frontier", {"limit": 10}),
        ("next_target", {"limit": 10}),
        ("export", {}),
        ("search", {"query": "rich", "limit": 10}),
    ],
)
def test_legacy_blackboard_read_actions_are_structured(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    legacy_ctx.coded_or_ok("blackboard", action=action, **extra)


@pytest.mark.parametrize(
    ("tool", "action", "extra"),
    [
        ("bookmarks", "list", {"limit": 10}),
        ("bookmarks", "find", {"query": "rich", "limit": 10}),
        ("bookmarks", "export", {}),
        ("knowledge", "symbol_lookup", {"query": "rich_entry", "limit": 10}),
        ("knowledge", "export_session", {"limit": 10}),
        ("symbols", "status", {}),
        ("symbols", "export", {}),
        ("truncation", "summary", {}),
        ("truncation", "peek", {"token": "not-a-real-token"}),
        ("wiki", "list_topics", {}),
        ("wiki", "search", {"query": "analysis", "limit": 5}),
        ("wiki", "sections", {"topic": "tools"}),
        ("wiki", "catalog", {}),
    ],
)
def test_legacy_supporting_tools_return_real_or_coded_results(
    legacy_ctx: LegacyContext, tool: str, action: str, extra: dict[str, Any]
):
    legacy_ctx.coded_or_ok(tool, action=action, **extra)


# ---------------------------------------------------------------------------
# Stateful host orchestration and cross-tool behavior
# ---------------------------------------------------------------------------


def test_legacy_batch_runs_multiple_real_calls(legacy_ctx: LegacyContext):
    payload = legacy_ctx.ok(
        "batch",
        calls=[
            {"tool": "idb", "action": "meta"},
            {"tool": "data", "action": "functions", "count": 3},
            {"tool": "calc", "action": "eval", "expr": "0x10 + 2"},
        ],
    )
    results = payload.get("results")
    assert isinstance(results, list) and len(results) == 3, payload
    assert all(isinstance(item, dict) for item in results), payload


@pytest.mark.parametrize("action", ["catalog", "estimate", "plan", "explain"])
def test_legacy_workflow_planning_actions_are_live(legacy_ctx: LegacyContext, action: str):
    payload = legacy_ctx.coded_or_ok("workflow", action=action)
    if payload.get("error") is not True:
        assert legacy_ctx.text(payload), payload


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("eval", {"expr": "0x400000 + 0x20"}),
        ("offset", {"address": "0x400020", "base": "0x400000"}),
        ("convert", {"value": "42"}),
        ("resolve", {"query": "rich_entry"}),
        ("deref", {"address": "0x400000"}),
        ("chain", {"address": "0x400000", "offsets": [0]}),
        ("align", {"value": "0x401023", "alignment": 16}),
        ("bitops", {"op": "and", "left": "0xff", "right": "0x0f"}),
    ],
)
def test_legacy_calc_actions_return_values_or_coded_errors(
    legacy_ctx: LegacyContext, action: str, extra: dict[str, Any]
):
    payload = legacy_ctx.coded_or_ok("calc", action=action, **extra)
    if action == "eval" and payload.get("error") is not True:
        assert payload.get("value") == 0x400020, payload
