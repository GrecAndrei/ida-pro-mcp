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
from pathlib import Path
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


# ---------------------------------------------------------------------------
# Expanded real-user sweep
# ---------------------------------------------------------------------------


def test_legacy_annotation_review_pipeline_is_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Exercise the review/comment workflow a user would run after triage.

    These calls deliberately use dry-run for generated annotations.  The
    management actions still cross the IDA process boundary, while a single
    export/import round-trip verifies the file-backed path without leaving
    test comments behind in the shared fixture.
    """
    for action, extra in (
        ("auto_comment", {"addr": "rich_entry", "dry_run": True}),
        ("auto_comment_function", {"addr": "rich_entry", "dry_run": True, "limit": 20}),
        ("label_loops", {"addr": "rich_entry", "dry_run": True}),
        ("label_branches", {"addr": "rich_entry", "dry_run": True}),
        ("mark_dangerous", {"addr": "rich_entry", "dry_run": True, "limit": 20}),
        ("annotate_constants", {"addr": "rich_entry", "dry_run": True}),
        ("tag_functions", {"addr": "rich_entry", "dry_run": True}),
        ("document_args", {"addr": "rich_entry", "dry_run": True}),
        ("mark_error_paths", {"addr": "rich_alloc_free", "dry_run": True}),
        ("propagate_names", {"addr": "rich_entry", "dry_run": True}),
        ("cleanup", {"addr": "rich_entry", "dry_run": True}),
        ("validate", {"addr": "rich_entry", "value": "reviewed analyst note"}),
        ("get_context", {"addr": "rich_entry"}),
        ("set_structured", {"addr": "rich_entry", "text": "temporary review", "fmt": "markdown", "dry_run": True}),
        ("bulk_set", {"items": json.dumps([{"addr": "rich_entry", "text": "temporary review"}]), "dry_run": True}),
        ("summary", {}),
    ):
        legacy_ctx.coded_or_ok("annotation", action=action, **extra)

    export_path = tmp_path / "expanded-comments.md"
    source_path = tmp_path / "expanded-comments-import.md"
    source_path.write_text("# rich_entry\nImported review note\n", encoding="utf-8")
    exported = legacy_ctx.coded_or_ok(
        "annotation", action="export_md", path=str(export_path), limit=50
    )
    if exported.get("error") is not True:
        assert export_path.exists()
    legacy_ctx.coded_or_ok("annotation", action="import_md", path=str(source_path))


def test_legacy_analysis_and_database_controls_are_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Cover non-destructive analysis controls and reversible IDB plumbing."""
    for action, extra in (
        ("get_options", {}),
        ("state", {}),
        ("get_af", {}),
        ("get_af", {"af_flag": "AF_MARKCODE"}),
        ("auto_wait", {"timeout_ms": 0}),
        ("set_processor", {"processor": "metapc"}),
        ("set_architecture", {"bitness": 64, "endian": "le"}),
        ("set_loader_options", {"loader": "elf", "value": ""}),
        ("set_options", {"options": {"unknown_option": 1}}),
        ("set_af", {"af_flag": "AF_MARKCODE", "af_value": True}),
        ("set_gp", {}),
        ("reanalyze", {"start": "rich_tiny", "end": "rich_tiny", "blocking": False}),
        ("run", {"start": "rich_tiny", "end": "rich_tiny", "blocking": False}),
        ("analyze", {"start": "rich_tiny", "end": "rich_tiny", "blocking": False}),
        ("make_code", {"addr": "rich_tiny", "size": 1}),
        ("undefine", {"addr": "rich_tiny", "size": 1}),
        ("force_offset", {"addr": "rich_tiny", "size": 8}),
        ("add_entry", {"addr": "rich_tiny", "ordinal": 29991, "name": "expanded_entry"}),
        ("save_idb", {"path": str(tmp_path / "expanded-copy.i64")}),
    ):
        if action in {
            "set_processor", "set_architecture", "set_loader_options", "set_options",
            "set_af", "set_gp", "reanalyze", "run", "analyze", "make_code",
            "undefine", "force_offset", "add_entry", "save_idb",
        }:
            extra = {**extra, "_risk_ack": True}
        legacy_ctx.coded_or_ok("analysis", action=action, **extra)

    snapshot = legacy_ctx.coded_or_ok(
        "analysis", action="snapshot", snapshot_name="expanded-live-snapshot"
    )
    if snapshot.get("error") is not True:
        legacy_ctx.coded_or_ok(
            "analysis", action="restore_snapshot", snapshot_name="expanded-live-snapshot",
            _risk_ack=True,
        )


def test_legacy_intelligence_and_symbol_surfaces_are_live(legacy_ctx: LegacyContext):
    """Exercise optional intelligence backends through their coded contracts."""
    for action, extra in (
        ("intelligence_status", {}),
        ("embedder_status", {}),
        ("reranker_status", {}),
        ("anchor_status", {}),
        ("classify_text", {"text": "a suspicious indirect call"}),
        ("classify_function", {"addr": "rich_entry"}),
        # Full indexing is covered by the dedicated agent live suite.  The
        # compatibility path intentionally probes its status/fallback
        # behavior here; launching a synchronous index from this legacy
        # client can exceed its short RPC timeout when llama-server is absent.
        ("blackboard_search", {"query": "rich", "limit": 5}),
        ("export_index_summary", {}),
        ("function_families", {"limit": 5}),
    ):
        legacy_ctx.coded_or_ok("intelligence", action=action, **extra)

    for action, extra in (
        ("status", {}),
        ("apply", {"addr": "rich_entry"}),
        ("load_pdb", {"path": "/tmp/no-such-expanded.pdb"}),
        ("load_dwarf", {}),
    ):
        legacy_ctx.coded_or_ok("symbols", action=action, **extra)

    for action, extra in (
        ("symbol_lookup", {"query": "rich_entry", "limit": 10}),
        ("import_symbols", {"min_confidence": 0.9, "limit": 10}),
        ("export_session", {"session_id": legacy_ctx.session_id, "limit": 10}),
    ):
        legacy_ctx.coded_or_ok("knowledge", action=action, **extra)


def test_legacy_exploit_and_emulation_surfaces_are_live(legacy_ctx: LegacyContext):
    """Cover exploit triage and debugger-backed actions without a debugger."""
    for action, extra in (
        ("rop", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("jop", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("cop", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("syscall", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("write_what_where", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("stack_pivot", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("shellcode_space", {"addr": "rich_entry", "limit": 5}),
        ("mitigations", {}),
        ("seh_handlers", {"addr": "rich_entry", "limit": 5}),
        ("pivot_chains", {"addr": "rich_entry", "limit": 5, "max_insns": 4}),
        ("classify_chain", {"query": "pop rdi; ret"}),
        ("semantic_find", {"query": "stack pivot", "limit": 5}),
    ):
        legacy_ctx.coded_or_ok("gadgets", action=action, **extra)

    for action, extra in (
        ("info", {}),
        ("backend", {}),
        ("state", {}),
        ("start", {"start_addr": "rich_entry"}),
        ("step", {"count": 1}),
        ("run_to", {"address": "rich_tiny"}),
        ("get_reg", {"name": "rip"}),
        ("set_reg", {"name": "rip", "value": "0x0"}),
        ("read_mem", {"address": "0x400000", "size": 8}),
        ("set_mem", {"address": "0x400000", "data": "00"}),
        ("suspend", {}),
        ("continue", {}),
        ("stop", {}),
    ):
        legacy_ctx.coded_or_ok("emulate", action=action, **extra)


def test_legacy_types_memory_segments_and_search_variants_are_live(
    legacy_ctx: LegacyContext
):
    """Exercise less-common query and data-shape variants used by analysts."""
    for action, extra in (
        ("read", {"addr": "rich_entry", "type": "u16"}),
        ("read", {"addr": "rich_entry", "type": "u32"}),
        ("read", {"addr": "rich_entry", "type": "u64"}),
        ("struct_walk", {"addr": "rich_entry", "depth": 2}),
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "7f 45 4c 46", "aligned": True}),
        ("compare", {"addr1": "0x400000", "addr2": "0x400000", "size": 1}),
    ):
        legacy_ctx.coded_or_ok("memory", action=action, **extra)

    for action, extra in (
        ("list", {"kind": "all", "limit": 20}),
        ("get", {"name": "rich_entry"}),
        ("parse_decl", {"declaration": "struct expanded_type { int value; };"}),
        ("search_structs", {"query": "expanded", "limit": 10}),
        ("infer", {"addr": "rich_entry"}),
        ("read_struct", {"addr": "rich_entry", "type_name": "expanded_type"}),
        ("diff", {"left": "rich_entry", "right": "rich_helper"}),
        ("visualize", {"name": "rich_entry"}),
        ("propagate", {"addr": "rich_entry"}),
        ("enum_values", {"name": "missing_expanded_enum"}),
        ("type_graph", {"name": "int"}),
        ("vtable", {"addr": "rich_entry"}),
    ):
        legacy_ctx.coded_or_ok("types", action=action, **extra)

    for action, extra in (
        ("list", {"limit": 20}),
        ("info", {"addr": "rich_entry"}),
        ("metrics", {"addr": "rich_entry"}),
        ("suggest_names", {"addr": "rich_entry", "limit": 5}),
        ("find_similar", {"addr": "rich_entry", "limit": 5}),
    ):
        legacy_ctx.coded_or_ok("funcs", action=action, **extra)

    for action, extra in (
        ("list", {}),
        ("info", {"addr": "rich_entry"}),
        ("find_code", {"start": "0x400000", "end": "0x401000"}),
        ("find_data", {"start": "0x400000", "end": "0x401000"}),
        ("compare", {"first": "0x400000", "second": "0x400000"}),
        ("sreg_get", {"addr": "rich_entry", "reg": "cs"}),
        ("sreg_list", {"start": "rich_entry"}),
    ):
        legacy_ctx.coded_or_ok("segments", action=action, **extra)


def test_legacy_type_edit_and_til_lifecycle_is_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Exercise acknowledged type-library and member editing operations.

    The compatibility client must pass the host policy acknowledgement through
    to IDA; otherwise these calls only test the policy gate and never reach the
    type implementation.  The names are unique to this run and are removed at
    the end so the fixture remains reusable.
    """
    for declaration in (
        "struct ExpandedProbe { uint32_t value; uint16_t kind; };",
        "enum ExpandedProbeKind { EXPANDED_ZERO = 0, EXPANDED_ONE = 1 };",
    ):
        payload = legacy_ctx.coded_or_ok(
            "types", action="declare", declaration=declaration, _risk_ack=True
        )
        assert payload.get("error") is not True, payload

    legacy_ctx.coded_or_ok(
        "types", action="import_header",
        declaration="struct ExpandedHeader { uint64_t marker; };",
        _risk_ack=True,
    )
    for action, extra in (
        ("get", {"name": "ExpandedProbe"}),
        ("get", {"name": "ExpandedProbeKind"}),
        ("visualize", {"name": "ExpandedProbe"}),
        ("diff", {"name": "ExpandedProbe", "other_name": "ExpandedHeader"}),
        ("search_structs", {"query": "value", "limit": 20}),
        ("enum_values", {"name": "ExpandedProbeKind", "value": 1}),
        ("type_graph", {"name": "ExpandedProbe", "max_depth": 3}),
    ):
        legacy_ctx.coded_or_ok("types", action=action, **extra)

    for action, extra in (
        ("struct_member_add", {
            "struct_name": "ExpandedProbe", "member_name": "tail",
            "type_str": "uint8_t", "offset": -1,
        }),
        ("struct_member_rename", {
            "struct_name": "ExpandedProbe", "member_name": "tail",
            "new_name": "tail_renamed",
        }),
        ("struct_member_set_type", {
            "struct_name": "ExpandedProbe", "member_name": "tail_renamed",
            "type_str": "uint16_t",
        }),
        ("struct_member_del", {
            "struct_name": "ExpandedProbe", "member_name": "tail_renamed",
        }),
        ("enum_member_add", {
            "enum_name": "ExpandedProbeKind", "member_name": "EXPANDED_TWO",
            "enum_value": 2,
        }),
        ("enum_member_rename", {
            "enum_name": "ExpandedProbeKind", "member_name": "EXPANDED_TWO",
            "new_name": "EXPANDED_TWO_RENAMED",
        }),
        ("enum_member_revalue", {
            "enum_name": "ExpandedProbeKind", "member_name": "EXPANDED_TWO_RENAMED",
            "enum_value": 22,
        }),
    ):
        legacy_ctx.coded_or_ok("types", action=action, **extra, _risk_ack=True)

    legacy_ctx.coded_or_ok(
        "types", action="set_prototype", addr="rich_entry",
        declaration="int rich_entry(int v);", _risk_ack=True,
    )
    legacy_ctx.coded_or_ok(
        "types", action="apply", addr="rich_entry",
        declaration="int32_t", kind="function", _risk_ack=True,
    )
    legacy_ctx.coded_or_ok(
        "types", action="read_struct", addr="0x400000", name="ExpandedProbe"
    )

    header_path = tmp_path / "expanded-types.h"
    exported = legacy_ctx.coded_or_ok(
        "types", action="til_export", path=str(header_path),
        name="ExpandedProbe", _risk_ack=True,
    )
    if exported.get("error") is not True:
        assert header_path.exists()
        legacy_ctx.coded_or_ok(
            "types", action="til_import", path=str(header_path), _risk_ack=True
        )

    for name in ("ExpandedProbe", "ExpandedProbeKind", "ExpandedHeader"):
        legacy_ctx.coded_or_ok("types", action="til_delete", name=name, _risk_ack=True)


def test_legacy_annotation_write_and_cleanup_lifecycle_is_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Verify a real user can write, inspect, export, import, and clean notes."""
    # Annotation context resolves an address strictly, while the write and
    # cleanup actions intentionally accept IDA names. Resolve the fixture name
    # through the same public search route a user would use instead of relying
    # on a layout-specific hard-coded address.
    resolved = legacy_ctx.coded_or_ok(
        "search", action="find", query="rich_tiny", kind="names",
        include_items=True, limit=10,
    )
    tiny_item = next(
        (
            item for item in (resolved.get("items") or [])
            if isinstance(item, dict) and item.get("name") == "rich_tiny"
        ),
        None,
    )
    assert tiny_item and tiny_item.get("addr"), resolved
    tiny_addr = str(tiny_item["addr"])

    legacy_ctx.coded_or_ok(
        "annotation", action="set_structured", addr="rich_tiny",
        text="temporary structured review", fmt="structured", _risk_ack=True,
    )
    legacy_ctx.coded_or_ok(
        "annotation", action="bulk_set",
        items=json.dumps([
            {"addr": "rich_entry", "text": "repeatable review", "type": "repeatable"},
            {"addr": "rich_tiny", "text": "function review", "type": "func"},
            {"addr": "not_an_address", "text": "rejected"},
        ]),
        _risk_ack=True,
    )
    context = legacy_ctx.coded_or_ok(
        "annotation", action="get_context", addr=tiny_addr, _risk_ack=True
    )
    assert context.get("addr")
    legacy_ctx.coded_or_ok(
        "annotation", action="auto_comment", addr="rich_entry",
        dry_run=False, _risk_ack=True,
    )
    legacy_ctx.coded_or_ok(
        "annotation", action="auto_comment_function", addr="rich_use_strings",
        limit=10, dry_run=False, _risk_ack=True,
    )

    export_path = tmp_path / "written-comments.md"
    legacy_ctx.coded_or_ok(
        "annotation", action="export_md", path=str(export_path), limit=100,
        _risk_ack=True,
    )
    if export_path.exists():
        legacy_ctx.coded_or_ok(
            "annotation", action="import_md", path=str(export_path),
            dry_run=True, _risk_ack=True,
        )
    legacy_ctx.coded_or_ok(
        "annotation", action="cleanup", prefix="[MCP] ",
        dry_run=False, _risk_ack=True,
    )
    summary = legacy_ctx.coded_or_ok("annotation", action="summary", _risk_ack=True)
    assert "total_functions" in summary


def test_legacy_composed_search_scopes_are_live(legacy_ctx: LegacyContext):
    """Exercise boolean, structural, reachability, and semantic search routes."""
    bool_queries = (
        "name:rich_entry AND NOT leaf",
        "api:malloc OR string:RICH_FIXTURE",
        "mnem:call && (caller:rich_entry || callee:rich_helper)",
        "size:>10 AND NOT no_callers",
        "leaf OR no_callers",
        'name:"rich_entry"',
    )
    for expression in bool_queries:
        legacy_ctx.coded_or_ok(
            "search", action="bool", pattern=expression, limit=20
        )
    legacy_ctx.coded_or_ok(
        "search", action="bool", pattern="name:rich_entry ???", limit=20
    )

    for action, extra in (
        ("analyze", {"addr": "rich_entry", "scope": "neighborhood", "radius": 4, "include_items": True}),
        ("neighborhood", {"addr": "rich_entry", "radius": 4}),
        ("outlier", {"metric": "size", "top": 10}),
        ("outlier", {"metric": "tiny", "top": 10}),
        ("outlier", {"metric": "huge", "top": 10}),
        ("outlier", {"metric": "bb_count", "top": 10}),
        ("outlier", {"metric": "orphan", "top": 10}),
        ("outlier", {"metric": "leaf", "top": 10}),
        ("outlier", {"metric": "hub", "top": 10}),
        ("outlier", {"metric": "deep", "top": 10}),
        ("fingerprint", {"pattern": "rich_entry", "top_k": 10}),
        ("analyze", {"addr": "rich_entry", "scope": "similar", "top_k": 10}),
        ("analyze", {"scope": "vulnerable", "pattern": "rich", "depth": 5}),
        ("analyze", {"scope": "semantic", "pattern": "allocator"}),
        ("structured", {"constraints": {"behavior_tags": ["crypto"], "tag_mode": "or"}}),
        ("nl", {"query": "function that handles strings", "mode": "quick"}),
    ):
        legacy_ctx.coded_or_ok("search", action=action, limit=10, **extra)


def test_legacy_code_navigation_variants_are_live(legacy_ctx: LegacyContext):
    """Exercise the address, range, enrichment, and bulk code paths."""
    for action, extra in (
        ("decompile", {"addrs": "rich_entry", "details": True}),
        ("semantic_decompile", {"addrs": "rich_entry"}),
        ("decompile_chain", {"addrs": "rich_entry", "max_depth": 2}),
        ("trace_argument_origin", {"addrs": "rich_helper", "arg_index": 0, "max_depth": 2}),
        ("diff_functions", {"addrs": ["rich_entry", "rich_helper"]}),
        ("find_paths", {"addrs": "rich_entry", "target": "rich_helper", "max_depth": 5}),
        ("xrefs_to_field", {"addrs": "rich_entry", "field_name": "value"}),
        ("strings_in_func", {"addrs": "rich_use_strings", "max_items": 20}),
        ("decompile_all", {"query": "rich_", "mode": "listing", "limit": 20}),
        ("decompile_all", {"query": "rich_", "mode": "full", "limit": 3, "offset": 1}),
    ):
        legacy_ctx.coded_or_ok("code", action=action, **extra)

    for style in ("csmini", "classic", "annotated"):
        legacy_ctx.coded_or_ok(
            "code", action="disasm", addrs="rich_entry", end="rich_helper",
            disasm_style=style, include_bytes=True, include_comments=True,
            annotate_branches=True, max_items=40,
        )
    legacy_ctx.coded_or_ok(
        "code", action="disasm", addrs="0x400000", end="0x400080",
        structured=True, max_items=40,
    )
    legacy_ctx.coded_or_ok(
        "code", action="disasm", addrs="rich_entry", window=4, max_items=20
    )

    for rule in (
        {"rule_type": "string_ref", "pattern": "RICH_FIXTURE"},
        {"rule_type": "xor_threshold", "threshold": 2},
        {"rule_type": "caller_of", "target": "rich_helper"},
        {"rule_type": "callee_of", "target": "rich_entry"},
        {"rule_type": "type_match", "type_pattern": "int"},
        {"rule_type": "api_chain", "apis": ["malloc", "free"], "strict_order": True},
    ):
        legacy_ctx.coded_or_ok("code", action="detect", **rule)

    for action, extra in (
        ("find", {"query": "rich", "kind": "names", "include_context": True, "include_items": True, "include_breakdown": True}),
        ("find", {"query": "RICH_FIXTURE", "kind": "strings"}),
        ("data_value", {"value": "0x400000", "endian": "le", "word_size": "u64"}),
        ("data_value", {"value": "RICH_FIXTURE_STRING_ONE"}),
        ("query_lang", {"query": "strings containing RICH_FIXTURE LIMIT 5"}),
        ("export", {"pattern": "rich_*", "include_items": True}),
        ("summary", {}),
    ):
        legacy_ctx.coded_or_ok("search", action=action, limit=10, **extra)


def test_legacy_calc_aliases_and_typed_paths_are_live(legacy_ctx: LegacyContext):
    """Exercise calculator inference, scalar formats, and typed reads end to end."""
    for action, extra in (
        ("eval", {"expr": "(1 + 2) * 3 == 9"}),
        ("eval", {"expr": "u8('0x400000') + u16('0x400001')"}),
        ("eval", {"expr": "rich_entry + 0x10"}),
        ("eval", {"semantic_action": "delta", "intent": "distance between rich_entry and rich_helper"}),
        ("offset", {"addr": "rich_helper", "target": "rich_entry"}),
        ("offset", {"intent": "distance between rich_entry and rich_helper"}),
        ("convert", {"value": "2k"}),
        ("convert", {"value": "-1"}),
        ("convert", {"value": "rich_entry"}),
        ("resolve", {"addr": "rich_entry"}),
        ("resolve", {"addr": "0x0", "to_va": True}),
        ("resolve", {"intent": "file offset 0x0"}),
        ("deref", {"addr": "0x400000", "type": "bytes", "size": 8}),
        ("deref", {"addr": "0x400000", "type": "s8"}),
        ("deref", {"addr": "0x400000", "type": "s16"}),
        ("deref", {"addr": "0x400000", "type": "s32"}),
        ("deref", {"addr": "0x400000", "type": "s64"}),
        ("deref", {"addr": "0x400000", "type": "f32"}),
        ("deref", {"addr": "0x400000", "type": "f64"}),
        ("deref", {"addr": "0x400000", "type": "ptr", "size": 8, "deref_depth": 3}),
        ("deref", {"addr": "rich_use_strings", "type": "string"}),
        ("chain", {"addr": "0x400000", "offsets": [0]}),
        ("chain", {"addr": "0x400000", "offsets": "0x0;1"}),
        ("chain", {"addr": "0x400000", "intent": "pointer chain at 0x400000 offsets 0"}),
        ("align", {"addr": "rich_entry", "size": 10}),
        ("align", {"expr": "0x401003", "size": 16}),
        ("align", {"value": "0x401003", "size": 16}),
        ("bitops", {"op": "and", "value": "0xff", "target": "0x0f"}),
        ("bitops", {"op": "or", "value": "0x10", "target": "0x03"}),
        ("bitops", {"op": "xor", "value": "0xff", "target": "0x0f"}),
        ("bitops", {"op": "not", "value": "0xff"}),
        ("bitops", {"op": "shl", "value": "1", "target": "3"}),
        ("bitops", {"op": "shr", "value": "8", "target": "2"}),
        ("eval", {"expr": "1 + 1", "persist": True, "_risk_ack": True}),
    ):
        legacy_ctx.coded_or_ok("calc", action=action, **extra)


def test_legacy_misc_knowledge_and_symbol_file_paths_are_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Verify utility files, symbol persistence, and optional loader failures."""
    text_path = tmp_path / "misc-live.txt"
    binary_path = tmp_path / "misc-live.bin"
    db_path = tmp_path / "knowledge-live.sqlite3"
    legacy_ctx.coded_or_ok(
        "misc", action="write_file", path=str(text_path), content="live utility text",
        _risk_ack=True,
    )
    legacy_ctx.coded_or_ok(
        "misc", action="write_file", path=str(binary_path), content="00 ff 10",
        encoding="binary", _risk_ack=True,
    )
    legacy_ctx.coded_or_ok("misc", action="read_file", path=str(text_path))
    legacy_ctx.coded_or_ok(
        "misc", action="read_file", path=str(binary_path), encoding="binary"
    )
    for action, extra in (
        ("load_sig", {"name": "missing-live-signature"}),
        ("list_sigs", {"name": "libc"}),
        ("plugin_run", {"name": "missing-live-plugin"}),
        ("health", {"verbose": False}),
        ("health", {"verbose": True}),
        ("reload", {"module": "funcs"}),
    ):
        legacy_ctx.coded_or_ok("misc", action=action, **extra, _risk_ack=True)

    export = legacy_ctx.coded_or_ok(
        "symbols", action="export", path=str(tmp_path / "symbols-live.json"),
        _risk_ack=True,
    )
    if export.get("error") is not True:
        assert (tmp_path / "symbols-live.json").exists()
    for action, extra in (
        ("load_pdb", {"path": str(tmp_path / "missing-live.pdb")}),
        ("load_dwarf", {}),
        ("status", {}),
        ("apply", {"addr": "rich_entry"}),
    ):
        legacy_ctx.coded_or_ok("symbols", action=action, **extra, _risk_ack=True)

    for action, extra in (
        ("export_session", {"db_path": str(db_path), "session_id": legacy_ctx.session_id}),
        ("import_symbols", {"db_path": str(db_path), "min_confidence": 0.0, "limit": 20}),
        ("symbol_lookup", {"db_path": str(db_path), "query": "rich", "limit": 20}),
    ):
        legacy_ctx.coded_or_ok("knowledge", action=action, **extra, _risk_ack=True)


def test_legacy_function_modify_and_analysis_write_paths_are_live(
    legacy_ctx: LegacyContext, tmp_path: Path
):
    """Cover acknowledged IDB edits while restoring the fixture afterward."""
    info = legacy_ctx.coded_or_ok(
        "funcs", action="info", addr="rich_entry", include_xrefs=True,
        include_prototype=True, include_stack=True,
    )
    fn_info = info.get("function") if info.get("error") is not True else None
    if isinstance(fn_info, dict) and fn_info.get("end"):
        legacy_ctx.coded_or_ok(
            "funcs", action="change", addr="rich_entry", end=fn_info["end"],
            _risk_ack=True,
        )
    for action, extra in (
        ("create", {"addr": "rich_tiny", "name": "rich_tiny"}),
        ("set_flags", {"addr": "rich_entry", "flags": 0}),
        ("delete", {"addr": "0xdeadbeef"}),
        ("list", {"query": "rich", "min_size": 1, "min_xrefs": 0, "named_only": True, "offset": 1, "count": 5}),
    ):
        legacy_ctx.coded_or_ok("funcs", action=action, **extra, _risk_ack=True)

    snapshot = legacy_ctx.coded_or_ok(
        "analysis", action="snapshot", snapshot_name="modify-live-snapshot",
        _risk_ack=True,
    )
    try:
        for comment_type in ("regular", "repeatable", "anterior", "posterior"):
            legacy_ctx.coded_or_ok(
                "modify", action="comment", addr="rich_tiny",
                value=f"temporary {comment_type} comment", comment_type=comment_type,
                _risk_ack=True,
            )
        legacy_ctx.coded_or_ok(
            "modify", action="rename", addr="rich_tiny", value="mcp_temporary_tiny",
            _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="rename", addr="mcp_temporary_tiny", value="rich_tiny",
            _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="set_type", addr="rich_entry", type_str="int32_t",
            _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="patch_bytes", addr="rich_tiny", nop=True, count=1,
            _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="patch_asm", addr="rich_tiny", asm="nop; nop",
            _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="rename_local", addr="rich_entry",
            new_name="temporary_local", _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="create_data", addr="0x400000", item_type="byte",
            count=2, _risk_ack=True,
        )
        legacy_ctx.coded_or_ok(
            "modify", action="create_strlit", addr="0x400000", size=4,
            strtype="c", _risk_ack=True,
        )
        legacy_ctx.coded_or_ok("modify", action="undo_begin", _risk_ack=True)
        legacy_ctx.coded_or_ok("modify", action="undo_end", _risk_ack=True)
    finally:
        if snapshot.get("error") is not True:
            legacy_ctx.coded_or_ok(
                "analysis", action="restore_snapshot", snapshot_name="modify-live-snapshot",
                _risk_ack=True,
            )


def test_legacy_memory_typed_search_and_segment_analysis_are_live(
    legacy_ctx: LegacyContext
):
    """Exercise typed memory modes plus the full segment analysis matrix."""
    string_payload = legacy_ctx.ok(
        "data", action="strings", query="RICH_FIXTURE", count=1
    )
    string_addr = None
    first_line = str(string_payload.get("strings") or "").splitlines()
    if first_line and first_line[0].split():
        token = first_line[0].split()[0]
        if token.startswith("0x"):
            string_addr = token

    for value_type in ("s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"):
        legacy_ctx.coded_or_ok(
            "memory", action="read", addr=string_addr or "0x400000",
            type=value_type, size=8,
        )
    for action, extra in (
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "0x7f", "int_width": 1}),
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "7f 45 ?? 46"}),
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "ELF", "regex": True}),
        ("search", {"addr": "0x400000", "end_addr": "0x401000", "data": "7f", "literal": True}),
        ("compare", {"addr1": "0x400000", "addr2": "0x400001", "size": 8}),
        ("pointers", {"addr": "0x400000", "end_addr": "0x401000", "aligned": True}),
        ("struct_walk", {"addr": "0x400000", "depth": 0}),
    ):
        legacy_ctx.coded_or_ok("memory", action=action, **extra)

    scratch_start = "0x700000"
    scratch_end = "0x701000"
    added = legacy_ctx.coded_or_ok(
        "segments", action="add", start=scratch_start, end=scratch_end,
        name="mcp_scratch", sclass="DATA", _risk_ack=True,
    )
    current_start = scratch_start
    if added.get("error") is not True:
        for action, extra in (
            ("info", {"start": current_start}),
            ("set_attr", {"start": current_start, "attr": "color", "value": 0x123456}),
            ("set_perms", {"start": current_start, "value": "rw"}),
            ("analyze", {"start": current_start}),
            ("find_code", {"start": current_start}),
            ("find_data", {"start": current_start}),
            ("sreg_get", {"start": current_start, "reg": "cs"}),
            ("sreg_list", {"start": current_start}),
        ):
            legacy_ctx.coded_or_ok("segments", action=action, **extra, _risk_ack=True)
        moved = legacy_ctx.coded_or_ok(
            "segments", action="move", start=current_start, end="0x710000",
            _risk_ack=True,
        )
        if moved.get("error") is not True:
            current_start = "0x710000"
        legacy_ctx.coded_or_ok(
            "segments", action="delete", start=current_start, _risk_ack=True
        )

    for action, extra in (
        ("analyze", {}),
        ("merge", {}),
        ("compare", {"name": ".text", "name2": ".text"}),
        ("list", {"offset": 1, "count": 2}),
    ):
        legacy_ctx.coded_or_ok("segments", action=action, **extra)


def test_legacy_batch_templates_pipes_conditions_and_macros_are_live(
    legacy_ctx: LegacyContext
):
    """Exercise the batch DSL and JSON orchestration modes over real tools."""
    dry = legacy_ctx.coded_or_ok(
        "batch", script='set targets = data(action="functions")\nreturn targets',
        dry_run=True, _risk_ack=True,
    )
    if dry.get("error") is not True:
        assert dry.get("mode") == "script"

    for template in ("analyze_function", "map_binary", "deep_function_audit"):
        legacy_ctx.coded_or_ok(
            "batch", template=template, template_vars={"addr": "rich_entry"},
            _risk_ack=True,
        )
    legacy_ctx.coded_or_ok(
        "batch", template="not-a-template", template_vars={"addr": "rich_entry"},
        _risk_ack=True,
    )

    calls = [
        {"tool": "data", "action": "functions", "count": 3},
        {
            "tool": "search", "action": "find", "query": "rich_entry",
            "depends_on": 0, "pipe_from": 0, "pipe_field": "functions",
            "if_result": {"index": 0, "field": "ok", "op": "eq", "value": True},
        },
        {"tool": "calc", "action": "eval", "expr": "1 + 1", "depends_on": [0, 1]},
    ]
    legacy_ctx.coded_or_ok(
        "batch", calls=calls, stop_on_error=False, _risk_ack=True
    )

    script = "\n".join(
        (
            'set rows = [{"name":"b","score":2},{"name":"a","score":1},{"name":"b","score":2}]',
            "filter rows where score >= 1",
            "set names = rows | sort(-score) | pluck(name) | unique",
            'if names != "never": data(action="lookup", query="rich_entry")',
            'for row in rows: calc(action="convert", value="2k")',
            "return names",
        )
    )
    result = legacy_ctx.coded_or_ok("batch", script=script, _risk_ack=True)
    if result.get("error") is not True:
        assert isinstance(result.get("final"), list), result


def test_legacy_types_declarations_inference_and_dependency_graph_are_live(
    legacy_ctx: LegacyContext
):
    """Cover type parsing modes and nested dependency rendering via MCP."""
    for declaration in (
        "typedef unsigned long ExpandedWord;",
        "struct ExpandedNested { ExpandedWord count; uint8_t data[4]; };",
        "struct ExpandedOuter { struct ExpandedNested nested; int status; };",
        "enum ExpandedMode { EXPANDED_MODE_A = 3, EXPANDED_MODE_B = 4 };",
    ):
        legacy_ctx.coded_or_ok(
            "types", action="declare", declaration=declaration, _risk_ack=True
        )

    for declaration in (
        "int *",
        "int expanded_function(int value);",
        "struct ExpandedNested",
        "enum ExpandedMode",
    ):
        legacy_ctx.coded_or_ok(
            "types", action="parse_decl", declaration=declaration, _risk_ack=True
        )
    for action, extra in (
        ("list", {"query": "Expanded", "offset": 0, "count": 50}),
        ("get", {"name": "ExpandedOuter", "include_members": True}),
        ("infer", {"addr": "rich_entry", "include_xrefs": True}),
        ("propagate", {"addr": "rich_entry", "limit": 10}),
        ("type_graph", {"name": "ExpandedOuter", "max_depth": 5}),
        ("visualize", {"name": "ExpandedOuter", "format": "text"}),
        ("diff", {"name": "ExpandedNested", "other_name": "ExpandedOuter"}),
        ("enum_values", {"name": "ExpandedMode", "value": 3}),
        ("search_structs", {"query": "Expanded", "offset": 0, "count": 50}),
        ("vtable", {"addr": "rich_entry"}),
    ):
        legacy_ctx.coded_or_ok("types", action=action, **extra, _risk_ack=True)

    for name in (
        "ExpandedOuter", "ExpandedNested", "ExpandedMode", "ExpandedWord",
    ):
        legacy_ctx.coded_or_ok("types", action="til_delete", name=name, _risk_ack=True)
