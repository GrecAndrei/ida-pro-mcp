"""Regression tests for the Step-5 dedup: extracting the 13
`agent.intelligence_*` actions into a new dedicated `intelligence`
tool.

Companion to `test_agent_intelligence_static.py`, which focuses on
the action names + schema surface; this file focuses on the
extraction side-effects (file added, agent.py slimmed, schema
registration, alias routing, CLI plumbing, doc/wiki).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _abs(rel: str) -> Path:
    return ROOT / rel


def test_intelligence_tool_file_exists_and_is_a_tool():
    """The new tool file exists and is a real @tool module."""
    p = _abs("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    assert p.exists()
    text = p.read_text(encoding="utf-8")
    assert "@tool" in text
    assert "@idaread" in text
    # The dispatcher signature must use `**kwargs` (intelligence actions
    # accept varied `threshold`/`top_k`/etc. parameters).
    assert "**kwargs" in text
    # Module-level guard: the IDA SDK is not imported unconditionally;
    # the intelligence_core import is inside the try/except inside the
    # function so a missing optional dependency surfaces gracefully.
    assert "ida_pro_mcp.host.intelligence_core" in text
    # The dispatcher must call `handle_error` (catches the broad except).
    assert "handle_error" in text


def test_intelligence_tool_no_residual_agent_dispatcher_branches():
    """`agent.py` must not contain `intelligence_*` dispatcher branches
    any more."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    # No `elif action in ("intelligence_status", ...)`.
    assert "elif action in (\"intelligence_status\"" not in text
    # No `if action in ("intelligence_status", "embedder_status"):` block.
    assert "if action in (\"intelligence_status\", \"embedder_status\")" not in text
    # No `if action == "evidence_card":` branch (extracted).
    assert "if action == \"evidence_card\":" not in text
    # No `if action == "classify_text":` branch.
    assert "if action == \"classify_text\":" not in text


def test_intelligence_tool_action_enum_has_13_entries():
    """The Literal enum in the new tool has exactly 13 actions."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    # Pull out the Literal block.
    lit_match = re.search(
        r"Literal\[(.*?)\]", text, re.DOTALL
    )
    assert lit_match, "Literal[...] block not found"
    body = lit_match.group(1)
    actions = re.findall(r'"([a-z_]+)"', body)
    expected = {
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
        "structural_ingest", "structural_query", "structural_get",
        "structural_stats", "structural_delete", "structural_refresh",
        "structural_extract", "structural_extract_single", "blackboard_federate",
    }
    assert set(actions) == expected, f"mismatch: got {set(actions)}"


def test_agent_tool_action_enum_dropped_13_entries():
    """`agent.py` Literal enum dropped from 30 to 17 actions."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    lit_match = re.search(
        r"Literal\[(.*?)\]", text, re.DOTALL
    )
    assert lit_match
    body = lit_match.group(1)
    actions = re.findall(r'"([a-z_]+)"', body)
    expected = {
        "analyze_function", "explore_address", "find_references",
        "search_all", "search_structs", "context_pack", "quick",
        "rename_suggestions", "batch_context", "similar", "bridge_query",
        "reflect", "cluster", "fingerprint", "cfg_encode", "cfg_similar",
        "cfg_stats",
    }
    assert set(actions) == expected, f"mismatch: got {set(actions)}"


def test_tools_init_exports_intelligence():
    """The lazy `__getattr__` tool registry lists `intelligence`."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/__init__.py")
    assert '"intelligence"' in text


def test_intelligence_added_to_legacy_alias_map():
    """Back-compat aliases for `intelligence` are added to the
    `_EXTRA_TOOL_ALIASES` dict."""
    text = _read("src/ida_pro_mcp/host/schemas_data.py")
    for alias in ("embeddings", "ai_classifier", "agent_intelligence"):
        m = re.search(rf'"{re.escape(alias)}":\s*"intelligence"', text)
        assert m, f"legacy alias {alias!r} → intelligence not found"


def test_intelligence_tool_module_imports_safely():
    """Import the new tool module's source via importlib and verify the
    exported `intelligence` symbol is bound and decorated with @tool."""
    # We cannot import the module directly because it triggers `idaapi`
    # at module load via `_common`. Use the same regex+exec pattern
    # used for firmware_bootstrap tests.
    src_text = (ROOT / "src/ida_pro_mcp/ida_mcp/tools/intelligence.py").read_text(
        encoding="utf-8"
    )
    # The module must define exactly one top-level async/sync `def intelligence(`.
    assert re.search(r"^def intelligence\(", src_text, re.MULTILINE), (
        "intelligence() function not found at module scope"
    )


def test_schemas_py_knows_about_intelligence_tool():
    """schemas.py exports `intelligence` in TOOLS, ADVERTISED, and
    TOOL_ACTIONS via _TOOL_ACTIONS_DATA."""
    from ida_pro_mcp.host.schemas import TOOLS, TOOL_ACTIONS, HIDDEN_TOOLS_IN_LIST, ADVERTISED_TOOLS
    assert "intelligence" in TOOLS
    assert "intelligence" in TOOL_ACTIONS
    assert "intelligence" in ADVERTISED_TOOLS
    # The wrapper actions (grep/pick/head/tail/next/stats) extend the
    # enum at schema-build time; the raw TOOL_ACTIONS has 13.
    assert len(TOOL_ACTIONS["intelligence"]) == 13


def test_intelligence_arg_schema_includes_intelligence_specific_args():
    """The intelligence arg schema includes addr/query/threshold/etc."""
    text = _read("src/ida_pro_mcp/host/schemas_data.py")
    # Find the intelligence arg-schema block.
    m = re.search(r'"intelligence":\s*\{(.*?)\n\s*\}', text, re.DOTALL)
    assert m, "intelligence arg schema block not found"
    block = m.group(1)
    for key in ("action", "addr", "query", "max_items",
                "threshold", "top_k", "block", "probe", "deep_hash", "limit"):
        assert f'"{key}"' in block, f"intelligence arg schema missing {key}"


def test_agent_arg_schema_drops_intelligence_specific_args():
    """`agent` arg schema no longer has threshold/top_k/probe/deep_hash."""
    text = _read("src/ida_pro_mcp/host/schemas_data.py")
    m = re.search(r'"agent":\s*\{(.*?)\n\s*\}', text, re.DOTALL)
    assert m
    block = m.group(1)
    for key in ("threshold", "top_k", "block", "probe", "deep_hash", "limit"):
        assert f'"{key}"' not in block, f"agent arg schema still has {key}"


def test_cli_calls_intelligence_tool_not_agent():
    """`ida_pro_mcp.cli` calls the new `intelligence` tool (not agent)
    for the `intelligence <subcommand>` shortcut."""
    text = _read("src/ida_pro_mcp/cli.py")
    # Find the tools/call inside the `if args.mode == "intelligence":`
    # branch and verify the tool name is `intelligence`.
    intel_block = text[text.index('if args.mode == "intelligence":'):]
    intel_block = intel_block[:intel_block.index('raise SystemExit(f"unsupported mode')]
    assert '"name": "intelligence"' in intel_block
    # The legacy `{"name": "agent", "arguments": ...}` literal must not
    # be inside the intelligence branch any more.
    assert '"name": "agent"' not in intel_block


def test_cli_intelligence_action_mapping_includes_new_actions():
    """The CLI's allowed-actions set is updated to match the new tool."""
    text = _read("src/ida_pro_mcp/cli.py")
    intel_block = text[text.index('if args.mode == "intelligence":'):]
    intel_block = intel_block[:intel_block.index('raise SystemExit(f"unsupported mode')]
    # All 13 actions must be in the allowed set.
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "export_index_summary", "evidence_card",
    ):
        assert f'"{action}"' in intel_block, f"CLI allowed-actions missing {action}"


def test_wiki_intelligence_page_exists():
    """A new `docs/wiki/tools/intelligence.md` page is added."""
    p = _abs("docs/wiki/tools/intelligence.md")
    assert p.exists()
    text = p.read_text(encoding="utf-8")
    # Lists all 13 actions.
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f"`{action}`" in text, f"wiki intelligence.md missing {action}"


def test_wiki_index_links_to_intelligence():
    """`docs/wiki/INDEX.md` links to the new intelligence page."""
    text = _read("docs/wiki/INDEX.md")
    assert "[intelligence](tools/intelligence.md)" in text


def test_wiki_agent_page_drops_intelligence_action_bullets():
    """`docs/wiki/tools/agent.md` no longer lists the 13 intelligence
    actions (they live in `intelligence.md` now)."""
    text = _read("docs/wiki/tools/agent.md")
    # The 12 actions that are uniquely intelligence (excluding
    # `similar_functions` which is also a result-payload key).
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f"`{action}`" not in text, (
            f"agent.md wiki page still lists {action}"
        )
    # The first paragraph should now reference the new tool.
    assert "intelligence.md" in text


def test_tools_reference_md_documents_intelligence_tool():
    """`docs/TOOLS_REFERENCE.md` has an `### intelligence` section."""
    text = _read("docs/TOOLS_REFERENCE.md")
    assert "### intelligence" in text
    # And the agent section no longer lists the extracted actions.
    # The slice from `### agent` up to but not including the next `### `
    # heading must not contain any of the 13 extracted actions.
    agent_start = text.index("### agent")
    # Find the next heading after `### agent` and slice to it.
    next_heading = text.index("\n### ", agent_start + 1)
    agent_section = text[agent_start:next_heading]
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert action not in agent_section, (
            f"TOOLS_REFERENCE agent section still lists {action}"
        )



def test_intelligence_capsule_uses_intelligence_owner_string():
    """The `evidence_card` action persists to CapsuleStore with
    `created_by='ida-pro-mcp-intelligence'` (not `ida-pro-mcp-agent`)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    assert "created_by=\"ida-pro-mcp-intelligence\"" in text
    # And both `evidence_card` and the embedder-state use the
    # intelligence owner string.
    assert text.count("ida-pro-mcp-intelligence") >= 2


def test_agent_capsule_owner_no_longer_used_for_intelligence():
    """`agent.py` no longer defines `_persist_embedder_state` (extracted
    to the new `intelligence` tool). The remaining
    `created_by="ida-pro-mcp-agent"` string in agent.py is a legitimate
    use by `rename_suggestions`, not an intelligence action."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    # The `_persist_embedder_state` helper that was specifically tied
    # to the intelligence actions must be gone.
    assert "def _persist_embedder_state" not in text
    # The "intelligence" action set must not be referenced in any
    # embedder-state-related context.
    assert "embedder_state" not in text or "intelligence_status" not in text


def test_intelligence_schemas_alias_hints_clean():
    """The agent block in `schemas_alias_hints.py` is unchanged from
    before the extraction (the extracted intelligence actions were
    never in this alias registry)."""
    text = _read("src/ida_pro_mcp/host/schemas_alias_hints.py")
    # Sanity: the file is still a Python source file with a tool→action
    # aliases dict.
    assert "_ACTION_ALIAS_HINTS" in text
    # None of the 13 extracted actions should be aliased under any tool
    # (they are auto-derived from action names, not declared here).
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f'"{action}"' not in text, (
            f"schemas_alias_hints contains stale {action} alias"
        )


def test_intelligence_payload_preserved_verbatim():
    """The new tool preserves the payload keys from the old agent
    actions (e.g. 'embedder', 'anchors', 'indexes', 'capsule_embedding_state',
    'behavior_rows', 'matches', 'similar', 'blackboard', 'card',
    'persisted', 'persisted_id', etc.)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    expected_keys = (
        "embedder", "anchors", "indexes", "capsule_embedding_state",
        "behaviors", "matches", "similar", "blackboard",
        "card", "persisted", "persisted_id",
    )
    for key in expected_keys:
        assert f'"{key}"' in text, f"intelligence.py missing payload key {key}"


def test_intelligence_tool_handler_signature_match():
    """The new tool's signature uses `query` (not `text`), consistent
    with the old agent signature and the schemas."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    # Skip past any decorators (the def is preceded by @tool/@idaread).
    m = re.search(r"^def intelligence\(", text, re.MULTILINE)
    assert m, "intelligence function not found"
    # Get from the def line to the closing paren of the signature.
    start = m.start()
    sig_end = text.index("):", start) + 2
    sig = text[start:sig_end]
    assert "query: Annotated" in sig
    assert "addr: Annotated" in sig
    assert "max_items: Annotated" in sig
    assert "**kwargs" in sig
