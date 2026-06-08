from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_intelligence_tool_exposes_intelligence_actions():
    """All 13 actions previously under `agent.intelligence_*` now live in
    a dedicated `intelligence` tool, extracted in the dedup pass."""
    src = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    assert "\"intelligence_status\"" in src
    assert "\"embedder_status\"" in src
    assert "\"anchor_status\"" in src
    assert "\"refresh_anchors\"" in src
    assert "\"classify_text\"" in src
    assert "\"classify_function\"" in src
    assert "\"index_function\"" in src
    assert "\"index_batch\"" in src
    assert "\"similar_functions\"" in src
    assert "\"semantic_search\"" in src
    assert "\"blackboard_search\"" in src
    assert "\"export_index_summary\"" in src
    assert "\"evidence_card\"" in src


def test_intelligence_status_reports_anchor_hash_and_index_counts():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/intelligence.py")
    assert "\"anchor_set_hash\"" in src
    assert "\"functions_indexed\"" in src
    assert "embedder.status(probe=bool(kwargs.get(\"probe\", False))" in src


def test_evidence_card_uses_backend_neutral_source_ref_shape():
    src = Path("src/ida_pro_mcp/ida_mcp/tools/intelligence.py").read_text(encoding="utf-8")
    assert '"object_kind": "function"' in src
    assert '"stable_ref": hex(ea)' in src
    assert '"backend": "ida"' in src


def test_agent_tool_no_longer_exposes_intelligence_actions():
    """`agent` tool's Literal enum no longer includes the 13 intelligence
    actions after extraction. The dispatcher in `agent.py` no longer
    routes them — they all live in the new `intelligence` tool."""
    src = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    # No references to these as the Literal enum entries (which are
    # always inside action=Literal[...] or elif action in (...)) — but
    # `similar_functions` is also a result-payload key in `similar`/
    # `bridge_query` actions, so we restrict the negative to the dispatcher.
    dispatcher_block = src[src.index("try:"):]
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f"\"{action}\"" not in dispatcher_block, f"agent.py dispatcher still references {action}"
    # `similar_functions` may only appear in `intelligence` tool, not in `agent` dispatcher.
    for action in ("similar_functions",):
        # The Literal enum/dispatcher must not include it; it can still
        # appear in result-payload dicts (which is fine, those are
        # backward-compatible keys).
        lit_idx = src.find("action: Annotated[Literal[")
        enum_block = src[lit_idx:lit_idx + 2000]
        assert f"\"{action}\"" not in enum_block, f"agent.py Literal enum still references {action}"


def test_agent_schemas_drop_intelligence_actions():
    src = _read("src/ida_pro_mcp/host/tool_registry.py")
    # agent section in TOOL_ACTIONS no longer contains these.
    agent_start = src.index('"agent": [')
    agent_end = src.index('],', agent_start)
    agent_block = src[agent_start:agent_end]
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f'"{action}"' not in agent_block, f"agent schema still lists {action}"


def test_intelligence_schemas_added_to_schemas_data():
    # TOOL_ACTIONS block now lives in tool_registry.py; TOOL_DESCRIPTIONS
    # and aliases remain in schemas_data.py.
    treg = _read("src/ida_pro_mcp/host/tool_registry.py")
    int_start = treg.index('"intelligence": [')
    int_end = treg.index('],', int_start)
    int_block = treg[int_start:int_end]
    for action in (
        "intelligence_status", "embedder_status", "anchor_status",
        "refresh_anchors", "classify_text", "classify_function",
        "index_function", "index_batch", "similar_functions",
        "semantic_search", "blackboard_search", "export_index_summary",
        "evidence_card",
    ):
        assert f'"{action}"' in int_block, f"intelligence schema missing {action}"
    # Description in TOOL_DESCRIPTIONS (still in schemas_data.py).
    sdata = _read("src/ida_pro_mcp/host/schemas_data.py")
    assert "intelligence_status, embedder_status" in sdata


def test_intelligence_added_to_tools_list():
    src = _read("src/ida_pro_mcp/host/schemas_data.py")
    # The tools list and advertised-tools list both contain "intelligence".
    tools_block = src.split("ADVERTISED_TOOLS")[0]
    assert '"intelligence"' in tools_block
    assert '"intelligence"' in src.split("ADVERTISED_TOOLS")[1]
