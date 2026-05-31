from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_agent_tool_exposes_intelligence_actions():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    assert "\"intelligence_status\"" in src
    assert "\"embedder_status\"" in src
    assert "\"anchor_status\"" in src
    assert "\"refresh_anchors\"" in src
    assert "\"classify_text\"" in src
    assert "\"classify_function\"" in src
    assert "\"index_function\"" in src
    assert "\"index_batch\"" in src
    assert "\"similar_functions\"" in src
    assert "\"export_index_summary\"" in src
    assert "\"evidence_card\"" in src


def test_agent_intelligence_status_reports_anchor_hash_and_index_counts():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    assert "\"anchor_set_hash\"" in src
    assert "\"functions_indexed\"" in src
    assert "embedder.status(probe=bool(kwargs.get(\"probe\", False))" in src


def test_agent_schemas_include_intelligence_actions():
    src = _read("src/ida_pro_mcp/host/schemas_data.py")
    assert "\"intelligence_status\"" in src
    assert "\"classify_text\"" in src
    assert "\"similar_functions\"" in src
    assert "\"export_index_summary\"" in src
    assert "\"evidence_card\"" in src
