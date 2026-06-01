from __future__ import annotations

from pathlib import Path


def test_agent_rename_suggestions_exposes_evidence_and_suggestion_fields():
    src = Path("src/ida_pro_mcp/ida_mcp/tools/agent.py").read_text(encoding="utf-8")
    assert 'elif action == "rename_suggestions"' in src
    assert "from .funcs import _embedding_rename_suggestions" in src
    assert '"suggestions"' in src
    assert '"suggested_name"' in src
    assert '"confidence"' in src
    assert 'persist_blackboard' in src
    assert 'persist_capsule' in src
    assert 'category="rename_suggestion"' in src
