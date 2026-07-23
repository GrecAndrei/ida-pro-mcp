"""Generated public-operation docs must stay aligned with the MCP contract."""

from __future__ import annotations

import re
from pathlib import Path

from ida_pro_mcp.host.agent_operations import list_agent_operations, render_agent_operations_markdown

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_readme_describes_the_agent_operation_surface():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "action-specific `ida_*` operations" in text
    assert "ida_help" in text


def test_tools_reference_is_generated_from_the_public_operation_contract():
    reference = REPO_ROOT / "docs" / "TOOLS_REFERENCE.md"
    generated = reference.read_text(encoding="utf-8")
    assert generated.replace("<!-- GENERATED: scripts/generate_tool_skills.py -->\n", "") == render_agent_operations_markdown()


def test_skill_markdown_is_generated_from_the_public_operation_contract():
    from ida_pro_mcp.host.agent_operations import render_agent_skill_markdown

    skill = REPO_ROOT / ".agents" / "skills" / "ida-pro-mcp" / "SKILL.md"
    generated = skill.read_text(encoding="utf-8")
    assert generated.replace("<!-- GENERATED: scripts/generate_tool_skills.py -->\n", "") == render_agent_skill_markdown()


def test_every_public_operation_is_documented_once():
    text = (REPO_ROOT / "docs" / "TOOLS_REFERENCE.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## `(ida_[a-z_]+)`$", text, flags=re.MULTILINE)
    names = [operation.name for operation in list_agent_operations()]
    assert headings == names
    assert len(headings) == len(set(headings))
