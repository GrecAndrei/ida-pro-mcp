"""Unit tests for scripts/generate_tool_skills.py."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import generate_tool_skills


def test_generate_tool_skills_content_helpers():
    skill = generate_tool_skills._skill_content()
    assert generate_tool_skills.GEN_MARKER in skill
    assert "ida_open_binary" in skill
    assert "ida_session_state" in skill

    ref = generate_tool_skills._reference_content()
    assert generate_tool_skills.GEN_MARKER in ref
    assert "ida_decompile" in ref

    readme = generate_tool_skills._readme_content()
    assert generate_tool_skills.GEN_MARKER in readme
    assert "AGENTS.md" in readme


def test_generate_tool_skills_write(tmp_path):
    target = tmp_path / "nested" / "doc.md"
    generate_tool_skills._write(target, "# Title\nContent")
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == "# Title\nContent"


def test_remove_obsolete_generated_layout(tmp_path, monkeypatch):
    old_router = tmp_path / "ida-tool-router"
    old_docs = tmp_path / ".agents" / "tool-docs"
    old_router.mkdir(parents=True)
    (old_router / "file.txt").write_text("x")
    old_docs.mkdir(parents=True)
    (old_docs / "doc.txt").write_text("y")

    monkeypatch.setattr(generate_tool_skills, "SKILLS_ROOT", tmp_path)
    monkeypatch.setattr(generate_tool_skills, "REPO_ROOT", tmp_path)

    generate_tool_skills._remove_obsolete_generated_layout()
    assert not old_router.exists()
    assert not old_docs.exists()


def test_generate_tool_skills_main_isolated(tmp_path, monkeypatch, capsys):
    skills_root = tmp_path / ".agents" / "skills"
    skill_root = skills_root / "ida-pro-mcp"
    ref_path = skill_root / "references" / "operations.md"
    doc_ref_path = tmp_path / "docs" / "TOOLS_REFERENCE.md"

    monkeypatch.setattr(generate_tool_skills, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(generate_tool_skills, "SKILLS_ROOT", skills_root)
    monkeypatch.setattr(generate_tool_skills, "SKILL_ROOT", skill_root)
    monkeypatch.setattr(generate_tool_skills, "REFERENCE_PATH", ref_path)
    monkeypatch.setattr(generate_tool_skills, "DOC_REFERENCE_PATH", doc_ref_path)

    rc = generate_tool_skills.main()
    assert rc == 0
    assert (skill_root / "SKILL.md").is_file()
    assert ref_path.is_file()
    assert doc_ref_path.is_file()
    assert (skills_root / "README.md").is_file()

    captured = capsys.readouterr()
    assert "Generated" in captured.out
