"""The installed agent skill must carry its reference material with it."""

from __future__ import annotations

import pytest

from ida_pro_mcp.installer.common import InstallReport
from ida_pro_mcp.installer.main import install_codex_skills
from ida_pro_mcp.installer.skills import install_skills


def test_agent_skill_install_contains_the_reference_tree(monkeypatch, tmp_path):
    source_root = tmp_path / "source"
    skill_root = source_root / ".agents" / "skills" / "ida-pro-mcp"
    reference = skill_root / "references" / "operations.md"
    reference.parent.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    reference.write_text("# Operations\n", encoding="utf-8")
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    report = InstallReport()
    install_codex_skills(source_root, "agent", report, dry_run=False)

    installed = codex_home / "skills" / "ida-pro-mcp"
    assert (installed / "SKILL.md").is_file()
    assert (installed / "references" / "operations.md").is_file()
    assert not report.warnings


def test_portable_installer_writes_the_skill_and_reference_together(tmp_path):
    written = install_skills([tmp_path])

    installed = tmp_path / "ida-pro-mcp"
    # Both files are reported so caller bookkeeping (counts, backup, rollback)
    # covers the reference document too, not just SKILL.md.
    assert written["ida-pro-mcp"] == [
        installed / "SKILL.md",
        installed / "references" / "operations.md",
    ]
    assert (installed / "SKILL.md").is_file()
    assert (installed / "references" / "operations.md").is_file()


def test_checkout_backed_codex_skill_link_is_reused(monkeypatch, tmp_path):
    source_root = tmp_path / "source"
    skill = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    (skill / "references").mkdir()
    (skill / "references" / "operations.md").write_text("# Operations\n", encoding="utf-8")

    codex_home = tmp_path / "codex"
    destination = codex_home / "skills" / "ida-pro-mcp"
    destination.parent.mkdir(parents=True)
    destination.symlink_to(skill, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    report = InstallReport()
    install_codex_skills(source_root, "agent", report, dry_run=False)

    assert destination.is_symlink()
    assert destination.resolve() == skill.resolve()
    assert not report.warnings
    assert "checkout-backed skill link" in report.steps[-1]["detail"]


def test_unrelated_codex_skill_symlink_is_rejected(monkeypatch, tmp_path):
    source_root = tmp_path / "source"
    skill = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Skill\n", encoding="utf-8")

    codex_home = tmp_path / "codex"
    redirect = tmp_path / "redirect"
    redirect.mkdir()
    destination = codex_home / "skills" / "ida-pro-mcp"
    destination.parent.mkdir(parents=True)
    destination.symlink_to(redirect, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    with pytest.raises(RuntimeError, match="Refusing symlinked skill installation path"):
        install_codex_skills(source_root, "agent", InstallReport(), dry_run=False)
