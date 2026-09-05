"""The installed agent skill must carry its reference material with it."""

from __future__ import annotations

import os
from pathlib import Path

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


def test_checkout_backed_codex_skill_link_is_reused(monkeypatch, tmp_path):
    source_root = tmp_path / "source"
    skill_root = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill_root.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    (skill_root / "references").mkdir()
    (skill_root / "references" / "operations.md").write_text("# Operations\n", encoding="utf-8")
    codex_home = tmp_path / "codex"
    destination = codex_home / "skills" / "ida-pro-mcp"
    destination.parent.mkdir(parents=True)
    destination.symlink_to(skill_root, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    report = InstallReport()
    install_codex_skills(source_root, "agent", report, dry_run=False)

    assert destination.is_symlink()
    assert destination.resolve() == skill_root.resolve()
    assert any("checkout-backed skill link" in step["detail"] for step in report.steps)


def test_generated_skill_link_is_reused_when_source_is_a_snapshot(monkeypatch, tmp_path):
    snapshot = tmp_path / "snapshot"
    skill_root = snapshot / ".agents" / "skills" / "ida-pro-mcp"
    skill_root.mkdir(parents=True)
    from ida_pro_mcp.host.agent_operations import (
        render_agent_operations_markdown,
        render_agent_skill_markdown,
    )

    (skill_root / "SKILL.md").write_text(render_agent_skill_markdown(), encoding="utf-8")
    (skill_root / "references").mkdir()
    (skill_root / "references" / "operations.md").write_text(
        render_agent_operations_markdown(), encoding="utf-8"
    )

    codex_home = tmp_path / "codex"
    destination = codex_home / "skills" / "ida-pro-mcp"
    destination.parent.mkdir(parents=True)
    checkout_skill = tmp_path / "checkout" / ".agents" / "skills" / "ida-pro-mcp"
    checkout_skill.mkdir(parents=True)
    (checkout_skill.parent.parent.parent / ".git").mkdir()
    (checkout_skill / "SKILL.md").write_text("# Checkout skill\n", encoding="utf-8")
    (checkout_skill / "references").mkdir()
    (checkout_skill / "references" / "operations.md").write_text(
        "# Checkout operations\n", encoding="utf-8"
    )
    destination.symlink_to(checkout_skill, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    report = InstallReport()
    install_codex_skills(snapshot, "agent", report, dry_run=False)

    assert destination.is_symlink()
    assert destination.resolve() == checkout_skill.resolve()
    assert any("checkout-backed skill link" in step["detail"] for step in report.steps)


def test_codex_skill_link_to_unrelated_directory_is_still_rejected(monkeypatch, tmp_path):
    source_root = tmp_path / "source"
    skill_root = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill_root.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    codex_home = tmp_path / "codex"
    destination = codex_home / "skills" / "ida-pro-mcp"
    destination.parent.mkdir(parents=True)
    destination.symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    with pytest.raises(RuntimeError, match="symlinked skill installation path"):
        install_codex_skills(source_root, "agent", InstallReport(), dry_run=False)
    assert not (outside / "SKILL.md").exists()


def test_packaged_installer_generates_codex_skill_without_repository_tree(
    monkeypatch, tmp_path
):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    report = InstallReport()
    install_codex_skills(tmp_path / "packaged-source", "agent", report, dry_run=False)

    installed = codex_home / "skills" / "ida-pro-mcp"
    assert (installed / "SKILL.md").is_file()
    assert (installed / "references" / "operations.md").is_file()
    assert not report.warnings


def test_empty_codex_home_uses_the_default_home_directory(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("CODEX_HOME", "")

    install_codex_skills(tmp_path / "packaged-source", "agent", InstallReport(), dry_run=False)

    assert (home / ".codex" / "skills" / "ida-pro-mcp" / "SKILL.md").is_file()


def test_blank_codex_home_uses_the_default_home_directory(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("CODEX_HOME", "   ")

    install_codex_skills(tmp_path / "packaged-source", "agent", InstallReport(), dry_run=False)

    assert (home / ".codex" / "skills" / "ida-pro-mcp" / "SKILL.md").is_file()


def test_codex_home_expands_environment_path(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_SKILL_ROOT", str(tmp_path))
    monkeypatch.setenv("CODEX_HOME", "$CODEX_SKILL_ROOT/codex")

    install_codex_skills(tmp_path / "packaged-source", "agent", InstallReport(), dry_run=False)

    assert (tmp_path / "codex" / "skills" / "ida-pro-mcp" / "SKILL.md").is_file()


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


def test_portable_installer_rejects_symlinked_skill_destination(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "skills"
    target.mkdir()
    (target / "ida-pro-mcp").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked skill installation path"):
        install_skills([target])

    assert not (outside / "SKILL.md").exists()


def test_portable_installer_rejects_symlinked_skill_reference_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "skills"
    target.mkdir()
    skill_dir = target / "ida-pro-mcp"
    skill_dir.mkdir()
    (skill_dir / "references").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked skill reference installation path"):
        install_skills([target])

    assert not (outside / "operations.md").exists()


def test_skill_refresh_preserves_user_files_and_publishes_as_one_directory(tmp_path, monkeypatch):
    skill_dir = tmp_path / "ida-pro-mcp"
    references = skill_dir / "references"
    references.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("old skill", encoding="utf-8")
    (references / "operations.md").write_text("old reference", encoding="utf-8")
    (skill_dir / "user-notes.md").write_text("keep me", encoding="utf-8")

    real_replace = os.replace
    failed = False

    def _fail_publish(source, target):
        nonlocal failed
        if Path(target) == skill_dir and not failed:
            failed = True
            raise OSError("publish failed")
        return real_replace(source, target)

    monkeypatch.setattr("ida_pro_mcp.installer.skills.os.replace", _fail_publish)

    with pytest.raises(OSError, match="publish failed"):
        install_skills([tmp_path])

    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == "old skill"
    assert (references / "operations.md").read_text(encoding="utf-8") == "old reference"
    assert (skill_dir / "user-notes.md").read_text(encoding="utf-8") == "keep me"


def test_multi_target_skill_install_rolls_back_when_later_target_fails(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import skills

    first_root = tmp_path / "first"
    first_skill = first_root / skills.SKILL_NAME
    first_skill.mkdir(parents=True)
    (first_skill / "SKILL.md").write_text("first old", encoding="utf-8")
    second_root = tmp_path / "second"

    real_publish = skills.install_skills.__globals__["_publish_skill"]

    def fail_second(skill_dir, skill_text, reference_text):
        if Path(skill_dir) == second_root / skills.SKILL_NAME:
            raise OSError("second target unavailable")
        return real_publish(skill_dir, skill_text, reference_text)

    monkeypatch.setitem(skills.install_skills.__globals__, "_publish_skill", fail_second)

    with pytest.raises(OSError, match="second target unavailable"):
        skills.install_skills([first_root, second_root])

    assert (first_skill / "SKILL.md").read_text(encoding="utf-8") == "first old"
    assert not (second_root / skills.SKILL_NAME).exists()
    assert not list(first_root.glob(".*transaction-backup-*"))


def test_publish_skill_rejects_non_directory(tmp_path):
    from ida_pro_mcp.installer import skills
    target = tmp_path / "skills"
    target.mkdir()
    non_dir = target / skills.SKILL_NAME
    non_dir.write_text("not a directory")
    with pytest.raises(RuntimeError, match="Skill installation path is not a directory"):
        skills._publish_skill(non_dir, "skill", "ref")


def test_publish_skill_unlinks_staged_symlinks(tmp_path):
    from ida_pro_mcp.installer import skills
    target = tmp_path / "skills"
    target.mkdir()
    skill_dir = target / skills.SKILL_NAME
    skill_dir.mkdir()
    outside_skill = tmp_path / "outside.md"
    outside_skill.write_text("outside")
    # Symlink at SKILL.md
    (skill_dir / "SKILL.md").symlink_to(outside_skill)
    # Perform publish
    skills._publish_skill(skill_dir, "new skill", "new ref")
    assert not (skill_dir / "SKILL.md").is_symlink()
    assert (skill_dir / "SKILL.md").read_text() == "new skill"



def test_default_skill_dirs_with_candidates(monkeypatch, tmp_path):
    from ida_pro_mcp.installer.skills import default_skill_dirs
    home = tmp_path / "home"
    home.mkdir()
    (home / ".codex").mkdir()
    (home / ".openclaw").mkdir()
    (home / ".pi").mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    dirs = default_skill_dirs()
    dir_strs = [str(d) for d in dirs]
    assert str(home / ".codex" / "skills") in dir_strs
    assert str(home / ".openclaw" / "workspace" / "skills") in dir_strs
    assert str(home / ".pi" / "agent" / "skills") in dir_strs


def test_install_skills_rollback_failure_raises_runtime_error(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import skills
    first_root = tmp_path / "first"
    first_skill = first_root / skills.SKILL_NAME
    first_skill.mkdir(parents=True)
    (first_skill / "SKILL.md").write_text("old", encoding="utf-8")
    second_root = tmp_path / "second"

    real_publish = skills.install_skills.__globals__["_publish_skill"]

    def fail_second(skill_dir, skill_text, reference_text):
        if Path(skill_dir) == second_root / skills.SKILL_NAME:
            raise OSError("second failed")
        return real_publish(skill_dir, skill_text, reference_text)

    monkeypatch.setitem(skills.install_skills.__globals__, "_publish_skill", fail_second)

    # Make rollback fail by breaking os.replace during rollback
    real_replace = os.replace
    def broken_replace(src, dst):
        if "backup" in str(src):
            raise RuntimeError("rollback disk failure")
        return real_replace(src, dst)

    monkeypatch.setattr("os.replace", broken_replace)
    with pytest.raises(RuntimeError, match="skill installation failed and rollback was incomplete"):
        skills.install_skills([first_root, second_root])


def test_install_skills_rollback_file_target(tmp_path, monkeypatch):
    import shutil

    from ida_pro_mcp.installer import skills
    root = tmp_path / "root"
    skill_dir = root / skills.SKILL_NAME
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("old")
    second = tmp_path / "second"

    real_publish = skills.install_skills.__globals__["_publish_skill"]
    def fail_second(sdir, stext, rtext):
        if Path(sdir) == second / skills.SKILL_NAME:
            shutil.rmtree(skill_dir)
            skill_dir.write_text("now a file")
            raise OSError("fail second")
        return real_publish(sdir, stext, rtext)

    monkeypatch.setitem(skills.install_skills.__globals__, "_publish_skill", fail_second)
    with pytest.raises(OSError, match="fail second"):
        skills.install_skills([root, second])
