from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall
from ida_pro_mcp.installer.main import (
    UI,
    _format_install_table,
    _is_interactive_terminal,
    _prompt_choice,
    _prompt_text,
    _prompt_yes_no,
    main,
    parse_args,
    run_embedder_doctor,
)


def test_ui_methods(capsys: pytest.CaptureFixture) -> None:
    ui = UI()
    ui.info("info message")
    ui.ok("ok message")
    ui.warn("warn message")
    ui.err("err message")

    out, _ = capsys.readouterr()
    assert "info message" in out
    assert "ok message" in out
    assert "warn message" in out
    assert "err message" in out


def test_interactive_prompts() -> None:
    # Test _prompt_yes_no with "y"
    with patch("builtins.input", return_value="y"):
        assert _prompt_yes_no("Continue?", default=True) is True

    # Test _prompt_yes_no with "n"
    with patch("builtins.input", return_value="n"):
        assert _prompt_yes_no("Continue?", default=True) is False

    # Test _prompt_yes_no default fallback on empty
    with patch("builtins.input", return_value=""):
        assert _prompt_yes_no("Continue?", default=True) is True
        assert _prompt_yes_no("Continue?", default=False) is False

    # Test _prompt_choice
    choices = ["Option A", "Option B"]
    with patch("builtins.input", return_value="1"):
        assert _prompt_choice("Pick one", choices, default="Option A") == "Option A"
    with patch("builtins.input", return_value="2"):
        assert _prompt_choice("Pick one", choices, default="Option A") == "Option B"

    # Test _prompt_text
    with patch("builtins.input", return_value="user text"):
        assert _prompt_text("Enter name", default="default") == "user text"
    with patch("builtins.input", return_value=""):
        assert _prompt_text("Enter name", default="default") == "default"


def test_format_install_table(tmp_path: Path) -> None:
    inst1 = IdaInstall(
        path=tmp_path / "ida93",
        version=(9, 3),
        build="260421.be7de18d",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="env",
    )
    formatted = _format_install_table([inst1])
    assert "9.3" in formatted


def test_parse_args() -> None:
    opts = parse_args(["--dry-run", "--ida-dir", "/opt/ida", "--yes"])
    assert opts.dry_run is True
    assert opts.yes is True
    assert opts.ida_dir == "/opt/ida"


def test_run_embedder_doctor(tmp_path: Path) -> None:
    opts = InstallerOptions(
        install_root=tmp_path / "install_root",
        embed_auto=False,
    )
    ui = UI()
    with patch("ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder") as mock_emb:
        instance = MagicMock()
        instance.status.return_value = {"ready": False, "mode": "none"}
        mock_emb.return_value = instance

        rc = run_embedder_doctor(opts, ui)
        assert rc in (0, 1)


def test_main_skills_only(tmp_path: Path) -> None:
    with patch("ida_pro_mcp.installer.main.run_install", return_value=0):
        rc = main(["--only", "skills", "--dry-run"])
        assert rc == 0


def test_main_bron_corpus(tmp_path: Path) -> None:
    with patch("ida_pro_mcp.installer.bron_corpus.download_bron_corpus", return_value={"built": True}):
        rc = main(["--with-corpus", "--dry-run"])
        assert rc == 0


def test_parse_args_auto_and_uninstall() -> None:
    opts_auto = parse_args(["--auto"])
    assert opts_auto.yes is True
    assert opts_auto.uninstall is False

    opts_un = parse_args(["--uninstall"])
    assert opts_un.uninstall is True


def test_main_uninstall(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    bin_dir = install_root / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "ida-pro-mcp").write_text("shim")

    with (
        patch("ida_pro_mcp.installer.clients.remove_server_entry_from_clients", return_value=["Cursor"]),
        patch("ida_pro_mcp.installer.discovery.detect_ida_installs", return_value=[]),
        patch("ida_pro_mcp.installer.skills.default_skill_dirs", return_value=[tmp_path / "skills"]),
    ):
        rc = main(["--uninstall", "--install-root", str(install_root)])
        assert rc == 0
        assert not (bin_dir / "ida-pro-mcp").exists()


def test_install_codex_skills_reuses_checkout_symlinks_in_packaged_mode(tmp_path: Path, monkeypatch) -> None:
    from ida_pro_mcp.installer.main import install_codex_skills

    # Create dummy checkout skill structure
    repo_root = tmp_path / "checkout"
    git_dir = repo_root / ".git"
    git_dir.mkdir(parents=True)
    skill_src = repo_root / ".agents" / "skills" / "ida-pro-mcp"
    skill_src.mkdir(parents=True)
    (skill_src / "SKILL.md").write_text("# Test Skill\n")
    (skill_src / "references").mkdir()
    (skill_src / "references" / "operations.md").write_text("# Ops\n")

    codex_home = tmp_path / "codex"
    codex_skills = codex_home / "skills"
    codex_skills.mkdir(parents=True)
    skill_link = codex_skills / "ida-pro-mcp"
    skill_link.symlink_to(skill_src, target_is_directory=True)
    assert skill_link.is_symlink()

    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    report = InstallReport()
    # In packaged mode (source_root has no .agents/skills/ida-pro-mcp)
    packaged_root = tmp_path / "empty_source"
    packaged_root.mkdir()

    install_codex_skills(packaged_root, "agent", report, dry_run=True)
    # The checkout link should be kept intact and acknowledged
    assert skill_link.is_symlink()
    assert any("checkout-backed" in step.get("detail", "") for step in report.steps)
