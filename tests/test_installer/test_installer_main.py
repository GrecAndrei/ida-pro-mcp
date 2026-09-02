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
