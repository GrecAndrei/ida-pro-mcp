"""Exercise installer CLI, wizard, and reporting branches offline."""

from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.installer import main as installer
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall


def _install(path: Path, version: tuple[int, int] = (9, 3)) -> IdaInstall:
    path.mkdir(parents=True, exist_ok=True)
    return IdaInstall(
        path=path,
        version=version,
        build="test",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="test",
    )


def test_idalib_activation_and_bashrc_platform_boundaries(tmp_path, monkeypatch):
    install = _install(tmp_path / "ida")
    report = InstallReport()
    opts = InstallerOptions(ida_runtime="idalib", dry_run=True)
    installer._activate_idalib_after_install(opts, install, report, installer.UI())
    assert report.steps[-1]["status"] == "dry-run"

    monkeypatch.setattr(installer.sys, "platform", "win32")
    report = InstallReport()
    assert installer.install_bashrc_cli(tmp_path / "install", False, report) is False
    assert report.warnings
