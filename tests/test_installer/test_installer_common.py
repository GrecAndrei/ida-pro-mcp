from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from ida_pro_mcp.installer.common import (
    InstallerOptions,
    InstallReport,
    SigsManifest,
    atomic_write_bytes,
    atomic_write_text,
    find_ida_sig_dir,
    installer_lock,
    reject_symlink_path,
)


def test_reject_symlink_path_valid(tmp_path: Path) -> None:
    regular_file = tmp_path / "regular.txt"
    regular_file.write_text("hello", encoding="utf-8")
    reject_symlink_path(regular_file, "regular path")
    reject_symlink_path(tmp_path / "nonexistent.txt", "nonexistent path")


def test_reject_symlink_path_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("hello", encoding="utf-8")
    symlink = tmp_path / "symlink.txt"
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")

    with pytest.raises(RuntimeError, match="Refusing symlinked test target"):
        reject_symlink_path(symlink, "test target")


def test_reject_symlink_path_symlink_parent(tmp_path: Path) -> None:
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    symlink_dir = tmp_path / "symlink_dir"
    try:
        symlink_dir.symlink_to(real_dir)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")

    nested = symlink_dir / "nested.txt"
    with pytest.raises(RuntimeError, match="Refusing symlinked nested target"):
        reject_symlink_path(nested, "nested target")


def test_atomic_write_text_and_bytes(tmp_path: Path) -> None:
    target_text = tmp_path / "subdir" / "sample.txt"
    atomic_write_text(target_text, "Hello, world! 🚀")
    assert target_text.read_text(encoding="utf-8") == "Hello, world! 🚀"

    target_bytes = tmp_path / "sample.bin"
    atomic_write_bytes(target_bytes, b"\x00\x01\x02\xfe\xff")
    assert target_bytes.read_bytes() == b"\x00\x01\x02\xfe\xff"


def test_atomic_write_permission_error_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    with (
        patch("os.replace", side_effect=OSError("replace failed")),
        pytest.raises(OSError, match="replace failed"),
    ):
        atomic_write_text(target, "fail")
    tmp_files = list(tmp_path.glob(".file.txt.tmp-*"))
    assert len(tmp_files) == 0


def test_installer_lock_success(tmp_path: Path) -> None:
    root = tmp_path / "install_root"
    with installer_lock(root) as lock_file:
        assert lock_file.exists()
        assert lock_file.name == ".install.lock"


def test_installer_lock_reentrancy_conflict(tmp_path: Path) -> None:
    root = tmp_path / "install_root"
    with (
        installer_lock(root),
        pytest.raises(RuntimeError, match="Another installer is already running"),
        installer_lock(root),
    ):
        pass


def test_installer_lock_symlink_rejection(tmp_path: Path) -> None:
    root = tmp_path / "install_root"
    root.mkdir()
    target_lock = tmp_path / "other_lock"
    target_lock.write_text("x", encoding="utf-8")
    symlink_lock = root / ".install.lock"
    try:
        symlink_lock.symlink_to(target_lock)
    except OSError:
        pytest.skip("Symlinks not supported")

    with (
        pytest.raises(RuntimeError, match="Refusing symlinked installer lock path"),
        installer_lock(root),
    ):
        pass


def test_install_report_lifecycle(tmp_path: Path) -> None:
    report = InstallReport()
    report.add_step("step1", "ok", "detail1")
    report.add_warning("warn1")
    report.add_error("err1")
    report.add_backup(tmp_path / "cfg.json", tmp_path / "cfg.json.bak")
    report.add_created(tmp_path / "created.txt")
    report.add_created(tmp_path / "created.txt")  # deduplicated
    report.add_modified(tmp_path / "modified.txt")
    assert len(report.created_files) == 1
    assert len(report.modified_files) == 1

    report.finalize(success=True)
    assert report.status == "ok"
    assert report.finished_at is not None

    report_path = tmp_path / "report.json"
    report.write(report_path)
    assert report_path.is_file()

    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["status"] == "ok"
    assert len(saved["steps"]) == 1
    assert saved["warnings"] == ["warn1"]
    assert saved["errors"] == ["err1"]
    assert len(saved["backups"]) == 1


def test_installer_options_defaults() -> None:
    options = InstallerOptions()
    assert options.dry_run is False
    assert options.runtime_source == "auto"
    assert options.skills_mode == "agent"
    assert options.ida_runtime == "idat"
    assert options.rollback_on_fail is True


def test_find_ida_sig_dir_and_sigs_manifest() -> None:
    ida_dir = Path("/opt/ida-pro-9.3")
    sig_dir = find_ida_sig_dir(ida_dir)
    assert sig_dir == Path("/opt/ida-pro-9.3/sig")

    manifest = SigsManifest(
        source="/tmp/sigs",
        sig_dir=str(sig_dir),
        staged=["sig1.sig", "sig2.sig"],
        skipped=["sig3.sig"],
        dry_run=True,
    )
    assert manifest.count == 2
    d = manifest.to_dict()
    assert d["source"] == "/tmp/sigs"
    assert d["count"] == 2
    assert d["dry_run"] is True
    assert len(d["staged"]) == 2
    assert len(d["skipped"]) == 1
