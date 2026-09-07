"""Offline platform and failure-mode coverage for installer common helpers."""

from __future__ import annotations

import errno
import sys
import tempfile
from pathlib import Path, PosixPath

import pytest

from ida_pro_mcp.installer import common


def test_relative_paths_and_platform_lock_fallbacks(tmp_path, monkeypatch):
    common.reject_symlink_path(Path("relative-installer-target"), "relative path")

    monkeypatch.delattr(common.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(common.os, "fchmod", raising=False)
    with common.installer_lock(tmp_path / "posix-lock") as lock_path:
        assert lock_path.name == ".install.lock"


def test_installer_lock_reports_eloop_and_unexpected_flock_errors(tmp_path, monkeypatch):
    real_open = common.os.open

    def loop_open(*_args, **_kwargs):
        raise OSError(errno.ELOOP, "symlink")

    monkeypatch.setattr(common.os, "open", loop_open)
    with pytest.raises(RuntimeError, match="symlinked installer lock"), common.installer_lock(
        tmp_path / "eloop"
    ):
        pass

    class _Fcntl:
        LOCK_EX = 1
        LOCK_NB = 2

        @staticmethod
        def flock(_fd, _flags):
            raise OSError(errno.EPERM, "unexpected lock failure")

    monkeypatch.setattr(common.os, "open", real_open)
    monkeypatch.setitem(sys.modules, "fcntl", _Fcntl)
    with pytest.raises(OSError, match="unexpected lock failure"), common.installer_lock(
        tmp_path / "flock-error"
    ):
        pass

    def denied_open(*_args, **_kwargs):
        raise OSError(errno.EPERM, "permission denied")

    monkeypatch.setattr(common.os, "open", denied_open)
    with pytest.raises(OSError, match="permission denied"), common.installer_lock(
        tmp_path / "open-error"
    ):
        pass


def test_installer_lock_windows_success_and_contention_error(tmp_path, monkeypatch):
    calls = []

    class _Msvcrt:
        LK_NBLCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(_fd, mode, count):
            calls.append((mode, count))

    monkeypatch.setitem(sys.modules, "msvcrt", _Msvcrt)
    monkeypatch.setattr(common.os, "name", "nt")
    monkeypatch.setattr(common, "Path", PosixPath)
    with common.installer_lock(tmp_path / "windows-lock") as lock_path:
        assert lock_path.exists()
    assert calls == [(1, 1), (2, 1)]

    class _BusyMsvcrt(_Msvcrt):
        @staticmethod
        def locking(_fd, _mode, _count):
            raise OSError("busy")

    monkeypatch.setitem(sys.modules, "msvcrt", _BusyMsvcrt)
    with pytest.raises(RuntimeError, match="Another installer"), common.installer_lock(
        tmp_path / "windows-busy"
    ):
        pass


def test_atomic_write_skips_directory_fsync_on_windows(tmp_path, monkeypatch):
    target = tmp_path / "config.json"
    fd, temporary = tempfile.mkstemp(prefix="precreated-", dir=str(tmp_path))
    monkeypatch.setattr(common.os, "name", "nt")
    monkeypatch.setattr(common, "Path", PosixPath)
    monkeypatch.setattr(common.tempfile, "mkstemp", lambda **_kwargs: (fd, temporary))
    common.atomic_write_text(target, "payload")
    assert target.read_text() == "payload"


def test_atomic_write_uses_existing_mode_when_present(tmp_path):
    target = tmp_path / "config.bin"
    target.write_bytes(b"old")
    target.chmod(0o640)
    common.atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o640
