"""Comprehensive tests for installer/discovery.py edge cases and platforms."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.installer import discovery
from ida_pro_mcp.installer.discovery import (
    IdaInstall,
    _binary_arch,
    _detect_flavor,
    _detect_version,
    _find_idat,
    _from_env,
    _from_path,
    _ida_binary_names,
    _make_install,
    _resolves_under_safe_root,
    _safe_roots,
    _scan_home,
    _scan_system_dirs,
    detect_ida_installs,
    read_install_state,
    select_ida_install,
)


def test_safe_roots_darwin_and_windows(monkeypatch, tmp_path):
    # Darwin platform
    monkeypatch.setattr(sys, "platform", "darwin")
    roots = _safe_roots()
    assert Path("/Applications") in roots

    # Windows platform
    monkeypatch.setattr(sys, "platform", "win32")
    win_pf = tmp_path / "ProgramFiles"
    win_pf.mkdir()
    monkeypatch.setenv("ProgramFiles", str(win_pf))
    roots_win = _safe_roots()
    assert win_pf.resolve() in roots_win

    # OSError during root.resolve()
    real_resolve = Path.resolve
    def flaky_resolve(self, *args, **kwargs):
        if "Applications" in str(self):
            raise OSError("I/O error")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "resolve", flaky_resolve)
    roots_flaky = _safe_roots()
    assert Path("/Applications") not in roots_flaky


def test_resolves_under_safe_root_edges(monkeypatch, tmp_path):
    # Resolve raises OSError -> False
    def broken_resolve(self, *args, **kwargs):
        raise OSError("failed to resolve")

    monkeypatch.setattr(Path, "resolve", broken_resolve)
    assert not _resolves_under_safe_root(tmp_path / "cand")

    monkeypatch.undo()

    # Empty safe roots -> fail open (returns True)
    monkeypatch.setattr(discovery, "_safe_roots", list)
    assert _resolves_under_safe_root(tmp_path / "cand") is True

    # Neither realpath nor resolved is under safe roots -> False
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    monkeypatch.setattr(discovery, "_safe_roots", lambda: [safe_dir])
    outside = tmp_path / "outside" / "dir"
    outside.mkdir(parents=True)
    assert _resolves_under_safe_root(outside) is False


def test_ida_install_display_under_home(monkeypatch, tmp_path):
    home = tmp_path / "userhome"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    cand = home / "ida-9.4"
    install = IdaInstall(
        path=cand,
        version=(9, 4),
        build="",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="home_scan",
    )
    assert install.display.startswith("IDA 9.4 pro (x64) at ~/ida-9.4")


def test_ida_binary_names_platforms(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert _ida_binary_names() == ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]

    monkeypatch.setattr(sys, "platform", "darwin")
    assert _ida_binary_names() == ["idat64", "idat", "ida64", "ida"]

    monkeypatch.setattr(sys, "platform", "linux")
    assert _ida_binary_names() == ["idat64", "idat", "ida64", "ida"]


def test_binary_arch_io_errors(tmp_path, monkeypatch):
    # Nonexistent file raises OSError when opened
    assert _binary_arch(tmp_path / "ghost") == "unknown"

    # Corrupt PE file where inner seek/read raises OSError
    pe_stub = tmp_path / "pe_stub.exe"
    pe_stub.write_bytes(b"MZ\x00\x00")
    # seeking to 0x3C and reading will read empty bytes, pe_off = 0
    # Let monkeypatch raise OSError on second read
    orig_open = Path.open
    calls = 0

    class FakeFile:
        def __init__(self, f):
            self._f = f
        def read(self, n):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise OSError("corrupt sector")
            return self._f.read(n)
        def seek(self, offset):
            return self._f.seek(offset)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self._f.__exit__(*args)

    def broken_open(self, *args, **kwargs):
        f = orig_open(self, *args, **kwargs)
        return FakeFile(f)

    monkeypatch.setattr(Path, "open", broken_open)
    assert _binary_arch(pe_stub) == "unknown"


def test_detect_version_branches(tmp_path, monkeypatch):
    idat = tmp_path / "idat"
    idat.write_bytes(b"stub")
    # Subprocess strings returncode != 0
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    assert _detect_version(idat) is None

    # Subprocess strings raises TimeoutExpired
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="strings", timeout=10)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    assert _detect_version(idat) is None


def test_detect_flavor_generic_hexlic(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    install_dir = tmp_path / "ida"
    install_dir.mkdir()
    (install_dir / "custom_named.hexlic").write_text("license")
    assert _detect_flavor(install_dir) == "pro"


def test_find_idat_macos_and_make_install_errors(tmp_path):
    # Contents/MacOS contains idat
    app_dir = tmp_path / "IDA.app"
    macos = app_dir / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    bin_file = macos / "idat64"
    bin_file.write_bytes(b"exe")
    bin_file.chmod(0o755)
    assert _find_idat(app_dir) == bin_file

    # _make_install on non-directory
    assert _make_install(tmp_path / "missing", "test") is None

    # _make_install on dir without idat
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    assert _make_install(empty_dir, "test") is None


def test_scan_home_oserror_and_unsafe_roots(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    c1 = home / "ida-pro-9.3"
    c1.mkdir()
    c2 = home / "ida-9.4"
    c2.mkdir()

    # c1 raises OSError on resolve
    real_resolve = Path.resolve
    def custom_resolve(self, *args, **kwargs):
        if self == c1:
            raise OSError("disk failure")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", custom_resolve)
    # c2 fails _resolves_under_safe_root
    monkeypatch.setattr(discovery, "_resolves_under_safe_root", lambda p: False)
    assert list(_scan_home()) == []


def test_scan_system_dirs_darwin_and_linux(tmp_path, monkeypatch):
    # 1. Darwin
    monkeypatch.setattr(sys, "platform", "darwin")
    fake_apps = tmp_path / "Applications"
    fake_apps.mkdir()
    ida_app = fake_apps / "IDA Pro 9.3.app"
    ida_app.mkdir()
    monkeypatch.setattr(discovery, "Path", lambda p: fake_apps if p == "/Applications" else Path(p))
    monkeypatch.setattr(discovery, "_resolves_under_safe_root", lambda p: True)
    assert ida_app in list(_scan_system_dirs())

    # 2. Linux
    monkeypatch.setattr(sys, "platform", "linux")
    fake_opt = tmp_path / "opt"
    fake_opt.mkdir()
    ida_opt = fake_opt / "ida-9.3"
    ida_opt.mkdir()
    monkeypatch.setattr(discovery, "Path", lambda p: fake_opt if p == "/opt" else Path(p))
    assert ida_opt in list(_scan_system_dirs())

    # 3. Windows bp not a directory
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nonexistent_dir"))
    assert list(_scan_system_dirs()) == []


def test_from_env_directories_and_oserror(tmp_path, monkeypatch):
    d = tmp_path / "ida_env_dir"
    d.mkdir()
    monkeypatch.setenv("IDADIR", str(d))
    assert d.resolve() in list(_from_env())

    # OSError on resolve
    real_resolve = Path.resolve
    def fail_resolve(self, *args, **kwargs):
        if self == d:
            raise OSError("unreachable")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert list(_from_env()) == []


def test_detect_ida_installs_dedup_and_invalid(tmp_path, monkeypatch):
    d = tmp_path / "ida"
    d.mkdir()
    # Mock _from_env yielding d and _from_path yielding d
    monkeypatch.setattr(discovery, "_from_env", lambda: [d])
    monkeypatch.setattr(discovery, "_from_path", lambda: [d])
    monkeypatch.setattr(discovery, "_scan_home", list)
    monkeypatch.setattr(discovery, "_scan_system_dirs", list)

    # Mock _make_install: first time valid, second time same path, third time None
    inst = IdaInstall(
        path=d.resolve(),
        version=(9, 4),
        build="",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="env",
    )
    calls = 0
    def fake_make_install(p, source):
        nonlocal calls
        calls += 1
        return inst if calls <= 2 else None

    monkeypatch.setattr(discovery, "_make_install", fake_make_install)
    installs = detect_ida_installs()
    assert len(installs) == 1


def test_read_install_state_symlink_and_corrupt(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    state_file = root / discovery.STATE_FILE
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    state_file.symlink_to(target)
    # Symlink state file should return None
    assert read_install_state(root) is None

    # Corrupted dict without valid version in selected
    state_file.unlink()
    state_file.write_text(json.dumps({"selected": {"path": "/opt", "version": "invalid"}}), encoding="utf-8")
    assert read_install_state(root) is None


def test_select_ida_install_single_component_version(tmp_path):
    inst92 = IdaInstall(
        path=tmp_path / "ida92",
        version=(9, 2),
        build="240101.111111",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="env",
    )
    inst84 = IdaInstall(
        path=tmp_path / "ida84",
        version=(8, 4),
        build="",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="env",
    )
    # Match major version only (len(want) == 1)
    matched = select_ida_install([inst92, inst84], explicit_version="9")
    assert matched == inst92

def test_detect_version_cand_not_file_and_seen(tmp_path):
    # binary is not a file
    missing = tmp_path / "missing_idat"
    assert _detect_version(missing) is None

    # sibling in seen
    idat = tmp_path / "idat"
    idat.write_bytes(b"stub")
    ida64 = tmp_path / "ida64"
    ida64.write_bytes(b"stub")
    # if candidates has duplicates
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("ida_pro_mcp.installer.discovery._scan_binary_for_version", lambda c: None)
        mp.setattr("subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout=""))
        assert _detect_version(idat) is None


def test_make_install_detected_none(tmp_path, monkeypatch):
    install_dir = tmp_path / "ida"
    install_dir.mkdir()
    idat = install_dir / "idat"
    idat.write_bytes(b"some binary")
    idat.chmod(0o755)
    monkeypatch.setattr(discovery, "_detect_version", lambda bin_path: None)
    install = _make_install(install_dir, "test")
    assert install is not None
    assert install.version == (0, 0)
    assert install.build == ""


def test_scan_system_dirs_linux_opt_and_filtering(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    opt = tmp_path / "opt"
    opt.mkdir()
    usr_local = tmp_path / "usr_local_missing"  # not a dir

    ida_dir = opt / "ida-9.5"
    ida_dir.mkdir()
    other_dir = opt / "other"
    other_dir.mkdir()

    monkeypatch.setattr(discovery, "Path", lambda p: opt if p == "/opt" else (usr_local if p == "/usr/local" else Path(p)))

    # 1. Candidate resolve raises OSError
    real_resolve = Path.resolve
    def fail_res(self, *args, **kwargs):
        if self == ida_dir:
            raise OSError("fail")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_res)
    assert list(_scan_system_dirs()) == []
    monkeypatch.undo()

    # 2. Candidate fails safe root check
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(discovery, "Path", lambda p: opt if p == "/opt" else (usr_local if p == "/usr/local" else Path(p)))
    monkeypatch.setattr(discovery, "_resolves_under_safe_root", lambda p: False)
    assert list(_scan_system_dirs()) == []
    monkeypatch.undo()

    # 3. Duplicate candidate seen
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(discovery, "Path", lambda p: opt if p == "/opt" else (usr_local if p == "/usr/local" else Path(p)))
    monkeypatch.setattr(discovery, "_resolves_under_safe_root", lambda p: True)
    # create another ida dir
    ida_dir2 = opt / "ida-9.6"
    ida_dir2.mkdir()
    found = list(_scan_system_dirs())
    assert len(found) >= 1


def test_detect_ida_installs_home_system_scans_and_none(tmp_path, monkeypatch):
    p1 = tmp_path / "ida1"
    p2 = tmp_path / "ida2"
    p3 = tmp_path / "ida3"
    p1.mkdir()
    p2.mkdir()
    p3.mkdir()

    monkeypatch.setattr(discovery, "_from_env", list)
    monkeypatch.setattr(discovery, "_from_path", list)
    monkeypatch.setattr(discovery, "_scan_home", lambda: [p1, p2])
    monkeypatch.setattr(discovery, "_scan_system_dirs", lambda: [p3])

    inst1 = IdaInstall(path=p1, version=(9, 4), build="", idat_binary=None, arch="x64", flavor="pro", source="home_scan")
    inst3 = IdaInstall(path=p3, version=(9, 3), build="", idat_binary=None, arch="x64", flavor="pro", source="system_scan")

    def mock_make_install(p, source):
        if p == p1:
            return inst1
        if p == p3:
            return inst3
        return None  # p2 returns None

    monkeypatch.setattr(discovery, "_make_install", mock_make_install)
    installs = detect_ida_installs()
    assert len(installs) == 2
    assert installs[0].path == p1
    assert installs[1].path == p3


def test_select_ida_install_explicit_dir_success(tmp_path):
    ida_dir = tmp_path / "ida_valid"
    ida_dir.mkdir()
    idat = ida_dir / "idat"
    idat.write_bytes(b"ida")
    idat.chmod(0o755)
    install = select_ida_install([], explicit_dir=ida_dir)
    assert install.path == ida_dir.resolve()

def test_detect_version_duplicate_candidate_in_seen(tmp_path, monkeypatch):
    idat = tmp_path / "idat"
    idat.write_bytes(b"stub")
    shared_sibling = tmp_path / "ida64"
    shared_sibling.write_bytes(b"shared")

    orig_div = Path.__truediv__
    def fake_div(self, other):
        if str(other) in ("ida64", "ida"):
            return shared_sibling
        return orig_div(self, other)

    monkeypatch.setattr(Path, "__truediv__", fake_div)
    monkeypatch.setattr("ida_pro_mcp.installer.discovery._scan_binary_for_version", lambda c: None)
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout=""))

    assert _detect_version(idat) is None


def test_scan_system_dirs_duplicate_resolved_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    fake_opt = tmp_path / "opt"
    fake_opt.mkdir()
    real_ida = fake_opt / "ida-9.3"
    real_ida.mkdir()
    sym_ida = fake_opt / "ida-symlink"
    sym_ida.symlink_to(real_ida)

    monkeypatch.setattr(discovery, "Path", lambda p: fake_opt if p == "/opt" else (tmp_path / "usr_local_none" if p == "/usr/local" else Path(p)))
    monkeypatch.setattr(discovery, "_resolves_under_safe_root", lambda p: True)

    results = list(_scan_system_dirs())
    assert len(results) == 1
    assert results[0] == real_ida.resolve()
