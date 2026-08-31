"""Edge coverage for IDA install discovery and selection."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.installer import discovery
from ida_pro_mcp.installer.discovery import IdaInstall, select_ida_install


def _binary(path: Path, payload: bytes, *, executable: bool = True) -> Path:
    path.write_bytes(payload)
    if executable:
        path.chmod(0o755)
    return path


def _elf(version: str = "9.3.260421.be7de18d", *, machine: int = 0x3E, bits: int = 2) -> bytes:
    header = b"\x7fELF" + bytes([bits]) + b"\x00" * 13 + machine.to_bytes(2, "little")
    return header + version.encode("ascii") + b"\x00"


def test_binary_version_scan_matches_build_string_across_chunk_boundary(tmp_path):
    binary = tmp_path / "ida64"
    prefix_length = (1 << 20) - 20
    binary.write_bytes(b"x" * prefix_length + b"9.3.260421.be7de18d" + b"tail")

    assert discovery._scan_binary_for_version(binary) == ((9, 3), "260421.be7de18d")


def test_detect_version_uses_real_sibling_when_idat_wrapper_has_no_version(tmp_path, monkeypatch):
    wrapper = _binary(tmp_path / "idat64", b"#!/bin/sh\nexec ida64\n")
    _binary(tmp_path / "ida64", _elf())
    monkeypatch.setattr(
        discovery.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )

    assert discovery._detect_version(wrapper) == ((9, 3), "260421.be7de18d")


def test_binary_architecture_sniffer_handles_elf_pe_and_unknown(tmp_path):
    assert discovery._binary_arch(_binary(tmp_path / "arm64", _elf(machine=0xB7))) == "arm64"
    assert discovery._binary_arch(_binary(tmp_path / "x64", _elf(machine=0x3E))) == "x64"
    assert discovery._binary_arch(_binary(tmp_path / "x86", _elf(machine=0x03, bits=1))) == "x86"

    pe = bytearray(b"MZ" + b"\x00" * 100)
    pe[0x3C:0x40] = (0x40).to_bytes(4, "little")
    pe.extend(b"\x00" * (0x44 - len(pe)))
    pe[0x44:0x46] = (0xAA64).to_bytes(2, "little")
    assert discovery._binary_arch(_binary(tmp_path / "pe-arm64.exe", bytes(pe))) == "arm64"
    assert discovery._binary_arch(_binary(tmp_path / "unknown", b"not executable")) == "unknown"


def test_safe_root_check_rejects_symlink_redirect(tmp_path, monkeypatch):
    safe = tmp_path / "safe"
    outside = tmp_path / "outside"
    safe.mkdir()
    outside.mkdir()
    redirected = safe / "ida-pro-9.3"
    redirected.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(discovery, "_safe_roots", lambda: [safe.resolve()])

    assert discovery._resolves_under_safe_root(safe / "regular") is True
    assert discovery._resolves_under_safe_root(redirected) is False


def test_make_install_requires_executable_idat_and_detects_flavor(tmp_path):
    install = tmp_path / "ida"
    install.mkdir()
    _binary(install / "idat64", b"wrapper")
    _binary(install / "ida64", _elf())
    (install / "idahome_license.hexlic").write_text("license")

    result = discovery._make_install(install, "explicit")

    assert result is not None
    assert result.version == (9, 3)
    assert result.build == "260421.be7de18d"
    assert result.flavor == "home"
    assert result.source == "explicit"
    assert discovery._make_install(tmp_path / "missing", "explicit") is None


def test_from_env_accepts_directory_or_binary_and_ignores_missing(monkeypatch, tmp_path):
    install = tmp_path / "ida"
    install.mkdir()
    binary = install / "idat64"
    binary.write_bytes(b"x")
    monkeypatch.setenv("IDADIR", str(install))
    monkeypatch.setenv("IDA_DIR", str(binary))
    monkeypatch.setenv("IDA_MCP_IDAT", str(tmp_path / "missing"))

    values = list(discovery._from_env())

    assert values == [install.resolve(), install.resolve()]


def test_from_path_returns_parent_of_first_available_binary(monkeypatch, tmp_path):
    install = tmp_path / "ida"
    install.mkdir()
    binary = install / "idat64"
    binary.write_bytes(b"x")
    monkeypatch.setattr(discovery, "_ida_binary_names", lambda: ["idat64", "idat"])
    monkeypatch.setattr(discovery.shutil, "which", lambda name: str(binary) if name == "idat64" else None)

    assert list(discovery._from_path()) == [install.resolve()]


def test_detect_ida_installs_deduplicates_sources_and_sorts_flavor(monkeypatch, tmp_path):
    pro = tmp_path / "pro"
    home = tmp_path / "home"
    for install, flavor_file in ((pro, "idapro_license.hexlic"), (home, "idahome_license.hexlic")):
        install.mkdir()
        _binary(install / "idat64", b"wrapper")
        _binary(install / "ida64", _elf())
        (install / flavor_file).write_text("license")

    monkeypatch.setattr(discovery, "_from_env", lambda: iter([pro, pro]))
    monkeypatch.setattr(discovery, "_from_path", lambda: iter([home]))
    monkeypatch.setattr(discovery, "_scan_home", lambda: iter([]))
    monkeypatch.setattr(discovery, "_scan_system_dirs", lambda: iter([]))

    installs = discovery.detect_ida_installs()

    assert [item.path for item in installs] == [pro.resolve(), home.resolve()]
    assert [item.source for item in installs] == ["env", "path"]


def test_selection_rejects_bad_explicit_directory_and_out_of_range_default(tmp_path):
    with pytest.raises(RuntimeError, match="does not contain"):
        select_ida_install([], explicit_dir=tmp_path / "not-an-install")
    installs = [IdaInstall(tmp_path / "one", (9, 3), "", None, "unknown", "unknown", "explicit")]
    assert select_ida_install(installs, default_index=0) is installs[0]
    with pytest.raises(IndexError):
        select_ida_install([installs[0], installs[0]], default_index=3)


def test_install_state_rejects_malformed_selected_records(tmp_path):
    state_path = tmp_path / discovery.STATE_FILE
    for payload in (
        [],
        "not an object",
        {"selected": []},
        {"selected": {"path": str(tmp_path)}},
        {"selected": {"path": str(tmp_path), "version": ["not", "ints"]}},
    ):
        state_path.write_text(__import__("json").dumps(payload), encoding="utf-8")
        assert discovery.read_install_state(tmp_path) is None
