from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.installer.discovery import (
    STATE_FILE,
    IdaInstall,
    _binary_arch,
    _detect_flavor,
    _detect_version,
    _expand_configured_path,
    _find_idat,
    _from_env,
    _from_path,
    _make_install,
    _resolves_under_safe_root,
    _safe_roots,
    _scan_binary_for_version,
    _scan_home,
    _scan_system_dirs,
    detect_ida_installs,
    parse_version,
    read_install_state,
    select_ida_install,
    write_install_state,
)


def test_parse_version_variants() -> None:
    assert parse_version("9.3") == (9, 3)
    assert parse_version("9.0.20240812") == (9, 0, 20240812)
    assert parse_version("9.0sp1") == (9, 0, 1)
    assert parse_version("9.3rc2") == (9, 3, 2)
    assert parse_version("9") == (9,)
    assert parse_version("no-digits-here") == (0,)
    assert parse_version("") == (0,)


def test_expand_configured_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_VAR", "my_custom_dir")
    expanded = _expand_configured_path("$TEST_VAR/subpath")
    assert "my_custom_dir" in str(expanded)


def test_safe_roots_and_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    roots = _safe_roots()
    assert len(roots) > 0
    assert _resolves_under_safe_root(tmp_path / "ida")
    assert _resolves_under_safe_root(Path.home())


def test_binary_arch_elf(tmp_path: Path) -> None:
    # ELF 64-bit x86_64: machine 0x3E
    elf64_x64 = bytearray(20)
    elf64_x64[:4] = b"\x7fELF"
    elf64_x64[4] = 2  # 64-bit
    elf64_x64[18:20] = (0x3E).to_bytes(2, "little")
    p = tmp_path / "elf_x64"
    p.write_bytes(elf64_x64)
    assert _binary_arch(p) == "x64"

    # ELF 64-bit arm64: machine 0xB7
    elf64_arm = bytearray(20)
    elf64_arm[:4] = b"\x7fELF"
    elf64_arm[4] = 2
    elf64_arm[18:20] = (0xB7).to_bytes(2, "little")
    p_arm = tmp_path / "elf_arm64"
    p_arm.write_bytes(elf64_arm)
    assert _binary_arch(p_arm) == "arm64"

    # ELF 32-bit: ei_class 1
    elf32 = bytearray(20)
    elf32[:4] = b"\x7fELF"
    elf32[4] = 1
    p_32 = tmp_path / "elf_x86"
    p_32.write_bytes(elf32)
    assert _binary_arch(p_32) == "x86"


def test_binary_arch_macho_and_pe(tmp_path: Path) -> None:
    # Mach-O arm64
    macho_arm = bytearray(20)
    macho_arm[:4] = b"\xcf\xfa\xed\xfe"
    macho_arm[4] = 0x0C  # CPU_TYPE_ARM
    p_macho = tmp_path / "macho_arm"
    p_macho.write_bytes(macho_arm)
    assert _binary_arch(p_macho) == "arm64"

    # PE AMD64
    pe = bytearray(128)
    pe[:2] = b"MZ"
    pe[0x3C:0x40] = (0x40).to_bytes(4, "little")  # PE header offset
    pe[0x44:0x46] = (0x8664).to_bytes(2, "little")  # AMD64
    p_pe = tmp_path / "pe_x64.exe"
    p_pe.write_bytes(pe)
    assert _binary_arch(p_pe) == "x64"

    # PE ARM64
    pe[0x44:0x46] = (0xAA64).to_bytes(2, "little")
    p_pe_arm = tmp_path / "pe_arm64.exe"
    p_pe_arm.write_bytes(pe)
    assert _binary_arch(p_pe_arm) == "arm64"

    # PE x86
    pe[0x44:0x46] = (0x14C).to_bytes(2, "little")
    p_pe_x86 = tmp_path / "pe_x86.exe"
    p_pe_x86.write_bytes(pe)
    assert _binary_arch(p_pe_x86) == "x86"

    # Unknown
    p_unk = tmp_path / "unknown.bin"
    p_unk.write_bytes(b"NOT_A_VALID_HEADER")
    assert _binary_arch(p_unk) == "unknown"


def test_scan_binary_for_version(tmp_path: Path) -> None:
    bin_file = tmp_path / "fake_ida"
    # Write build string into file
    bin_file.write_bytes(b"\x00\x00IDA: 9.3.260421.be7de18d built\x00")
    detected = _scan_binary_for_version(bin_file)
    assert detected is not None
    ver, build = detected
    assert ver == (9, 3)
    assert build == "260421.be7de18d"

    # Missing file returns None
    assert _scan_binary_for_version(tmp_path / "missing") is None


def test_detect_version_with_sibling(tmp_path: Path) -> None:
    idat = tmp_path / "idat"
    idat.write_bytes(b"small script")
    ida64 = tmp_path / "ida64"
    ida64.write_bytes(b"IDA version 9.2.240101.aabbccdd embedded")
    detected = _detect_version(idat)
    assert detected is not None
    ver, build = detected
    assert ver == (9, 2)
    assert build == "240101.aabbccdd"


def test_detect_flavor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake_home")
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    install_dir = tmp_path / "ida_dir"
    install_dir.mkdir()

    assert _detect_flavor(install_dir) == "unknown"

    (install_dir / "idahome_123.hexlic").write_text("lic")
    assert _detect_flavor(install_dir) == "home"

    (install_dir / "idapro_123.hexlic").write_text("lic")
    assert _detect_flavor(install_dir) == "pro"


def test_find_idat_and_make_install(tmp_path: Path) -> None:
    install_dir = tmp_path / "ida_pro_93"
    install_dir.mkdir()
    idat = install_dir / ("idat.exe" if sys.platform == "win32" else "idat")
    idat.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00" + b" 9.3.260421.be7de18d ")
    idat.chmod(0o755)

    found_idat = _find_idat(install_dir)
    assert found_idat is not None

    install = _make_install(install_dir, source="test")
    assert install is not None
    assert install.version == (9, 3)
    assert install.build == "260421.be7de18d"
    assert install.source == "test"
    assert "IDA 9.3.260421.be7de18d" in install.display
    assert install.version_str == "9.3"
    assert install.full_version_str == "9.3.260421.be7de18d"


def test_find_idat_idabin_and_nested_app(tmp_path: Path) -> None:
    bin_name = "idat64.exe" if sys.platform == "win32" else "idat64"

    # 1. idabin layout
    dir_idabin = tmp_path / "ida_idabin"
    (dir_idabin / "idabin").mkdir(parents=True)
    idat_idabin = dir_idabin / "idabin" / bin_name
    idat_idabin.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    idat_idabin.chmod(0o755)
    assert _find_idat(dir_idabin) == idat_idabin

    # 2. nested macOS .app layout
    dir_app = tmp_path / "ida_app"
    (dir_app / "ida64.app" / "Contents" / "MacOS").mkdir(parents=True)
    idat_app = dir_app / "ida64.app" / "Contents" / "MacOS" / bin_name
    idat_app.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    idat_app.chmod(0o755)
    assert _find_idat(dir_app) == idat_app


def test_ida_install_serialization(tmp_path: Path) -> None:
    inst = IdaInstall(
        path=tmp_path / "ida",
        version=(9, 3),
        build="260421.be7de18d",
        idat_binary=tmp_path / "ida" / "idat",
        arch="x64",
        flavor="pro",
        source="env",
    )
    d = inst.to_dict()
    assert d["arch"] == "x64"
    assert d["flavor"] == "pro"

    restored = IdaInstall.from_dict(d)
    assert restored.version == (9, 3)
    assert restored.build == "260421.be7de18d"
    assert restored.path == tmp_path / "ida"

    # Validation errors
    with pytest.raises(ValueError, match="install state must be an object"):
        IdaInstall.from_dict("not a dict")  # type: ignore

    with pytest.raises(ValueError, match="install version must contain two integer components"):
        IdaInstall.from_dict({"path": "/opt/ida", "version": [9]})


def test_write_and_read_install_state(tmp_path: Path) -> None:
    root = tmp_path / "mcp_home"
    root.mkdir()
    inst = IdaInstall(
        path=tmp_path / "ida_93",
        version=(9, 3),
        build="260421.be7de18d",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="explicit",
    )
    state_file = write_install_state(root, inst)
    assert state_file.is_file()

    read_back = read_install_state(root)
    assert read_back is not None
    assert read_back.version == (9, 3)
    assert read_back.flavor == "pro"

    # Corrupted state file
    state_file.write_text("invalid json")
    assert read_install_state(root) is None


def test_detect_ida_installs_ordering(tmp_path: Path) -> None:
    dir_92 = tmp_path / "ida_92"
    dir_92.mkdir()
    idat92 = dir_92 / ("idat.exe" if sys.platform == "win32" else "idat")
    idat92.write_bytes(b" 9.2.240101.111111 ")
    idat92.chmod(0o755)

    dir_93 = tmp_path / "ida_93"
    dir_93.mkdir()
    idat93 = dir_93 / ("idat.exe" if sys.platform == "win32" else "idat")
    idat93.write_bytes(b" 9.3.260421.be7de18d ")
    idat93.chmod(0o755)

    with patch(
        "ida_pro_mcp.installer.discovery._from_env",
        return_value=[dir_92, dir_93],
    ), patch(
        "ida_pro_mcp.installer.discovery._from_path",
        return_value=[],
    ), patch(
        "ida_pro_mcp.installer.discovery._scan_home",
        return_value=[],
    ), patch(
        "ida_pro_mcp.installer.discovery._scan_system_dirs",
        return_value=[],
    ):
        installs = detect_ida_installs()
        assert len(installs) == 2
        # Highest version must come first
        assert installs[0].version == (9, 3)
        assert installs[1].version == (9, 2)


def test_select_ida_install_options(tmp_path: Path) -> None:
    inst92 = IdaInstall(
        path=tmp_path / "ida92",
        version=(9, 2),
        build="240101.111111",
        idat_binary=tmp_path / "ida92" / "idat",
        arch="x64",
        flavor="pro",
        source="env",
    )
    inst93 = IdaInstall(
        path=tmp_path / "ida93",
        version=(9, 3),
        build="260421.be7de18d",
        idat_binary=tmp_path / "ida93" / "idat",
        arch="x64",
        flavor="pro",
        source="env",
    )

    # Empty list raises error
    with pytest.raises(RuntimeError, match="No IDA Pro install detected"):
        select_ida_install([])

    # Single install returns it
    assert select_ida_install([inst93]) == inst93

    # Default index
    assert select_ida_install([inst93, inst92], default_index=1) == inst92

    # Explicit version match
    assert select_ida_install([inst93, inst92], explicit_version="9.2") == inst92
    assert select_ida_install([inst93, inst92], explicit_version="9.3.260421") == inst93

    with pytest.raises(RuntimeError, match="Invalid --ida-version 'xyz'"):
        select_ida_install([inst93], explicit_version="xyz")

    with pytest.raises(RuntimeError, match="No installed IDA matches version 9.5"):
        select_ida_install([inst93, inst92], explicit_version="9.5")

    # Prompt fn
    assert select_ida_install([inst93, inst92], prompt_fn=lambda xs: xs[1]) == inst92


def test_discovery_handles_short_headers_external_versions_and_nested_macos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    short = tmp_path / "short"
    short.write_bytes(b"x")
    assert _binary_arch(short) == "unknown"

    macho_x64 = tmp_path / "macho-x64"
    macho_x64.write_bytes(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\0" * 12)
    assert _binary_arch(macho_x64) == "x64"

    pe_unknown = bytearray(128)
    pe_unknown[:2] = b"MZ"
    pe_unknown[0x3C:0x40] = (0x40).to_bytes(4, "little")
    pe_unknown[0x44:0x46] = (0x1234).to_bytes(2, "little")
    pe_path = tmp_path / "unknown.exe"
    pe_path.write_bytes(pe_unknown)
    assert _binary_arch(pe_path) == "unknown"

    raw = tmp_path / "raw-idat"
    raw.write_bytes(b"no embedded version")
    monkeypatch.setattr(
        "ida_pro_mcp.installer.discovery.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="UNKNOWN: placeholder\nIDA 9.4.260901.aabbccdd\n",
        ),
    )
    assert _detect_version(raw) == ((9, 4), "260901.aabbccdd")

    monkeypatch.setattr(sys, "platform", "darwin")
    nested = tmp_path / "IDA Pro.app" / "Contents" / "MacOS"
    nested.mkdir(parents=True)
    nested_idat = nested / "idat64"
    nested_idat.write_bytes(b"idat")
    nested_idat.chmod(0o755)
    assert _find_idat(tmp_path / "IDA Pro.app") == nested_idat


def test_discovery_flavors_sources_and_state_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    (home / "idaessential_1.hexlic").write_text("license")
    install = tmp_path / "ida"
    install.mkdir()
    assert _detect_flavor(install) == "essential"

    (home / "idaessential_1.hexlic").unlink()
    (home / "idafree_1.hexlic").write_text("license")
    assert _detect_flavor(install) == "free"

    ida_home = home / "ida-pro-9.4"
    ida_home.mkdir()
    (ida_home / "idat64").write_bytes(b"idat")
    (ida_home / "idat64").chmod(0o755)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert ida_home in list(_scan_home())

    monkeypatch.setenv("IDADIR", str(ida_home / "idat64"))
    assert list(_from_env()) == [ida_home]
    monkeypatch.setattr(
        "ida_pro_mcp.installer.discovery.shutil.which",
        lambda name: str(ida_home / name) if name == "idat64" else None,
    )
    assert list(_from_path()) == [ida_home]

    root = tmp_path / "state"
    root.mkdir()
    assert read_install_state(root) is None
    (root / STATE_FILE).write_text(json.dumps({"selected": []}), encoding="utf-8")
    assert read_install_state(root) is None
    (root / STATE_FILE).write_text("[]", encoding="utf-8")
    assert read_install_state(root) is None


def test_discovery_platform_scan_and_explicit_selection_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    win_root = tmp_path / "Program Files"
    win_root.mkdir()
    ida_dir = win_root / "IDA Pro 9.4"
    ida_dir.mkdir()
    binary = ida_dir / "idat64.exe"
    binary.write_bytes(b"idat")
    binary.chmod(0o755)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles", str(win_root))
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert ida_dir in list(_scan_system_dirs())

    with pytest.raises(RuntimeError, match="does not contain"):
        select_ida_install([], explicit_dir=tmp_path / "missing")

    with pytest.raises(RuntimeError, match="no version digits"):
        select_ida_install([], explicit_version="xyz")
