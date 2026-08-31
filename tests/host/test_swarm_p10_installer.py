"""Regression tests for WO-INST installer additions (paper §8.2 item 11, §10.2 item 5e).

Files under test:
* installer/main.py    -- ``--with-r2`` flag + ``--sigs <dir>`` staging phase
* installer/runtime.py -- ``resolve_r2_binary``, ``stage_sigs``, ``IDA_MCP_R2_BIN``
* installer/common.py  -- ``with_r2``/``sigs_dir`` options, ``find_ida_sig_dir``, ``SigsManifest``

These tests are hermetic: no live IDA, no real rz/r2.  The r2 tests drive a fake
``rz`` on PATH; the sig tests stage packs into throwaway temp sig dirs.  A
RISC-V sig-pack scenario (the "nothing installs a RISC-V .sig pack" gap) is
covered with opaque raw-blob signature payloads.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_ida_install(install_dir: Path):
    """A minimal discovery.IdaInstall pointing at a throwaway install dir.

    No real idat binary is required -- the installer only reads ``.path`` for
    sig-dir discovery, and the sig dir need not exist yet.
    """
    from ida_pro_mcp.installer.discovery import IdaInstall

    return IdaInstall(
        path=install_dir,
        version=(9, 3),
        build="260421.be7de18d",
        idat_binary=install_dir / "idat64",
        arch="x64",
        flavor="pro",
        source="explicit",
    )


def _write_rz_fake(bin_dir: Path, name: str = "rz") -> Path:
    """Write an executable fake ``rz``/``r2`` that answers --version/-v.

    A binary named ``r2`` reports the radare2 banner for both probes; ``rz``
    reports the rizin banner (mirroring the real tools' banners).
    """
    script = bin_dir / name
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "NAME = os.path.basename(sys.argv[0])\n"
        'BANNER = "radare2 5.9.0 fake (test)" if NAME == "r2" else "rizin 0.7.4 fake (test)"\n'
        'if "--version" in sys.argv or "-v" in sys.argv:\n'
        "    print(BANNER)\n"
        "else:\n"
        '    print("unknown")\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _prepend_path(monkeypatch: pytest.MonkeyPatch, bin_dir: Path) -> None:
    monkeypatch.setenv(
        "PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", "")
    )


# ---------------------------------------------------------------------------
# installer.main: flag-parse smoke tests
# ---------------------------------------------------------------------------


def test_parse_args_with_r2_flag():
    from ida_pro_mcp.installer.main import parse_args

    assert parse_args(["--with-r2"]).with_r2 is True
    assert parse_args(["--yes", "--with-r2"]).with_r2 is True
    assert parse_args([]).with_r2 is False


def test_parse_args_sigs_dir_flag(tmp_path):
    from ida_pro_mcp.installer.main import parse_args

    pack = tmp_path / "riscv64-sigpack"
    opts = parse_args(["--sigs", str(pack)])
    assert opts.sigs_dir == str(pack)
    assert parse_args([]).sigs_dir == ""


def test_parse_args_only_accepts_r2_and_sigs_phases():
    """--only must accept the new r2/sigs phases without SystemExit."""
    from ida_pro_mcp.installer.main import parse_args

    assert parse_args(["--only", "r2"]).only == {"r2"}
    assert parse_args(["--only", "sigs"]).only == {"sigs"}
    assert parse_args(["--only", "r2", "--only", "sigs"]).only == {"r2", "sigs"}
    assert parse_args(["--only", "clients"]).only == {"clients"}


# ---------------------------------------------------------------------------
# installer.common: shared sig-dir discovery
# ---------------------------------------------------------------------------


def test_find_ida_sig_dir_returns_ida_sig_path(tmp_path):
    from ida_pro_mcp.installer.common import find_ida_sig_dir

    install_dir = tmp_path / "ida-pro-9.3"
    assert find_ida_sig_dir(install_dir) == install_dir / "sig"


# ---------------------------------------------------------------------------
# installer.runtime: stage_sigs
# ---------------------------------------------------------------------------


def _make_sig_pack(tmp_path: Path) -> Path:
    pack = tmp_path / "sigpack"
    pack.mkdir()
    (pack / "riscv64_musl.sig").write_bytes(b"\x00RISCV\x01opaque sig blob\xff")
    (pack / "riscv64_newlib.sig").write_bytes(b"\x00RISCV\x02opaque sig blob\xfe")
    (pack / "riscv64_libc.sig.gz").write_bytes(b"\x1f\x8b\x08\x00gzip sig payload")
    (pack / "README.txt").write_text("not a signature", encoding="utf-8")
    return pack


def test_stage_sigs_copies_sig_and_sig_gz_into_sig_dir(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    pack = _make_sig_pack(tmp_path)
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"
    report = InstallReport()

    manifest = stage_sigs(pack, sig_dir, dry_run=False, report=report)

    assert manifest.count == 3
    # The .sig and .sig.gz files land under sig_dir; the README is ignored.
    for name in ("riscv64_musl.sig", "riscv64_newlib.sig", "riscv64_libc.sig.gz"):
        dest = sig_dir / name
        assert dest.is_file(), dest
        assert str(dest) in manifest.staged
    assert not (sig_dir / "README.txt").exists()
    assert manifest.dry_run is False
    assert manifest.source == str(pack.resolve())
    # Staged destinations are recorded as modified files.
    assert len(report.modified_files) == 3
    assert all(str(p).startswith(str(sig_dir)) for p in report.modified_files)
    # No conflicts -> nothing skipped.
    assert manifest.skipped == []


def test_stage_sigs_dry_run_writes_nothing(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    pack = _make_sig_pack(tmp_path)
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"
    report = InstallReport()

    manifest = stage_sigs(pack, sig_dir, dry_run=True, report=report)

    assert manifest.count == 3
    assert manifest.dry_run is True
    assert not sig_dir.exists()  # nothing touched the filesystem
    assert report.modified_files == []


def test_stage_sigs_single_file_source(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    sig_file = tmp_path / "riscv64_gnu.sig"
    sig_file.write_bytes(b"\x00RISCV\x03single file\xff")
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"

    manifest = stage_sigs(sig_file, sig_dir, dry_run=False, report=InstallReport())

    assert manifest.count == 1
    dest = sig_dir / "riscv64_gnu.sig"
    assert dest.is_file()
    assert dest.read_bytes() == sig_file.read_bytes()


def test_stage_sigs_preserves_nested_subdirs(tmp_path):
    """A multi-arch pack with nested layout must not collide on basename."""
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    pack = tmp_path / "sigpack"
    nested = pack / "riscv" / "pc"
    nested.mkdir(parents=True)
    (pack / "gnu.sig").write_bytes(b"\x00gnu top")
    (nested / "gnu.sig").write_bytes(b"\x00gnu nested")
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"

    manifest = stage_sigs(pack, sig_dir, dry_run=False, report=InstallReport())

    assert manifest.count == 2
    assert (sig_dir / "gnu.sig").is_file()
    assert (sig_dir / "riscv" / "pc" / "gnu.sig").is_file()
    assert (sig_dir / "riscv" / "pc" / "gnu.sig").read_bytes() == b"\x00gnu nested"


def test_stage_sigs_skips_existing_never_overwrites(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    pack = _make_sig_pack(tmp_path)
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"
    sig_dir.mkdir(parents=True)
    # IDA already ships a riscv64_musl.sig; the pack must not clobber it.
    (sig_dir / "riscv64_musl.sig").write_bytes(b"ORIGINAL")
    report = InstallReport()

    manifest = stage_sigs(pack, sig_dir, dry_run=False, report=report)

    assert manifest.count == 2  # newlib + libc.gz staged
    assert str(sig_dir / "riscv64_musl.sig") in manifest.skipped
    assert (sig_dir / "riscv64_musl.sig").read_bytes() == b"ORIGINAL"
    assert (sig_dir / "riscv64_newlib.sig").is_file()
    assert len(report.modified_files) == 2


def test_stage_sigs_missing_source_raises(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    missing = tmp_path / "does-not-exist"
    with pytest.raises(RuntimeError, match="--sigs source not found"):
        stage_sigs(missing, tmp_path / "sig", dry_run=False, report=InstallReport())


def test_stage_sigs_refuses_symlinked_destination_root(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    sig_file = tmp_path / "riscv64.sig"
    sig_file.write_bytes(b"signature")
    outside = tmp_path / "outside"
    outside.mkdir()
    sig_dir = tmp_path / "ida-pro-9.3" / "sig"
    sig_dir.parent.mkdir()
    sig_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked IDA signature directory"):
        stage_sigs(sig_file, sig_dir, dry_run=False, report=InstallReport())

    assert not (outside / sig_file.name).exists()


def test_stage_sigs_empty_pack_returns_zero_count(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import stage_sigs

    empty = tmp_path / "empty-pack"
    empty.mkdir()
    (empty / "README.txt").write_text("nothing here", encoding="utf-8")

    manifest = stage_sigs(empty, tmp_path / "sig", dry_run=False, report=InstallReport())

    assert manifest.count == 0
    assert manifest.staged == []


def test_stage_riscv_sig_pack_into_ida_sig_dir(tmp_path):
    """The RISC-V sig-pack gap: a riscv64 pack stages into <IDADIR>/sig where
    ida_list_sigs (which globs <IDADIR>/sig/**/*.sig) will surface it."""
    from ida_pro_mcp.installer.common import InstallReport, find_ida_sig_dir
    from ida_pro_mcp.installer.runtime import stage_sigs

    install_dir = tmp_path / "ida-pro-9.3"
    pack = tmp_path / "riscv64-sigpack"
    pack.mkdir()
    # Opaque raw-blob payloads -- FLIRT sigs are binary, not text.
    (pack / "riscv64_rtos.sig").write_bytes(bytes(range(256)) * 4 + b"\x00RISCV-SIG")
    (pack / "riscv64_bootrom.sig").write_bytes(b"\x00RISCV\xf0\xf1bootrom")

    report = InstallReport()
    sig_dir = find_ida_sig_dir(install_dir)
    manifest = stage_sigs(pack, sig_dir, dry_run=False, report=report)

    assert str(sig_dir) == str(install_dir / "sig")
    assert manifest.count == 2
    assert (sig_dir / "riscv64_rtos.sig").is_file()
    assert (sig_dir / "riscv64_bootrom.sig").is_file()
    # The host list_sigs op globs *.sig under this directory, so both files
    # are discoverable by basename.
    discovered = sorted(p.name for p in sig_dir.glob("*.sig"))
    assert discovered == ["riscv64_bootrom.sig", "riscv64_rtos.sig"]


# ---------------------------------------------------------------------------
# installer.runtime: resolve_r2_binary + IDA_MCP_R2_BIN
# ---------------------------------------------------------------------------


def test_resolve_r2_binary_finds_fake_rz_on_path(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import resolve_r2_binary

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_rz = _write_rz_fake(bin_dir, "rz")
    _prepend_path(monkeypatch, bin_dir)

    bin_path, version = resolve_r2_binary()

    assert bin_path == str(fake_rz)
    assert "rizin 0.7.4 fake" in version


def test_resolve_r2_binary_falls_back_to_r2(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import resolve_r2_binary

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_r2 = _write_rz_fake(bin_dir, "r2")
    _prepend_path(monkeypatch, bin_dir)

    bin_path, version = resolve_r2_binary()

    assert bin_path == str(fake_r2)
    assert "radare2 5.9.0 fake" in version


def test_resolve_r2_binary_returns_empty_when_absent(monkeypatch):
    import ida_pro_mcp.installer.runtime as runtime_mod

    monkeypatch.setattr(runtime_mod.shutil, "which", lambda name: None)
    assert runtime_mod.resolve_r2_binary() == ("", "")


def test_build_stdio_config_records_r2_bin(tmp_path):
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(tmp_path / "python", tmp_path, r2_bin="/usr/bin/rz")
    assert cfg["env"].get("IDA_MCP_R2_BIN") == "/usr/bin/rz"

    cfg2 = build_stdio_config(tmp_path / "python", tmp_path)
    assert "IDA_MCP_R2_BIN" not in cfg2["env"]


# ---------------------------------------------------------------------------
# installer.main: run_install integration (hermetic, no live IDA)
# ---------------------------------------------------------------------------


def test_run_install_stages_sigs_with_only_sigs_phase(tmp_path, monkeypatch):
    """`--only sigs --sigs <pack>` resolves the IDA install, stages the pack
    into <IDADIR>/sig, writes the report, and exits 0 -- without touching
    runtime/clients/skills phases."""
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    install_root = tmp_path / "install-root"
    install_root.mkdir()
    install_dir = tmp_path / "ida-pro-9.3"
    install_dir.mkdir()
    pack = _make_sig_pack(tmp_path)

    opts = InstallerOptions(
        interactive=False,
        only={"sigs"},
        install_root=install_root,
        sigs_dir=str(pack),
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", lambda: [_fake_ida_install(install_dir)])

    assert main_mod.run_install(opts, main_mod.UI()) == 0

    sig_dir = install_dir / "sig"
    assert (sig_dir / "riscv64_musl.sig").is_file()
    assert (sig_dir / "riscv64_libc.sig.gz").is_file()
    # The install report records the staged manifest.
    report_path = install_root / "install-report.json"
    assert report_path.is_file()
    import json

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["sigs_manifest"]["count"] == 3
    assert payload["metadata"]["sigs_manifest"]["sig_dir"] == str(sig_dir)


def test_run_install_with_r2_records_env_into_client_config(tmp_path, monkeypatch):
    """`--only clients --with-r2` records the resolved rz/r2 as IDA_MCP_R2_BIN
    in the generated client config."""
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    install_root = tmp_path / "install-root"
    install_root.mkdir()
    install_dir = tmp_path / "ida-pro-9.3"
    install_dir.mkdir()

    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=install_root,
        with_r2=True,
        no_ida_prompt=True,
    )
    fake_rz = str(tmp_path / "rz")
    monkeypatch.setattr(main_mod, "detect_ida_installs", lambda: [_fake_ida_install(install_dir)])
    monkeypatch.setattr(main_mod, "resolve_r2_binary", lambda: (fake_rz, "rizin 0.7.4 fake"))
    captured: dict = {}

    def _fake_configure(**kwargs):
        captured["server_cfg"] = kwargs.get("server_cfg")
        return []

    monkeypatch.setattr(main_mod, "configure_clients", _fake_configure)

    assert main_mod.run_install(opts, main_mod.UI()) == 0

    assert captured["server_cfg"]["env"].get("IDA_MCP_R2_BIN") == fake_rz


# ---------------------------------------------------------------------------
# python_environment_kind — IDA 9.4 uv/conda/homebrew interpreter awareness
# ---------------------------------------------------------------------------

def test_python_environment_kind_detects_managed_interpreters(monkeypatch):
    from ida_pro_mcp.installer.runtime import python_environment_kind

    monkeypatch.delenv("UV_ACTIVE", raising=False)
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)

    cases = [
        (str(Path.home() / ".local/share/uv/python/3.12.1/bin/python3"), "uv"),
        ("/opt/homebrew/opt/python@3.12/bin/python3.12", "homebrew"),
        ("/usr/local/Cellar/python@3.12/3.12.4/bin/python3", "homebrew"),
        ("/usr/local/opt/python@3.12/bin/python3", "homebrew"),
        ("/opt/miniconda3/bin/python", "conda"),
        ("/home/user/anaconda3/envs/re/bin/python", "conda"),
        ("/home/user/.pyenv/versions/3.12.4/bin/python", "pyenv"),
        ("/home/user/.asdf/installs/python/3.12.4/bin/python", "asdf"),
        ("/usr/bin/python3", "system"),
        (str(Path.home() / ".venvs/project/bin/python"), "system"),
    ]
    for path, expected in cases:
        assert python_environment_kind(Path(path)) == expected, path

    # uv/conda also announce themselves via env vars regardless of path.
    monkeypatch.setenv("UV_ACTIVE", "1")
    assert python_environment_kind(Path("/usr/bin/python3")) == "uv"
    monkeypatch.delenv("UV_ACTIVE")
    monkeypatch.setenv("CONDA_PREFIX", "/opt/miniconda3")
    assert python_environment_kind(Path("/usr/bin/python3")) == "conda"


# ---------------------------------------------------------------------------
# idalib runtime backend: helpers + client-config env
# ---------------------------------------------------------------------------


def test_find_idalib_python_dir_detected(tmp_path):
    from ida_pro_mcp.installer.runtime import find_idalib_python_dir

    install = tmp_path / "ida-pro-9.4"
    (install / "idalib" / "python" / "idapro").mkdir(parents=True)
    assert find_idalib_python_dir(str(install)) == str(install / "idalib" / "python")


def test_find_idalib_python_dir_missing(tmp_path):
    from ida_pro_mcp.installer.runtime import find_idalib_python_dir

    install = tmp_path / "ida-pro-9.2"
    install.mkdir()
    assert find_idalib_python_dir(str(install)) == ""


def test_activate_idalib_runs_activator(tmp_path, monkeypatch):
    import ida_pro_mcp.installer.runtime as runtime_mod

    install = tmp_path / "ida-pro-9.4"
    (install / "idalib" / "python" / "idapro").mkdir(parents=True)
    activator = install / "idalib" / "python" / "py-activate-idalib.py"
    activator.write_text("exit 0\n")

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=120):
        calls.append(list(cmd))
        class R:
            returncode = 0
            stdout = "activated"
            stderr = ""
        return R()

    monkeypatch.setattr(runtime_mod.subprocess, "run", fake_run)
    ok, detail = runtime_mod.activate_idalib(str(install))
    assert ok is True
    assert calls and calls[0][-2:] == ["-d", str(install)]


def test_activate_idalib_reports_failure(tmp_path, monkeypatch):
    import ida_pro_mcp.installer.runtime as runtime_mod

    install = tmp_path / "ida-pro-9.4"
    (install / "idalib" / "python" / "idapro").mkdir(parents=True)
    (install / "idalib" / "python" / "py-activate-idalib.py").write_text("exit 1\n")

    class R:
        returncode = 1
        stdout = ""
        stderr = "no license"

    monkeypatch.setattr(
        runtime_mod.subprocess, "run", lambda *a, **k: R()
    )
    ok, detail = runtime_mod.activate_idalib(str(install))
    assert ok is False
    assert "no license" in detail


def test_build_stdio_config_records_idalib_runtime(tmp_path):
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(tmp_path / "python", tmp_path, ida_runtime="idalib")
    assert cfg["env"].get("IDA_MCP_RUNTIME") == "idalib"

    cfg2 = build_stdio_config(tmp_path / "python", tmp_path)
    assert "IDA_MCP_RUNTIME" not in cfg2["env"]
