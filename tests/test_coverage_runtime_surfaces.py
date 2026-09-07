"""Offline coverage for installer runtime, download, and platform boundaries."""

from __future__ import annotations

import io
import os
import subprocess
import types
from pathlib import Path

import pytest

from ida_pro_mcp.installer import runtime
from ida_pro_mcp.installer.common import InstallReport


def test_runtime_url_and_limited_reader_guards():
    profile = types.SimpleNamespace(
        download_url="https://huggingface.co/org/model/resolve/main/model.gguf",
        download_revision="a" * 40,
    )
    assert runtime._profile_download_url(profile).endswith(f"resolve/{'a' * 40}/model.gguf")
    for bad in (
        types.SimpleNamespace(download_url="https://example.test/model", download_revision="a" * 40),
        types.SimpleNamespace(download_url="https://huggingface.co/model/resolve/main/model", download_revision="bad"),
    ):
        assert runtime._profile_download_url(bad) == ""
    with pytest.raises(ValueError):
        runtime._read_response_limited(io.BytesIO(b"x"), max_bytes=-1, label="data")
    with pytest.raises(RuntimeError, match="safety limit"):
        runtime._read_response_limited(io.BytesIO(b"12345"), max_bytes=4, label="data")
    assert runtime._read_response_limited(io.BytesIO(b"1234"), max_bytes=4, label="data") == b"1234"


def test_kill_ida_processes_scopes_linux_and_windows(monkeypatch, tmp_path):
    target = tmp_path / "idat64"
    target.write_text("binary", encoding="ascii")
    commands = []

    def linux_run(command, **_kwargs):
        commands.append(command)
        if command[0] == "pgrep":
            return types.SimpleNamespace(
                returncode=0,
                stdout=f"101 {target}\nnot-a-pid /other\n102 /other-idat\n",
            )
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.subprocess, "run", linux_run)
    assert runtime.kill_ida_processes(target) is True
    assert [command[0] for command in commands] == ["pgrep", "kill"]

    def windows_run(command, **_kwargs):
        commands.append(command)
        if command[0] == "wmic":
            return types.SimpleNamespace(returncode=0, stdout=f"Node,{target},201\nNode,,bad\n")
        return types.SimpleNamespace(returncode=0)

    commands.clear()
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(runtime.subprocess, "run", windows_run)
    assert runtime.kill_ida_processes(target) is True
    assert commands[-1][:3] == ["taskkill", "/F", "/PID"]

    def failed_kill(command, **_kwargs):
        if command[0] in {"pgrep", "wmic"}:
            return types.SimpleNamespace(returncode=0, stdout=f"Node,{target},201\n") if command[0] == "wmic" else types.SimpleNamespace(returncode=0, stdout=f"201 {target}\n")
        return types.SimpleNamespace(returncode=1)

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.subprocess, "run", failed_kill)
    assert runtime.kill_ida_processes(target) is False
    monkeypatch.setattr(runtime.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(OSError("missing")))
    assert runtime.kill_ida_processes() is False


def test_runtime_discovery_sigs_and_bundled_setup(monkeypatch, tmp_path):
    server_dir = tmp_path / "localappdata" / "Programs" / "llama.cpp" / "bin"
    server_dir.mkdir(parents=True)
    server = server_dir / "llama-server.exe"
    server.write_text("server", encoding="ascii")
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    assert runtime.find_llama_server_bin(tmp_path / "install") == str(server)

    signature = tmp_path / "one.sig"
    signature.write_text("sig", encoding="ascii")
    report = InstallReport()
    manifest = runtime.stage_sigs(signature, tmp_path / "ida" / "sig", False, report)
    assert manifest.staged == [str(tmp_path / "ida" / "sig" / "one.sig")]
    assert (tmp_path / "ida" / "sig" / "one.sig").read_text(encoding="ascii") == "sig"
    dry_report = InstallReport()
    dry = runtime.stage_sigs(signature, tmp_path / "ida-dry" / "sig", True, dry_report)
    assert dry.dry_run is True
    assert not (tmp_path / "ida-dry" / "sig" / "one.sig").exists()

    bundled = tmp_path / "bundle" / "runtime" / "bin" / "python3"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("python", encoding="ascii")
    bundled.chmod(0o755)
    report = InstallReport()
    result = runtime.setup_runtime_environment(
        tmp_path / "install", tmp_path / "bundle", "snapshot", False, report
    )
    assert result == bundled
    assert report.metadata["runtime_source"] == "bundled"
    assert (tmp_path / "install" / "bin" / "ida-pro-mcp").is_file()


def test_runtime_venv_probe_and_wipe_failure_modes(monkeypatch, tmp_path):
    missing = tmp_path / "missing-python"
    assert runtime._probe_venv(missing) is False
    python = tmp_path / "python"
    python.write_text("python", encoding="ascii")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(OSError("bad")))
    assert runtime._probe_venv(python) is False
    monkeypatch.setattr(runtime.subprocess, "run", lambda *_a, **_k: types.SimpleNamespace(returncode=1, stdout=""))
    assert runtime._probe_venv(python) is False

    regular = tmp_path / "regular"
    regular.write_text("old", encoding="ascii")
    runtime._wipe_venv(regular)
    assert not regular.exists()

    stale = tmp_path / "stale"
    stale.mkdir()
    clock = iter((0.0, 1.0, 20.0, 20.0))
    monkeypatch.setattr(runtime.time, "time", lambda: next(clock))
    monkeypatch.setattr(runtime.shutil, "rmtree", lambda *_a, **_k: (_ for _ in ()).throw(OSError("busy")))
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)
    runtime._wipe_venv(stale)
    assert any(path.name.startswith(".venv.stale.") for path in tmp_path.iterdir())

    impossible = tmp_path / "impossible"
    impossible.mkdir()
    clock = iter((0.0, 20.0, 20.0))
    monkeypatch.setattr(runtime.time, "time", lambda: next(clock))
    monkeypatch.setattr(runtime.Path, "rename", lambda *_a, **_k: (_ for _ in ()).throw(OSError("no rename")))
    with pytest.raises(RuntimeError, match="Could not remove stale venv"):
        runtime._wipe_venv(impossible)


def test_runtime_dev_pth_write_remove_and_dry_run(monkeypatch, tmp_path):
    venv = tmp_path / "venv"
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir(parents=True)
    stale_pkg = site_packages / "ida_pro_mcp"
    stale_pkg.mkdir()
    dist_info = site_packages / "ida_pro_mcp-1.dist-info"
    dist_info.mkdir()
    pth = site_packages / "ida_pro_mcp_dev.pth"
    pth.write_text("old", encoding="ascii")
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda *_a, **_k: types.SimpleNamespace(stdout=f"{site_packages}\n", stderr="", returncode=0),
    )
    monkeypatch.setattr("ida_pro_mcp.installer.clients.backup_file", lambda *_a, **_k: None)
    report = InstallReport()
    assert runtime._write_dev_pth(venv, tmp_path / "source", False, report) == pth
    assert pth.read_text(encoding="ascii").strip().endswith("source/src")
    assert not stale_pkg.exists() and not dist_info.exists()

    pth.write_text("live", encoding="ascii")
    report = InstallReport()
    runtime._remove_dev_pth(venv, report)
    assert not pth.exists()

    dry = InstallReport()
    assert runtime._write_dev_pth(venv, tmp_path / "source", True, dry) == pth
