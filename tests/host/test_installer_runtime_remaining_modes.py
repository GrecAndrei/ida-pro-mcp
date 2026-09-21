"""Exercise installer runtime branches that are easy to miss in happy paths."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.installer import runtime
from ida_pro_mcp.installer.common import InstallReport


class _Response:
    def __init__(self, body: bytes = b"", headers: dict[str, str] | None = None):
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        body, self.body = self.body, b""
        return body


def test_runtime_process_commands_fail_closed_across_platforms(tmp_path, monkeypatch):
    target = tmp_path / "idat64"
    target.write_bytes(b"ida")

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **_kwargs: (_ for _ in ()).throw(OSError("wmic missing"))
        if command[0] == "wmic"
        else subprocess.CompletedProcess(command, 0),
    )
    assert runtime.kill_ida_processes(target) is False

    def windows_timeout(command, **_kwargs):
        if command[0] == "taskkill":
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", windows_timeout)
    assert runtime.kill_ida_processes() is False

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 2, stdout="", stderr="")
        if command[0] == "pgrep"
        else subprocess.CompletedProcess(command, 0),
    )
    assert runtime.kill_ida_processes(target) is False

    calls = []

    def scoped_kill(command, **_kwargs):
        calls.append(command)
        if command[0] == "pgrep":
            return subprocess.CompletedProcess(command, 0, stdout=f"123 {target}\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad")

    monkeypatch.setattr(runtime.subprocess, "run", scoped_kill)
    assert runtime.kill_ida_processes(target) is False
    assert ["kill", "-KILL", "123"] in calls

    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("pkill missing")),
    )
    assert runtime.kill_ida_processes() is False


def test_stage_sigs_reports_single_file_invalid_and_racing_destinations(tmp_path, monkeypatch):
    report = InstallReport()
    missing = tmp_path / "missing"
    with pytest.raises(RuntimeError, match="source not found"):
        runtime.stage_sigs(missing, tmp_path / "sig", False, report)

    non_sig = tmp_path / "notes.txt"
    non_sig.write_text("not a signature", encoding="utf-8")
    manifest = runtime.stage_sigs(non_sig, tmp_path / "sig", False, report)
    assert manifest.staged == [] and manifest.skipped == []

    source = tmp_path / "source"
    source.mkdir()
    signature = source / "nested" / "one.sig"
    signature.parent.mkdir()
    signature.write_text("sig", encoding="utf-8")
    linked = source / "linked.sig"
    linked.symlink_to(signature)
    sig_dir = tmp_path / "ida" / "sig"
    sig_dir.mkdir(parents=True)
    existing = sig_dir / "nested" / "one.sig"
    existing.parent.mkdir()
    existing.write_text("bundled", encoding="utf-8")
    manifest = runtime.stage_sigs(source, sig_dir, False, report)
    assert str(existing) in manifest.skipped
    assert any("non-regular" in warning for warning in report.warnings)

    race = source / "race.sig"
    race.write_text("race", encoding="utf-8")
    monkeypatch.setattr(
        runtime,
        "_copy_file_atomically",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileExistsError("raced")),
    )
    raced = runtime.stage_sigs(source, tmp_path / "race-sig", False, InstallReport())
    assert str(tmp_path / "race-sig" / "race.sig") in raced.skipped


@pytest.mark.parametrize("raw", ["", "relative/site", "first\nsecond"])
def test_pth_helpers_reject_unusable_site_package_reports(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=raw, stderr=""),
    )
    report = InstallReport()
    with pytest.raises(RuntimeError):
        runtime._write_dev_pth(tmp_path / "venv", tmp_path / "source", False, report)
    with pytest.raises(RuntimeError):
        runtime._remove_dev_pth(tmp_path / "venv", report)


def test_pth_dry_run_and_runtime_source_modes(tmp_path, monkeypatch):
    site = tmp_path / "site-packages"
    site.mkdir()
    venv = tmp_path / "venv"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=f"{site}\n", stderr=""),
    )
    report = InstallReport()
    pth = runtime._write_dev_pth(venv, source, True, report)
    assert pth == site / "ida_pro_mcp_dev.pth"
    assert report.steps[-1]["status"] == "dry-run"

    install = tmp_path / "install"
    (install / ".venv").mkdir(parents=True)
    calls = []
    monkeypatch.setattr(runtime, "_probe_venv", lambda _python: True)
    monkeypatch.setattr(runtime, "_write_dev_pth", lambda *args: calls.append("local") or site / "x.pth")
    monkeypatch.setattr(runtime, "_remove_dev_pth", lambda *args: calls.append("remove"))
    monkeypatch.setattr(runtime, "_snapshot_source", lambda *args: install / "snapshot")
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda command, **_kwargs: calls.append(command) or SimpleNamespace(stdout="ok\n", stderr=""),
    )
    local_report = InstallReport()
    runtime.setup_runtime_environment(install, source, "local", False, local_report)
    assert "local" in calls and local_report.metadata["runtime_source"] == "local-dev"

    calls.clear()
    snapshot_report = InstallReport()
    runtime.setup_runtime_environment(install, source, "snapshot", False, snapshot_report)
    assert "remove" in calls and any(
        command[-2:] == ["install", str(install / "snapshot")]
        for command in calls
        if isinstance(command, list)
    )


def test_idalib_path_safety(tmp_path):
    ida = tmp_path / "ida"
    python_dir = ida / "idalib" / "python"
    (python_dir / "idapro").mkdir(parents=True)
    script = python_dir / "py-activate-idalib.py"
    script.write_text("activate", encoding="utf-8")
    script.unlink()
    assert runtime.activate_idalib(str(ida)) == (False, f"no py-activate-idalib.py under {ida}")
