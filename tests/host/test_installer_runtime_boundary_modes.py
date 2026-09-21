"""Exercise installer runtime helpers through process and filesystem boundaries."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ida_pro_mcp.installer import runtime
from ida_pro_mcp.installer.common import InstallReport


def test_kill_ida_processes_keeps_explicit_scope_on_posix_and_windows(tmp_path, monkeypatch):
    target = tmp_path / "idat64"
    target.write_text("binary", encoding="ascii")
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "pgrep":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"123 {target} -A\n124 /other/idat64\n", stderr="")
        if cmd[0] == "wmic":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"Node,{target},123\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    assert runtime.kill_ida_processes(target) is True
    assert ["kill", "-KILL", "123"] in calls
    assert not any(cmd[:2] == ["kill", "-KILL"] and cmd[-1] == "124" for cmd in calls)

    calls.clear()
    assert runtime.kill_ida_processes() is True
    assert ["pkill", "-x", "idat"] in calls

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    calls.clear()
    assert runtime.kill_ida_processes(target) is True
    assert any(cmd[:3] == ["taskkill", "/F", "/PID"] for cmd in calls)
    calls.clear()
    assert runtime.kill_ida_processes() is True
    assert ["taskkill", "/F", "/IM", "idat.exe"] in calls

    def failed(*_args, **_kwargs):
        raise OSError("pgrep unavailable")

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.subprocess, "run", failed)
    assert runtime.kill_ida_processes(target) is False


def test_snapshot_and_local_pth_setup_prune_stale_runtime_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "module.py").write_text("value = 1", encoding="utf-8")
    (source / ".coverage").write_text("machine output", encoding="utf-8")
    install = tmp_path / "install"
    report = InstallReport()
    dry = runtime._snapshot_source(source, install, True, report)
    assert not dry.exists() and report.steps[-1]["status"] == "dry-run"
    snapshot = runtime._snapshot_source(source, install, False, report)
    assert (snapshot / "src" / "module.py").exists()
    assert not (snapshot / ".coverage").exists()

    venv = install / ".venv"
    site = tmp_path / "site-packages"
    stale_pkg = site / "ida_pro_mcp"
    stale_dist = site / "ida_pro_mcp-1.dist-info"
    stale_pkg.mkdir(parents=True)
    stale_dist.mkdir()
    monkeypatch.setattr(runtime, "_venv_python_exe", lambda _venv: tmp_path / "python")
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=f"{site}\n", stderr=""),
    )
    pth = runtime._write_dev_pth(venv, source, False, report)
    assert pth.read_text(encoding="utf-8").strip() == str(source / "src")
    assert not stale_pkg.exists() and not stale_dist.exists()
    runtime._remove_dev_pth(venv, report)
    assert not pth.exists()
