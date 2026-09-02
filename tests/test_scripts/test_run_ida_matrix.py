"""Unit tests for scripts/run_ida_matrix.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import run_ida_matrix


def test_detect_installs_explicit():
    installs = run_ida_matrix._detect_installs(["/opt/ida-9.2", "/opt/ida-9.3"])
    assert installs == [("explicit", "/opt/ida-9.2"), ("explicit", "/opt/ida-9.3")]


def test_detect_installs_discovery(monkeypatch):
    mock_install = mock.MagicMock(full_version_str="IDA Pro 9.3", path=Path("/opt/ida-9.3"))
    with mock.patch("ida_pro_mcp.installer.discovery.detect_ida_installs", return_value=[mock_install]):
        installs = run_ida_matrix._detect_installs([])
        assert len(installs) == 1
        assert installs[0] == ("IDA Pro 9.3", "/opt/ida-9.3")


def test_activate_idalib(tmp_path, monkeypatch):
    assert run_ida_matrix._activate_idalib(str(tmp_path)) is False

    # Create dummy activate script
    script_dir = tmp_path / "idalib" / "python"
    script_dir.mkdir(parents=True)
    activate_script = script_dir / "py-activate-idalib.py"
    activate_script.write_text("#!/bin/sh\n")

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: mock.MagicMock(returncode=0))
    assert run_ida_matrix._activate_idalib(str(tmp_path)) is True

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: mock.MagicMock(returncode=1))
    assert run_ida_matrix._activate_idalib(str(tmp_path)) is False


def test_has_idalib_and_glob_whl(tmp_path):
    assert run_ida_matrix._has_idalib(str(tmp_path)) is False

    idapro_dir = tmp_path / "idalib" / "python" / "idapro"
    idapro_dir.mkdir(parents=True)
    assert run_ida_matrix._has_idalib(str(tmp_path)) is True


def test_run_suite(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: mock.MagicMock(returncode=0))
    rc = run_ida_matrix._run_suite({}, "/opt/ida", "IDA 9.3", ["-k", "test_foo"])
    assert rc == 0


def test_main_no_installs(monkeypatch, capsys):
    monkeypatch.setattr(run_ida_matrix, "_detect_installs", lambda explicit: [])
    rc = run_ida_matrix.main([])
    assert rc == 0
    captured = capsys.readouterr()
    assert "no IDA installs detected" in captured.out


def test_main_with_installs_and_idalib(monkeypatch, capsys):
    installs = [("IDA Pro 9.3", "/opt/ida-9.3")]
    monkeypatch.setattr(run_ida_matrix, "_detect_installs", lambda explicit: installs)
    monkeypatch.setattr(run_ida_matrix, "_run_suite", lambda env, install_dir, label, args: 0)
    monkeypatch.setattr(run_ida_matrix, "_has_idalib", lambda install_dir: True)
    monkeypatch.setattr(run_ida_matrix, "_activate_idalib", lambda install_dir: True)

    rc = run_ida_matrix.main(["--idalib"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "all 1 install(s) passed" in captured.out
    assert "PASS  IDA Pro 9.3 (idat)" in captured.out
    assert "PASS  IDA Pro 9.3 (idalib)" in captured.out


def test_main_failure(monkeypatch, capsys):
    installs = [("IDA Pro 9.3", "/opt/ida-9.3")]
    monkeypatch.setattr(run_ida_matrix, "_detect_installs", lambda explicit: installs)
    monkeypatch.setattr(run_ida_matrix, "_run_suite", lambda env, install_dir, label, args: 1)

    rc = run_ida_matrix.main([])
    assert rc == 1
    captured = capsys.readouterr()
    assert "1 leg(s) FAILED" in captured.out
