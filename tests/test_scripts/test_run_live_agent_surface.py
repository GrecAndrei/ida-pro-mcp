"""Unit tests for scripts/run_live_agent_surface.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import run_live_agent_surface


def test_main_cli_argument_parsing_and_env(monkeypatch, tmp_path):
    captured_cmd = []
    captured_env = {}

    def mock_subprocess_run(cmd, cwd=None, env=None, check=False):
        captured_cmd.extend(cmd)
        captured_env.update(env or {})
        return mock.MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    dummy_ida = tmp_path / "ida"
    dummy_idat = tmp_path / "ida" / "idat64"
    dummy_bin = tmp_path / "test.bin"
    test_args = [
        "run_live_agent_surface.py",
        "--ida-dir", str(dummy_ida),
        "--idat", str(dummy_idat),
        "--binary", str(dummy_bin),
        "--intelligence-mode", "disabled",
        "--jev-model", "jev-latest",
        "--call-timeout", "60",
        "--pytest-timeout", "120",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    rc = run_live_agent_surface.main()
    assert rc == 0
    assert "pytest" in captured_cmd
    assert "-m" in captured_cmd
    assert "live_ida" in captured_cmd
    assert captured_env["IDA_MCP_LIVE_TEST"] == "1"
    assert captured_env["IDA_MCP_LIVE_CALL_TIMEOUT"] == "60"
    assert captured_env["IDA_MCP_LIVE_IDADIR"] == str(dummy_ida.resolve())
    assert captured_env["IDA_MCP_LIVE_IDAT"] == str(dummy_idat.resolve())
    assert captured_env["IDA_MCP_LIVE_BINARY"] == str(dummy_bin.resolve())
    assert captured_env["IDA_MCP_INTELLIGENCE_MODE"] == "disabled"
    assert captured_env["IDA_MCP_JEV_MODEL"] == "jev-latest"
    assert captured_env["IDA_MCP_INTELLIGENCE_ENABLED"] == "0"


def _run(monkeypatch, args, capsys):
    captured: dict = {}

    def mock_subprocess_run(cmd, cwd=None, env=None, check=False):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(env or {})
        return mock.MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    monkeypatch.setattr(sys, "argv", ["run_live_agent_surface.py", *args])
    rc = run_live_agent_surface.main()
    return rc, captured, capsys.readouterr().out


def test_layer_switch_defaults_to_off_and_warns(monkeypatch, capsys):
    rc, captured, out = _run(
        monkeypatch, ["--intelligence-mode", "custom"], capsys
    )
    assert rc == 0
    assert captured["env"]["IDA_MCP_INTELLIGENCE_MODE"] == "custom"
    assert captured["env"]["IDA_MCP_INTELLIGENCE_ENABLED"] == "0"
    assert "intelligence layer is off" in out
    assert "--intelligence-enabled" in out


def test_layer_switch_arms_provider_without_warnings(monkeypatch, capsys):
    rc, captured, out = _run(
        monkeypatch,
        ["--intelligence-mode", "custom", "--intelligence-enabled"],
        capsys,
    )
    assert rc == 0
    assert captured["env"]["IDA_MCP_INTELLIGENCE_ENABLED"] == "1"
    assert "intelligence layer is off" not in out


def test_jev_spend_gate_warns_until_priced(monkeypatch, capsys):
    rc, captured, out = _run(
        monkeypatch, ["--intelligence-mode", "jev", "--intelligence-enabled"], capsys
    )
    assert rc == 0
    assert captured["env"]["IDA_MCP_INTELLIGENCE_ENABLED"] == "1"
    assert "IDA_MCP_JEV_INPUT_USD_PER_MTOK" not in captured["env"]
    assert "Jev spend is disabled" in out

    rc, captured, out = _run(
        monkeypatch,
        ["--intelligence-mode", "jev", "--intelligence-enabled",
         "--jev-input-usd-per-mtok", "0.042", "--jev-output-usd-per-mtok", "0"],
        capsys,
    )
    assert rc == 0
    assert captured["env"]["IDA_MCP_JEV_INPUT_USD_PER_MTOK"] == "0.042"
    assert captured["env"]["IDA_MCP_JEV_OUTPUT_USD_PER_MTOK"] == "0"
    assert "Jev spend is disabled" not in out


def test_disabled_mode_emits_no_provider_warnings(monkeypatch, capsys):
    rc, captured, out = _run(
        monkeypatch, ["--intelligence-mode", "disabled"], capsys
    )
    assert rc == 0
    assert captured["env"]["IDA_MCP_INTELLIGENCE_ENABLED"] == "0"
    assert "intelligence layer is off" not in out
    assert "Jev spend is disabled" not in out
