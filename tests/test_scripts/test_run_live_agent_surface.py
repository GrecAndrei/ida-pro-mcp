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
    dummy_model = tmp_path / "model.gguf"
    dummy_server = tmp_path / "llama-server"

    test_args = [
        "run_live_agent_surface.py",
        "--ida-dir", str(dummy_ida),
        "--idat", str(dummy_idat),
        "--binary", str(dummy_bin),
        "--embed-profile", "qwen3-embedding-0.6b",
        "--embed-model", str(dummy_model),
        "--embed-server-bin", str(dummy_server),
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
    assert captured_env["IDA_MCP_EMBED_PROFILE"] == "qwen3-embedding-0.6b"
    assert captured_env["IDA_MCP_EMBED_MODEL"] == str(dummy_model.resolve())
    assert captured_env["IDA_MCP_EMBED_SERVER_BIN"] == str(dummy_server.resolve())
