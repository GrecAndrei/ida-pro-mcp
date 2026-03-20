#!/usr/bin/env python3
"""
Linux support regression tests for IDA discovery.
"""

import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from ida_mcp_stdio import IDAMCPServer
import install
import threading


class TestLinuxIdaDetection(unittest.TestCase):
    def _make_exec(self, path: Path):
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)

    def test_detect_ida_dir_from_ida_mcp_idat(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            server = IDAMCPServer.__new__(IDAMCPServer)
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {"IDA_MCP_IDAT": str(idat)}, clear=False):
                    detected = server._detect_ida_dir()
            self.assertEqual(Path(detected), Path(td))

    def test_find_idat_from_ida_dir(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            server = IDAMCPServer.__new__(IDAMCPServer)
            server.ida_dir = td
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {}, clear=False):
                    found = server._find_idat()
            self.assertEqual(Path(found), idat)

    def test_find_idat_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            server = IDAMCPServer.__new__(IDAMCPServer)
            server.ida_dir = ""
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {}, clear=False):
                    with patch("shutil.which", return_value=str(idat)):
                        found = server._find_idat()
            self.assertEqual(Path(found), idat)


class TestInstallIdaDetection(unittest.TestCase):
    def _make_exec(self, path: Path):
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)

    def test_detect_install_dir_from_ida_mcp_idat(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {"IDA_MCP_IDAT": str(idat)}, clear=False):
                    detected = install.detect_ida_install_dir()
            self.assertEqual(detected, Path(td))


class TestInstallLinuxConfigPaths(unittest.TestCase):
    def test_linux_paths_default(self):
        with patch.object(sys, "platform", "linux"):
            with patch.dict(os.environ, {}, clear=True):
                cfg = install.get_mcp_config_paths()
        home = Path.home()
        self.assertEqual(cfg["Codex"], home / ".codex" / "config.toml")
        self.assertEqual(cfg["Gemini CLI"], home / ".gemini" / "settings.json")
        self.assertEqual(cfg["Claude Code"], home / ".claude.json")
        self.assertEqual(cfg["Copilot CLI"], home / ".copilot" / "mcp-config.json")
        self.assertEqual(cfg["OpenCode"], home / ".config" / "opencode" / "opencode.json")

    def test_linux_paths_with_xdg(self):
        with tempfile.TemporaryDirectory() as td:
            xdg = Path(td) / "xdg"
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}, clear=True):
                    cfg = install.get_mcp_config_paths()
            self.assertEqual(cfg["Copilot CLI"], xdg / "copilot" / "mcp-config.json")
            self.assertEqual(cfg["OpenCode"], xdg / "opencode" / "opencode.json")


class TestInstallerRepairBehavior(unittest.TestCase):
    def test_update_json_replaces_legacy_mcp_entry(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "settings.json"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            legacy = {
                "mcpServers": {
                    "github.com/mrexodia/ida-pro-mcp": {
                        "command": "/old/python",
                        "args": ["-u", "/old/ida_mcp_stdio.py"],
                        "env": {"IDADIR": "/old/ida"},
                    }
                }
            }
            cfg.write_text(json.dumps(legacy), encoding="utf-8")
            ok = install.update_json_config(cfg, client_name="Gemini CLI", install_path=Path(td))
            self.assertTrue(ok)
            repaired = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertIn("ida-pro-mcp", repaired.get("mcpServers", {}))
            self.assertNotIn("github.com/mrexodia/ida-pro-mcp", repaired.get("mcpServers", {}))

    def test_update_opencode_replaces_legacy_mcp_entry(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "opencode.json"
            legacy = {
                "mcp": {
                    "github.com/mrexodia/ida-pro-mcp": {
                        "type": "local",
                        "command": ["/old/python", "-u", "/old/ida_mcp_stdio.py"],
                    }
                }
            }
            cfg.write_text(json.dumps(legacy), encoding="utf-8")
            ok = install.update_opencode_config(cfg, install_path=Path(td))
            self.assertTrue(ok)
            repaired = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertIn("ida-pro-mcp", repaired.get("mcp", {}))
            self.assertNotIn("github.com/mrexodia/ida-pro-mcp", repaired.get("mcp", {}))


class TestRuntimeLeaseCleanup(unittest.TestCase):
    @staticmethod
    def _lease_test_server(lease_dir: str) -> IDAMCPServer:
        server = IDAMCPServer.__new__(IDAMCPServer)
        server._runtime_lease_dir = lease_dir
        server.session_runtimes = {}
        server._runtime_lock = threading.RLock()
        return server

    def test_adopt_cleanup_kills_expired_lease_pid(self):
        with tempfile.TemporaryDirectory() as td:
            server = self._lease_test_server(td)
            server._kill_stale_pid = Mock(return_value=True)
            lease_path = os.path.join(td, "SID_DEADBEEF.lease.json")
            with open(lease_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": "DEADBEEF",
                        "pid": 4242,
                        "port": 31337,
                        "updated_at": 1.0,
                    },
                    f,
                )

            with patch("ida_mcp_stdio.time.time", return_value=1000.0):
                server._adopt_or_cleanup_stale_runtime_leases()

            server._kill_stale_pid.assert_called_once_with(4242)
            self.assertFalse(os.path.exists(lease_path))

    def test_adopt_cleanup_keeps_fresh_lease(self):
        with tempfile.TemporaryDirectory() as td:
            server = self._lease_test_server(td)
            server._kill_stale_pid = Mock(return_value=True)
            lease_path = os.path.join(td, "SID_CAFEBABE.lease.json")
            with open(lease_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": "CAFEBABE",
                        "pid": 5252,
                        "port": 12345,
                        "updated_at": 995.0,
                    },
                    f,
                )

            with patch("ida_mcp_stdio.time.time", return_value=1000.0):
                server._adopt_or_cleanup_stale_runtime_leases()

            server._kill_stale_pid.assert_not_called()
            self.assertTrue(os.path.exists(lease_path))

    def test_shutdown_is_idempotent(self):
        server = IDAMCPServer.__new__(IDAMCPServer)
        server._shutdown = False
        server._shutdown_requested = False
        server._stop_runtime_lease_heartbeat = Mock()
        server._cleanup_all_runtimes = Mock()

        server.shutdown()
        server.shutdown()

        server._stop_runtime_lease_heartbeat.assert_called_once()
        server._cleanup_all_runtimes.assert_called_once()


if __name__ == "__main__":
    unittest.main()
