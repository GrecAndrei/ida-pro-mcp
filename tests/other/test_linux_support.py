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


def _same_path(a, b) -> bool:
    """Compare two paths robustly across Windows short/long form and POSIX.

    On Windows, `tempfile.TemporaryDirectory()` often returns the 8.3
    short form (C:/Users/ALEXAN~1/...) while implementation code that
    calls os.path.expanduser / Path.resolve returns the long form
    (C:/Users/Alexander/...). Use realpath (which calls
    GetFinalPathNameByHandle on Windows) to canonicalize both sides
    to the long form before comparing.
    """
    def _norm(p):
        if p is None:
            return None
        try:
            return os.path.normcase(os.path.realpath(str(p)))
        except Exception:
            try:
                return os.path.normcase(os.path.abspath(str(p)))
            except Exception:
                return str(p)
    return _norm(a) == _norm(b)


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
            self.assertTrue(_same_path(detected, td),
                            f"expected {td!r}, got {detected!r}")

    def test_find_idat_from_ida_dir(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            server = IDAMCPServer.__new__(IDAMCPServer)
            server.ida_dir = td
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {}, clear=False):
                    found = server._find_idat()
            self.assertTrue(_same_path(found, idat),
                            f"expected {idat!r}, got {found!r}")

    def test_find_idat_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            idat = Path(td) / "idat64"
            self._make_exec(idat)
            server = IDAMCPServer.__new__(IDAMCPServer)
            server.ida_dir = ""
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, {}, clear=True):
                    with patch("shutil.which", return_value=str(idat)):
                        with patch.object(server, "_detect_ida_dir", return_value=""):
                            found = server._find_idat()
            self.assertTrue(_same_path(found, idat),
                            f"expected {idat!r}, got {found!r}")


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
            self.assertTrue(_same_path(detected, td),
                            f"expected {td!r}, got {detected!r}")


class TestInstallLinuxConfigPaths(unittest.TestCase):
    def test_linux_paths_default(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            # Path.home() on Windows reads USERPROFILE; on POSIX it reads HOME.
            # Set both so the test is portable.
            env = {"HOME": str(home), "USERPROFILE": str(home)}
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, env, clear=True):
                    cfg = install.get_mcp_config_paths()
        self.assertEqual(cfg["Codex"], home / ".codex" / "config.toml")
        self.assertEqual(cfg["Gemini CLI"], home / ".gemini" / "settings.json")
        self.assertEqual(cfg["Antigravity"], home / ".gemini" / "antigravity" / "mcp_config.json")
        self.assertEqual(cfg["Antigravity IDE"], home / ".gemini" / "antigravity" / "mcp_config.json")
        self.assertEqual(
            cfg["Antigravity CLI"],
            home / ".gemini" / "antigravity-cli" / "plugins" / "ida-pro-mcp" / "mcp_config.json",
        )
        self.assertEqual(cfg["Claude Code"], home / ".claude.json")
        self.assertEqual(cfg["Copilot CLI"], home / ".copilot" / "mcp-config.json")
        self.assertEqual(cfg["OpenCode"], home / ".config" / "opencode" / "opencode.json")

    def test_linux_paths_with_xdg(self):
        with tempfile.TemporaryDirectory() as td:
            xdg = Path(td) / "xdg"
            home = Path(td) / "home"
            home.mkdir()
            env = {"XDG_CONFIG_HOME": str(xdg),
                   "HOME": str(home), "USERPROFILE": str(home)}
            with patch.object(sys, "platform", "linux"):
                with patch.dict(os.environ, env, clear=True):
                    cfg = install.get_mcp_config_paths()
            self.assertEqual(cfg["Copilot CLI"], xdg / "copilot" / "mcp-config.json")
            self.assertEqual(cfg["OpenCode"], xdg / "opencode" / "opencode.json")


class TestInstallerRepairBehavior(unittest.TestCase):
    def test_update_json_replaces_legacy_mcp_entry(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "settings.json"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            legacy_remote_key = next(
                (k for k in install.LEGACY_SERVER_NAMES if isinstance(k, str) and k.startswith("github.com/")),
                "github.com/legacy/ida-pro-mcp",
            )
            legacy = {
                "mcpServers": {
                    legacy_remote_key: {
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
            for legacy_name in install.LEGACY_SERVER_NAMES:
                self.assertNotIn(legacy_name, repaired.get("mcpServers", {}))

    def test_antigravity_enables_vertex_compat(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "plugins" / "ida-pro-mcp" / "mcp_config.json"
            ok = install.update_json_config(cfg, client_name="Antigravity IDE", install_path=Path(td))
            self.assertTrue(ok)
            repaired = json.loads(cfg.read_text(encoding="utf-8"))
            server = repaired.get("mcpServers", {}).get("ida-pro-mcp", {})
            self.assertEqual(server.get("env", {}).get("IDA_MCP_VERTEX_COMPAT"), "1")

    def test_antigravity_cli_writes_plugin_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "plugins" / "ida-pro-mcp" / "mcp_config.json"
            ok = install.update_json_config(cfg, client_name="Antigravity CLI", install_path=Path(td))
            self.assertTrue(ok)
            plugin_json = cfg.parent / "plugin.json"
            self.assertTrue(plugin_json.exists())
            manifest = json.loads(plugin_json.read_text(encoding="utf-8"))
            self.assertEqual(manifest.get("name"), "ida-pro-mcp")

    def test_update_opencode_replaces_legacy_mcp_entry(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "opencode.json"
            legacy_remote_key = next(
                (k for k in install.LEGACY_SERVER_NAMES if isinstance(k, str) and k.startswith("github.com/")),
                "github.com/legacy/ida-pro-mcp",
            )
            legacy = {
                "mcp": {
                    legacy_remote_key: {
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
            for legacy_name in install.LEGACY_SERVER_NAMES:
                self.assertNotIn(legacy_name, repaired.get("mcp", {}))


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
            server._is_expected_ida_process = Mock(return_value=True)
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

            with patch("ida_pro_mcp.host.server.time.time", return_value=1000.0):
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

            with patch("ida_pro_mcp.host.server.time.time", return_value=1000.0):
                server._adopt_or_cleanup_stale_runtime_leases()

            server._kill_stale_pid.assert_not_called()
            self.assertTrue(os.path.exists(lease_path))

    def test_shutdown_is_idempotent(self):
        server = IDAMCPServer.__new__(IDAMCPServer)
        server._shutdown = False
        server._shutdown_requested = False
        server._stop_runtime_lease_heartbeat = Mock()
        server._cleanup_all_runtimes = Mock()
        server.assembler = Mock()

        server.shutdown()
        server.shutdown()

        server._stop_runtime_lease_heartbeat.assert_called_once()
        server._cleanup_all_runtimes.assert_called_once()
        server.assembler.stop.assert_called_once()

    def test_cleanup_skips_mismatched_session_id_and_filename(self):
        with tempfile.TemporaryDirectory() as td:
            server = self._lease_test_server(td)
            server._kill_stale_pid = Mock(return_value=True)
            lease_path = os.path.join(td, "SID_DEADBEEF.lease.json")
            with open(lease_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": "CAFEBABE",
                        "pid": 3333,
                        "updated_at": 1.0,
                    },
                    f,
                )

            with patch("ida_pro_mcp.host.server.time.time", return_value=1000.0):
                server._cleanup_stale_runtime_leases()

            server._kill_stale_pid.assert_not_called()
            self.assertFalse(os.path.exists(lease_path))

    def test_cleanup_keeps_lease_when_kill_fails(self):
        with tempfile.TemporaryDirectory() as td:
            server = self._lease_test_server(td)
            server._kill_stale_pid = Mock(return_value=False)
            server._is_expected_ida_process = Mock(return_value=True)
            lease_path = os.path.join(td, "SID_DEADBEEF.lease.json")
            with open(lease_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": "DEADBEEF",
                        "pid": 4444,
                        "updated_at": 1.0,
                    },
                    f,
                )

            with patch("ida_pro_mcp.host.server.time.time", return_value=1000.0):
                server._cleanup_stale_runtime_leases()

            self.assertTrue(os.path.exists(lease_path))
            with open(lease_path, "r", encoding="utf-8") as f:
                lease = json.load(f)
            self.assertEqual(lease["updated_at"], 1000.0)
            self.assertEqual(lease["last_error"], "terminate_failed")

    def test_cleanup_skips_non_ida_process(self):
        with tempfile.TemporaryDirectory() as td:
            server = self._lease_test_server(td)
            server._kill_stale_pid = Mock(return_value=True)
            server._is_expected_ida_process = Mock(return_value=False)
            lease_path = os.path.join(td, "SID_DEADBEEF.lease.json")
            with open(lease_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": "DEADBEEF",
                        "pid": 5555,
                        "updated_at": 1.0,
                    },
                    f,
                )

            with patch("ida_pro_mcp.host.server.time.time", return_value=1000.0):
                server._cleanup_stale_runtime_leases()

            server._kill_stale_pid.assert_not_called()
            self.assertTrue(os.path.exists(lease_path))


if __name__ == "__main__":
    unittest.main()
