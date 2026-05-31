#!/usr/bin/env python3
"""Installer entrypoint + compatibility helpers for legacy tests/callers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _bootstrap_import_path() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


_bootstrap_import_path()

from ida_pro_mcp.installer.clients import (  # noqa: E402
    LEGACY_SERVER_NAMES,
    get_config_paths,
    update_json_config as _update_json_config,
    update_opencode_config as _update_opencode_config,
    update_toml_config as _update_toml_config,
)
from ida_pro_mcp.installer.common import InstallReport  # noqa: E402
from ida_pro_mcp.installer.main import main as installer_main  # noqa: E402
from ida_pro_mcp.installer.runtime import (  # noqa: E402
    build_stdio_config,
    detect_ida_install_dir,
    get_install_root,
)


_SOURCE_ROOT = Path(__file__).resolve().parent


def get_mcp_config_paths():
    """Compatibility wrapper used by older tests/callers."""
    cfg = get_config_paths(_SOURCE_ROOT)
    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
    if "XDG_CONFIG_HOME" in os.environ:
        cfg["Copilot CLI"] = xdg / "copilot" / "mcp-config.json"
    else:
        cfg["Copilot CLI"] = home / ".copilot" / "mcp-config.json"
    cfg["OpenCode"] = xdg / "opencode" / "opencode.json"
    return cfg


def get_mcp_server_config(
    install_path: Path,
    client_name: str = "",
    global_vertex_compat: bool = False,
):
    """Compatibility wrapper for previous installer API."""
    python_exe = install_path / ".venv" / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )
    cfg = build_stdio_config(python_exe, install_path)
    if global_vertex_compat or client_name in {
        "Gemini CLI",
        "OpenCode",
        "opencode",
        "Antigravity",
        "Antigravity CLI",
        "Antigravity IDE",
    }:
        cfg.setdefault("env", {})["IDA_MCP_VERTEX_COMPAT"] = "1"
    return cfg


def update_json_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    client_name: str = "",
    install_path: Path | None = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Compatibility wrapper retaining old callable signature."""
    try:
        root = Path(install_path) if install_path is not None else get_install_root()
        report = InstallReport()
        server_cfg = get_mcp_server_config(root, client_name, global_vertex_compat)

        if client_name == "Antigravity CLI":
            plugin_json = config_path.parent / "plugin.json"
            plugin_json.parent.mkdir(parents=True, exist_ok=True)
            if not plugin_json.exists():
                plugin_json.write_text(
                    json.dumps({"name": server_name}, indent=2), encoding="utf-8"
                )

        if client_name == "Copilot CLI":
            # Maintain legacy Copilot format used by existing users/tests.
            config_path.parent.mkdir(parents=True, exist_ok=True)
            if config_path.exists():
                try:
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                except Exception:
                    config = {}
            else:
                config = {}
            config.pop("servers", None)
            mcp_servers = config.setdefault("mcpServers", {})
            for legacy in list(mcp_servers.keys()):
                if legacy != server_name and (
                    legacy in LEGACY_SERVER_NAMES
                    or "ida-pro-mcp" in str(mcp_servers.get(legacy, {})).lower()
                ):
                    mcp_servers.pop(legacy, None)
            mcp_servers[server_name] = {
                "type": "local",
                "command": server_cfg["command"],
                "args": server_cfg.get("args", []),
                "env": server_cfg.get("env", {}),
                "tools": ["*"],
            }
            config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
            return True

        return _update_json_config(
            path=config_path,
            server_name=server_name,
            server_cfg=server_cfg,
            report=report,
            dry_run=False,
        )
    except Exception:
        return False


def update_opencode_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path | None = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Compatibility wrapper retaining old callable signature."""
    try:
        root = Path(install_path) if install_path is not None else get_install_root()
        report = InstallReport()
        server_cfg = get_mcp_server_config(root, "OpenCode", global_vertex_compat)
        return _update_opencode_config(
            path=config_path,
            server_name=server_name,
            server_cfg=server_cfg,
            report=report,
            dry_run=False,
        )
    except Exception:
        return False


def update_toml_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path | None = None,
    client_name: str = "",
    global_vertex_compat: bool = False,
) -> bool:
    """Compatibility wrapper retaining old callable signature."""
    try:
        root = Path(install_path) if install_path is not None else get_install_root()
        report = InstallReport()
        server_cfg = get_mcp_server_config(root, client_name, global_vertex_compat)
        return _update_toml_config(
            path=config_path,
            server_name=server_name,
            server_cfg=server_cfg,
            report=report,
            dry_run=False,
        )
    except Exception:
        return False


def main() -> int:
    return installer_main()


if __name__ == "__main__":
    raise SystemExit(main())
