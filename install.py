#!/usr/bin/env python3
"""Installer entrypoint + compatibility helpers for legacy tests/callers."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any


def _bootstrap_import_path() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


_bootstrap_import_path()

from ida_pro_mcp.installer.clients import (  # noqa: E402
    get_config_paths,
    update_json_config as _update_json_config,
    update_opencode_config as _update_opencode_config,
    update_toml_config as _update_toml_config,
)
from ida_pro_mcp.installer.common import InstallReport  # noqa: E402
from ida_pro_mcp.installer.main import main as installer_main  # noqa: E402
from ida_pro_mcp.installer.runtime import (  # noqa: E402
    build_stdio_config,
    get_install_root,
)

__all__: list[str] = [
    "get_mcp_config_paths",
    "get_mcp_server_config",
    "update_json_config",
    "update_opencode_config",
    "update_toml_config",
    "main",
]

_log = logging.getLogger(__name__)
_SOURCE_ROOT = Path(__file__).resolve().parent

# Clients that expect vertex-compatibility mode enabled by default.
_VERTEX_COMPAT_CLIENTS: frozenset[str] = frozenset({
    "Gemini CLI",
    "OpenCode",
    "opencode",
    "Antigravity",
    "Antigravity CLI",
    "Antigravity IDE",
})


def _resolve_venv_python(install_root: Path) -> Path:
    """Return the Python executable path inside a project venv."""
    return install_root / ".venv" / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )


def get_mcp_config_paths() -> dict[str, Path]:
    """Return a dict of MCP client name → config path.

    Compatibility wrapper used by older tests/callers.  Delegates to the
    installer module's resolution, then applies client-specific overrides.
    """
    cfg = get_config_paths(_SOURCE_ROOT)
    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", "").strip() or str(home / ".config"))
    # Copilot always lives under ~/.copilot regardless of XDG.
    cfg["Copilot CLI"] = home / ".copilot" / "mcp-config.json"
    cfg["OpenCode"] = xdg / "opencode" / "opencode.json"
    return cfg


def get_mcp_server_config(
    install_path: Path,
    client_name: str = "",
    global_vertex_compat: bool = False,
) -> dict[str, Any]:
    """Build an MCP stdio server-config dict.

    Compatibility wrapper that delegates to ``build_stdio_config()`` with
    the venv Python resolved from *install_path*.  Vertex-compat mode is
    enabled when *global_vertex_compat* is set or *client_name* is in the
    known vertex-compat set.
    """
    python_exe = _resolve_venv_python(install_path)
    cfg = build_stdio_config(python_exe, install_path)
    if global_vertex_compat or client_name in _VERTEX_COMPAT_CLIENTS:
        cfg.setdefault("env", {})["IDA_MCP_VERTEX_COMPAT"] = "1"
    return cfg


def _try_update_config(
    install_path: Path | None,
    build_cfg_fn,  # (root) -> dict[str, Any]
    update_fn,     # (path, server_name, server_cfg, report, dry_run) -> bool
    config_path: Path,
    server_name: str,
) -> bool:
    """Shared error-handling wrapper for config update callbacks."""
    try:
        root = Path(install_path) if install_path is not None else get_install_root()
        report = InstallReport()
        server_cfg = build_cfg_fn(root)
        return update_fn(
            path=config_path,
            server_name=server_name,
            server_cfg=server_cfg,
            report=report,
            dry_run=False,
        )
    except Exception:
        _log.exception("Failed to update config at %s", config_path)
        return False


def update_json_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    client_name: str = "",
    install_path: Path | None = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Register *server_name* in a JSON-based MCP client config.

    Compatibility wrapper retaining the old callable signature.
    """
    root = Path(install_path) if install_path is not None else get_install_root()
    report = InstallReport()
    server_cfg = get_mcp_server_config(root, client_name, global_vertex_compat)

    if client_name == "Antigravity CLI":
        return _write_antigravity_plugin(config_path, server_name, server_cfg)

    if client_name == "Copilot CLI":
        return _update_copilot_config(config_path, server_name, server_cfg)

    return _delegate_json_config(config_path, server_name, server_cfg, report)


def _write_antigravity_plugin(
    config_path: Path,
    server_name: str,
    server_cfg: dict[str, Any],
) -> bool:
    """Write Antigravity CLI plugin.json if missing, then delegate to JSON updater."""
    try:
        plugin_json = config_path.parent / "plugin.json"
        from ida_pro_mcp.installer.common import atomic_write_text, reject_symlink_path

        reject_symlink_path(plugin_json, "Antigravity plugin path")
        plugin_json.parent.mkdir(parents=True, exist_ok=True)
        created_plugin = False
        if not plugin_json.exists():
            atomic_write_text(
                plugin_json,
                json.dumps({"name": server_name}, indent=2), encoding="utf-8"
            )
            created_plugin = True
        ok = _delegate_json_config(config_path, server_name, server_cfg, InstallReport())
        if not ok and created_plugin:
            plugin_json.unlink()
        return ok
    except Exception:
        _log.exception("Antigravity plugin config failed")
        return False


def _update_copilot_config(
    config_path: Path,
    server_name: str,
    server_cfg: dict[str, Any],
) -> bool:
    """Write Copilot CLI config in its legacy format through the safe updater."""
    try:
        legacy_cfg = dict(server_cfg)
        legacy_cfg["tools"] = ["*"]
        return _update_json_config(
            path=config_path,
            server_name=server_name,
            server_cfg=legacy_cfg,
            report=InstallReport(),
            dry_run=False,
            top_level_key="mcpServers",
            server_type="local",
        )
    except Exception:
        _log.exception("Copilot CLI config update failed")
        return False


def _delegate_json_config(
    config_path: Path,
    server_name: str,
    server_cfg: dict[str, Any],
    report: InstallReport,
) -> bool:
    """Delegate to the installer module's JSON config updater."""
    try:
        return _update_json_config(
            path=config_path,
            server_name=server_name,
            server_cfg=server_cfg,
            report=report,
            dry_run=False,
        )
    except Exception:
        _log.exception("JSON config update failed for %s", config_path)
        return False


def update_opencode_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path | None = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Register *server_name* in OpenCode's config.

    Compatibility wrapper retaining the old callable signature.
    """
    def _build_cfg(root: Path) -> dict[str, Any]:
        return get_mcp_server_config(root, "OpenCode", global_vertex_compat)

    return _try_update_config(
        install_path, _build_cfg, _update_opencode_config,
        config_path, server_name,
    )


def update_toml_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path | None = None,
    client_name: str = "",
    global_vertex_compat: bool = False,
) -> bool:
    """Register *server_name* in a TOML-based MCP client config.

    Compatibility wrapper retaining the old callable signature.
    """
    def _build_cfg(root: Path) -> dict[str, Any]:
        return get_mcp_server_config(root, client_name, global_vertex_compat)

    return _try_update_config(
        install_path, _build_cfg, _update_toml_config,
        config_path, server_name,
    )


def main() -> int:
    return installer_main()


if __name__ == "__main__":
    raise SystemExit(main())
