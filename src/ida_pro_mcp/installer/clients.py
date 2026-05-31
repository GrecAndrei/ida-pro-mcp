from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

from .common import InstallReport


LEGACY_SERVER_NAMES = (
    "github.com/GrecAndrei/ida-pro-mcp",
    "ida_mcp",
    "ida-pro-mcp-server",
)


def load_client_map(source_root: Path) -> dict:
    config_path = source_root / "client_configs.json"
    if not config_path.exists():
        return {}
    data = json.loads(config_path.read_text(encoding="utf-8"))
    return data.get("clients", {})


def backup_file(path: Path, report: InstallReport, dry_run: bool) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{stamp}")
    if not dry_run:
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    report.add_backup(path, backup)
    return backup


def _looks_like_ida_mcp_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    tokens: list[str] = []
    cmd = entry.get("command")
    args = entry.get("args")
    if isinstance(cmd, str):
        tokens.append(cmd)
    elif isinstance(cmd, list):
        tokens.extend(str(x) for x in cmd)
    if isinstance(args, str):
        tokens.append(args)
    elif isinstance(args, list):
        tokens.extend(str(x) for x in args)
    text = " ".join(tokens).lower()
    return ("ida_mcp_stdio.py" in text) or ("ida-pro-mcp" in text)


def _prune_legacy_entries(container: dict, server_name: str) -> None:
    to_remove = []
    for key, value in container.items():
        if key == server_name:
            continue
        if key in LEGACY_SERVER_NAMES or _looks_like_ida_mcp_entry(value):
            to_remove.append(key)
    for key in to_remove:
        container.pop(key, None)


def _toml_key(key: str) -> str:
    if re.match(r"^[A-Za-z0-9_-]+$", key):
        return key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_literal(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_literal(v) for v in value) + "]"
    raise TypeError(f"Unsupported TOML value type: {type(value)}")


def _toml_dump_simple(data: dict) -> str:
    lines: list[str] = []

    def emit_table(table: dict, path: list[str]) -> None:
        scalar_items = []
        table_items = []
        for k, v in table.items():
            if isinstance(v, dict):
                table_items.append((k, v))
            else:
                scalar_items.append((k, v))
        if path:
            if lines:
                lines.append("")
            lines.append(f"[{'.'.join(_toml_key(p) for p in path)}]")
        for k, v in scalar_items:
            lines.append(f"{_toml_key(k)} = {_toml_literal(v)}")
        for k, sub in table_items:
            emit_table(sub, path + [k])

    emit_table(data, [])
    return "\n".join(lines) + "\n"


def get_config_paths(source_root: Path) -> dict[str, Path]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
    is_windows = os.name == "nt"
    raw = load_client_map(source_root)

    def resolve(path_template: str) -> Path:
        rendered = (
            path_template.replace("{home}", str(home))
            .replace("{appdata}", str(appdata))
            .replace("{xdg_config}", str(xdg_config))
        )
        return Path(rendered)

    out: dict[str, Path] = {}
    for name, meta in raw.items():
        paths = meta.get("paths", [])
        env_override = meta.get("env_override")
        pick_existing = bool(meta.get("pick_existing", False))
        if env_override and os.environ.get(env_override):
            out[name] = Path(os.environ[env_override]).expanduser()
            continue
        if isinstance(paths, dict):
            out[name] = resolve(paths.get("windows" if is_windows else "unix", ""))
            continue
        candidates = [resolve(p) for p in paths]
        if pick_existing:
            existing = next((p for p in candidates if p.exists()), None)
            out[name] = existing or candidates[0]
        else:
            out[name] = candidates[0]
    return out


def update_json_config(path: Path, server_name: str, server_cfg: dict, report: InstallReport, dry_run: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_file(path, report, dry_run)
    config = {}
    if path.exists():
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            config = {}
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    _prune_legacy_entries(config["mcpServers"], server_name)
    config["mcpServers"][server_name] = server_cfg
    if not dry_run:
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    report.add_modified(path)
    return True


def update_opencode_config(path: Path, server_name: str, server_cfg: dict, report: InstallReport, dry_run: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_file(path, report, dry_run)
    config = {}
    if path.exists():
        content = path.read_text(encoding="utf-8")
        content = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
        try:
            config = json.loads(content)
        except Exception:
            config = {}
    config.setdefault("$schema", "https://opencode.ai/config.json")
    config.setdefault("mcp", {})
    _prune_legacy_entries(config["mcp"], server_name)
    config["mcp"][server_name] = {
        "type": "local",
        "command": [server_cfg["command"], *server_cfg.get("args", [])],
        "enabled": True,
        "environment": server_cfg.get("env", {}),
    }
    if not dry_run:
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    report.add_modified(path)
    return True


def update_toml_config(path: Path, server_name: str, server_cfg: dict, report: InstallReport, dry_run: bool) -> bool:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore

    try:
        import tomli_w
    except ImportError:
        tomli_w = None

    path.parent.mkdir(parents=True, exist_ok=True)
    backup_file(path, report, dry_run)
    config = {}
    if path.exists():
        try:
            config = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            config = {}
    config.setdefault("mcp_servers", {})
    _prune_legacy_entries(config["mcp_servers"], server_name)
    config["mcp_servers"][server_name] = server_cfg
    if not dry_run:
        if tomli_w is not None:
            with open(path, "wb") as f:
                tomli_w.dump(config, f)
        else:
            path.write_text(_toml_dump_simple(config), encoding="utf-8")
    report.add_modified(path)
    return True


def configure_clients(
    source_root: Path,
    server_cfg: dict,
    report: InstallReport,
    dry_run: bool,
    server_name: str = "ida-pro-mcp",
) -> list[str]:
    configured: list[str] = []
    for client, path in get_config_paths(source_root).items():
        try:
            if client == "OpenCode":
                ok = update_opencode_config(path, server_name, server_cfg, report, dry_run)
            elif path.suffix == ".toml":
                ok = update_toml_config(path, server_name, server_cfg, report, dry_run)
            else:
                ok = update_json_config(path, server_name, server_cfg, report, dry_run)
            if ok:
                configured.append(client)
        except Exception as exc:
            report.add_warning(f"{client} config update failed: {exc}")
    return configured


def rollback_from_backups(report: InstallReport) -> None:
    for item in reversed(report.backups):
        target = Path(item["target"])
        backup = Path(item["backup"])
        if not backup.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)
