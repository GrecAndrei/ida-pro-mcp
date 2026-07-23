from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .common import InstallReport

# Canonical legacy server identifiers that should be migrated/replaced with
# the current canonical MCP server name.
LEGACY_SERVER_NAMES = (
    "github.com/GrecAndrei/ida-pro-mcp",
    "ida_mcp",
    "ida-pro-mcp-server",
)


def _atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Atomically replace `path` with `content` via tmp file + os.replace.

    A mid-write crash leaves either the old file or the new file in place —
    never a half-written byte stream that would brick the MCP client
    (audit §6.4).  The tmp file lives in the same directory so the rename
    stays on one filesystem.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # Best-effort cleanup of stragglers; never mask the original error.
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    """Atomically replace `path` with `content` (binary)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with open(tmp, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def load_client_map(source_root: Path) -> dict:
    candidates = [
        source_root / "client_configs.json",
        Path(__file__).resolve().parent / "client_configs.json",
    ]
    for config_path in candidates:
        if config_path.exists():
            data = json.loads(config_path.read_text(encoding="utf-8"))
            return data.get("clients", {})
    return {}


def backup_file(path: Path, report: InstallReport, dry_run: bool) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
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


def _prepare_config_path(path: Path, report: InstallReport, dry_run: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_file(path, report, dry_run)


def _strip_jsonc_comments(text: str) -> str:
    """Strip // and /* */ comments from JSONC/JSON5 text while preserving strings.

    Trailing commas left by removed comments are normalized so json.loads succeeds.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    string_quote = ""
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == string_quote:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_string = True
            string_quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    cleaned = re.sub(r",(\s*[\]\}])", r"\1", cleaned)
    return cleaned


class ConfigParseError(Exception):
    """Raised when an existing config file cannot be parsed.

    The installer refuses to write back to a file it cannot read; doing otherwise
    would silently wipe the user's settings.
    """


def _load_json_config(path: Path, *, allow_comments: bool = True) -> dict:
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigParseError(f"Could not read {path}: {exc}") from exc

    if not content.strip():
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    if not allow_comments:
        raise ConfigParseError(
            f"{path} is not strict JSON. Strict mode is enforced for this client; "
            "fix the syntax or remove the file before retrying."
        )
    try:
        return json.loads(_strip_jsonc_comments(content))
    except json.JSONDecodeError as exc:
        raise ConfigParseError(
            f"Could not parse {path} as JSON or JSONC: {exc}. "
            "Fix the syntax or remove the file before retrying."
        ) from exc


def _upsert_server_entry(container: dict, server_name: str, server_cfg: dict) -> None:
    _prune_legacy_entries(container, server_name)
    container[server_name] = server_cfg


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
    _prepare_config_path(path, report, dry_run)
    try:
        config = _load_json_config(path, allow_comments=True)
    except ConfigParseError as exc:
        report.add_error(str(exc))
        return False
    config.setdefault("mcpServers", {})
    _upsert_server_entry(config["mcpServers"], server_name, server_cfg)
    if not dry_run:
        _atomic_write_text(path, json.dumps(config, indent=2))
    report.add_modified(path)
    return True


def update_opencode_config(path: Path, server_name: str, server_cfg: dict, report: InstallReport, dry_run: bool) -> bool:
    _prepare_config_path(path, report, dry_run)
    try:
        config = _load_json_config(path, allow_comments=True)
    except ConfigParseError as exc:
        report.add_error(str(exc))
        return False
    config.setdefault("$schema", "https://opencode.ai/config.json")
    config.setdefault("mcp", {})
    opencode_entry = {
        "type": "local",
        "command": [server_cfg["command"], *server_cfg.get("args", [])],
        "enabled": True,
        "environment": server_cfg.get("env", {}),
    }
    _upsert_server_entry(config["mcp"], server_name, opencode_entry)
    if not dry_run:
        _atomic_write_text(path, json.dumps(config, indent=2))
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

    _prepare_config_path(path, report, dry_run)
    config = {}
    if path.exists():
        try:
            config = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            report.add_error(
                f"Could not parse {path} as TOML: {exc}. "
                "Fix the syntax or remove the file before retrying."
            )
            return False
    config.setdefault("mcp_servers", {})
    _upsert_server_entry(config["mcp_servers"], server_name, server_cfg)
    if not dry_run:
        if tomli_w is not None:
            import io
            buf = io.BytesIO()
            tomli_w.dump(config, buf)
            _atomic_write_bytes(path, buf.getvalue())
        else:
            _atomic_write_text(path, _toml_dump_simple(config))
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
