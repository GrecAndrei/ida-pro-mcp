from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.installer.clients import (
    ConfigParseError,
    _looks_like_ida_mcp_entry,
    _prune_legacy_entries,
    _strip_jsonc_comments,
    _toml_dump_simple,
    _toml_key,
    _toml_literal,
    backup_file,
    configure_clients,
    get_config_paths,
    load_client_map,
    rollback_from_backups,
    update_json_config,
    update_opencode_config,
    update_toml_config,
)
from ida_pro_mcp.installer.common import InstallReport


def test_strip_jsonc_comments() -> None:
    jsonc = """
    {
      // Single line comment
      "name": "ida-mcp", /* Inline comment */
      "path": "http://example.com/api", // URL with slashes
      "quote": "hello \\"world\\" // not a comment",
      "items": [
        1,
        2, /* comment inside list */
        3,
      ],
    }
    """
    cleaned = _strip_jsonc_comments(jsonc)
    data = json.loads(cleaned)
    assert data["name"] == "ida-mcp"
    assert data["path"] == "http://example.com/api"
    assert data["quote"] == 'hello "world" // not a comment'
    assert data["items"] == [1, 2, 3]

    # Unterminated block comment raises ValueError
    with pytest.raises(ValueError, match="unterminated block comment"):
        _strip_jsonc_comments('{"a": 1 /* unclosed')


def test_toml_serializer() -> None:
    assert _toml_key("simple_key") == "simple_key"
    assert _toml_key("complex key.with.dots") == '"complex key.with.dots"'

    assert _toml_literal(True) == "true"
    assert _toml_literal(False) == "false"
    assert _toml_literal(42) == "42"
    assert _toml_literal(3.14) == "3.14"
    assert _toml_literal("hello\nworld") == '"hello\\nworld"'
    assert _toml_literal(["a", "b"]) == '["a", "b"]'

    with pytest.raises(TypeError, match="Unsupported TOML value type"):
        _toml_literal(object())

    data = {
        "title": "Config",
        "enabled": True,
        "servers": {
            "ida": {
                "command": "python",
                "args": ["-m", "ida_mcp"],
            }
        },
    }
    dumped = _toml_dump_simple(data)
    assert 'title = "Config"' in dumped
    assert "enabled = true" in dumped
    assert "[servers.ida]" in dumped
    assert 'command = "python"' in dumped


def test_looks_like_ida_mcp_entry_and_prune() -> None:
    entry1 = {"command": "python", "args": ["/path/to/ida_mcp_stdio.py"]}
    entry2 = {"command": ["ida-pro-mcp", "run"]}
    entry3 = {"command": "node", "args": ["server.js"]}

    assert _looks_like_ida_mcp_entry(entry1) is True
    assert _looks_like_ida_mcp_entry(entry2) is True
    assert _looks_like_ida_mcp_entry(entry3) is False
    assert _looks_like_ida_mcp_entry("invalid") is False

    container = {
        "ida_mcp": entry1,
        "github.com/GrecAndrei/ida-pro-mcp": entry2,
        "custom_server": entry3,
        "ida-pro-mcp": entry1,
    }
    _prune_legacy_entries(container, server_name="ida-pro-mcp")
    assert "ida_mcp" not in container
    assert "github.com/GrecAndrei/ida-pro-mcp" not in container
    assert "custom_server" in container
    assert "ida-pro-mcp" in container


def test_update_json_config(tmp_path: Path) -> None:
    config_file = tmp_path / "claude_desktop_config.json"
    report = InstallReport()
    server_cfg = {"command": "python", "args": ["-m", "ida_pro_mcp"]}

    # Initial creation
    ok = update_json_config(config_file, "ida-pro-mcp", server_cfg, report, dry_run=False)
    assert ok is True
    assert config_file.is_file()
    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "ida-pro-mcp" in data["mcpServers"]

    # Updating with invalid JSON syntax creates error in report
    config_file.write_text("{invalid json", encoding="utf-8")
    report2 = InstallReport()
    ok2 = update_json_config(config_file, "ida-pro-mcp", server_cfg, report2, dry_run=False)
    assert ok2 is False
    assert len(report2.errors) > 0


def test_update_opencode_config(tmp_path: Path) -> None:
    config_file = tmp_path / "opencode.json"
    report = InstallReport()
    server_cfg = {"command": "python", "args": ["-m", "ida_pro_mcp"], "env": {"ENV_VAR": "1"}}

    ok = update_opencode_config(config_file, "ida-pro-mcp", server_cfg, report, dry_run=False)
    assert ok is True
    assert config_file.is_file()
    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert data["$schema"] == "https://opencode.ai/config.json"
    assert "mcp" in data
    assert data["mcp"]["ida-pro-mcp"]["type"] == "local"
    assert data["mcp"]["ida-pro-mcp"]["command"] == ["python", "-m", "ida_pro_mcp"]
    assert data["mcp"]["ida-pro-mcp"]["environment"] == {"ENV_VAR": "1"}


def test_update_toml_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    report = InstallReport()
    server_cfg = {"command": "python", "args": ["-m", "ida_pro_mcp"]}

    ok = update_toml_config(config_file, "ida-pro-mcp", server_cfg, report, dry_run=False)
    assert ok is True
    assert config_file.is_file()
    content = config_file.read_text(encoding="utf-8")
    assert "mcp_servers" in content


def test_backup_and_rollback(tmp_path: Path) -> None:
    target = tmp_path / "client.json"
    target.write_text('{"original": true}', encoding="utf-8")

    report = InstallReport()
    backup = backup_file(target, report, dry_run=False)
    assert backup is not None
    assert backup.is_file()

    # Modify original
    target.write_text('{"modified": true}', encoding="utf-8")

    # Add a created file
    created = tmp_path / "created.json"
    created.write_text("temporary", encoding="utf-8")
    report.add_created(created)

    # Perform rollback
    rollback_from_backups(report)
    assert json.loads(target.read_text(encoding="utf-8")) == {"original": True}
    assert not created.exists()
