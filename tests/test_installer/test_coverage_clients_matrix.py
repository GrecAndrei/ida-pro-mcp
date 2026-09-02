"""Offline matrix for client configuration formats and safety boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.installer import clients
from ida_pro_mcp.installer.common import InstallReport


def _cfg() -> dict:
    return {
        "command": "python",
        "args": ["-m", "ida_pro_mcp"],
        "env": {"IDA_PRO_MCP_HOME": "/tmp/mcp"},
    }


def test_client_file_primitives_and_jsonc_edges(tmp_path, monkeypatch):
    monkeypatch.setenv("CLIENT_CFG_ROOT", str(tmp_path))
    assert clients._expand_configured_path("$CLIENT_CFG_ROOT/~/config").parts[-1] == "config"

    text_path = tmp_path / "text.txt"
    clients._atomic_write_text(text_path, "hello")
    assert text_path.read_text(encoding="utf-8") == "hello"
    bytes_path = tmp_path / "data.bin"
    clients._atomic_write_bytes(bytes_path, b"bytes")
    assert bytes_path.read_bytes() == b"bytes"

    source = tmp_path / "source"
    source.mkdir()
    (source / "client_configs.json").write_text(
        json.dumps({"clients": {"A": {"paths": ["a.json"]}}}), encoding="utf-8"
    )
    assert clients.load_client_map(source) == {"A": {"paths": ["a.json"]}}
    assert isinstance(clients.load_client_map(tmp_path / "missing"), dict)

    assert clients._looks_like_ida_mcp_entry(None) is False
    assert clients._looks_like_ida_mcp_entry({"command": ["python", "ida_mcp_stdio.py"]}) is True
    assert clients._looks_like_ida_mcp_entry({"args": "ida-pro-mcp"}) is True
    assert clients._looks_like_ida_mcp_entry({"command": "other", "args": ["--safe"]}) is False
    container = {
        "ida_mcp": {},
        "legacy": {"command": "ida-pro-mcp"},
        "keep": {"command": "other"},
        "current": {"command": "old"},
    }
    clients._upsert_server_entry(container, "current", _cfg())
    assert set(container) == {"current", "keep"}
    assert container["current"]["command"] == "python"

    jsonc = '{\n // comment\n "text": "// keep /* keep */", /* block */\n "items": [1,],\n}'
    stripped = clients._strip_jsonc_comments(jsonc)
    assert json.loads(stripped) == {"text": "// keep /* keep */", "items": [1]}
    with pytest.raises(ValueError, match="unterminated"):
        clients._strip_jsonc_comments('{"x": /* never closes')

    valid = tmp_path / "valid.json"
    valid.write_text('{"mcpServers": {}}', encoding="utf-8")
    assert clients._load_json_config(valid) == {"mcpServers": {}}
    empty = tmp_path / "empty.json"
    empty.write_text("  ", encoding="utf-8")
    assert clients._load_json_config(empty) == {}
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    with pytest.raises(clients.ConfigParseError, match="top-level"):
        clients._load_json_config(scalar)
    comments = tmp_path / "comments.json"
    comments.write_text('{"mcpServers": { /* okay */ }}', encoding="utf-8")
    assert clients._load_json_config(comments)["mcpServers"] == {}
    with pytest.raises(clients.ConfigParseError, match="Strict mode"):
        clients._load_json_config(comments, allow_comments=False)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json}", encoding="utf-8")
    with pytest.raises(clients.ConfigParseError, match="Could not parse"):
        clients._load_json_config(broken)


def test_client_path_selection_and_format_serializers(tmp_path, monkeypatch):
    existing = tmp_path / "existing.json"
    existing.write_text("{}", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    path_map = {
        "Env": {"env_override": "CLIENT_OVERRIDE", "paths": ["unused"]},
        "Platform": {"paths": {"unix": "{home}/unix.json", "windows": "{appdata}/win.json"}},
        "Existing": {"paths": [str(tmp_path / "missing"), str(existing)], "pick_existing": True},
        "First": {"paths": [str(tmp_path / "first")]},
    }
    monkeypatch.setenv("CLIENT_OVERRIDE", str(tmp_path / "override.json"))
    monkeypatch.setattr(clients, "load_client_map", lambda _root: path_map)
    monkeypatch.setattr(clients.os, "name", "posix")
    paths = clients.get_config_paths(source)
    assert paths["Env"] == tmp_path / "override.json"
    assert paths["Platform"].name == "unix.json"
    assert paths["Existing"] == existing
    assert paths["First"] == tmp_path / "first"

    assert clients._toml_key("plain-key") == "plain-key"
    assert clients._toml_key('odd.key\\"') == '"odd.key\\\\\\""'
    assert clients._toml_literal(True) == "true"
    assert clients._toml_literal(False) == "false"
    assert clients._toml_literal(2) == "2"
    assert clients._toml_literal(1.5) == "1.5"
    assert clients._toml_literal('a"b\n') == '"a\\"b\\n"'
    assert clients._toml_literal([True, "x"]) == '[true, "x"]'
    with pytest.raises(TypeError):
        clients._toml_literal(object())
    dumped = clients._toml_dump_simple({"root": 1, "nested": {"key": "value"}})
    assert "root = 1" in dumped and "[nested]" in dumped and 'key = "value"' in dumped


def test_json_and_opencode_updates_cover_nested_and_invalid_shapes(tmp_path):
    report = InstallReport()
    path = tmp_path / "client.json"
    assert clients.update_json_config(path, "ida-pro-mcp", _cfg(), report, False) is True
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["mcpServers"]["ida-pro-mcp"]["command"] == "python"
    assert report.modified_files

    nested = tmp_path / "nested.json"
    assert clients.update_json_config(
        nested, "ida-pro-mcp", _cfg(), InstallReport(), False,
        nested_key="outer.inner", server_type="stdio",
    )
    nested_data = json.loads(nested.read_text(encoding="utf-8"))
    assert nested_data["outer"]["inner"]["ida-pro-mcp"]["type"] == "stdio"

    top_bad = tmp_path / "top-bad.json"
    top_bad.write_text('{"mcpServers": []}', encoding="utf-8")
    bad_report = InstallReport()
    assert clients.update_json_config(top_bad, "x", _cfg(), bad_report, False) is False
    assert bad_report.errors
    nested_bad = tmp_path / "nested-bad.json"
    nested_bad.write_text('{"outer": {"inner": []}}', encoding="utf-8")
    nested_report = InstallReport()
    assert clients.update_json_config(
        nested_bad, "x", _cfg(), nested_report, False, nested_key="outer.inner"
    ) is False
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{nope}", encoding="utf-8")
    assert clients.update_json_config(malformed, "x", _cfg(), InstallReport(), False) is False
    dry = tmp_path / "dry.json"
    assert clients.update_json_config(dry, "x", _cfg(), InstallReport(), True) is True
    assert not dry.exists()

    opencode = tmp_path / "opencode.json"
    assert clients.update_opencode_config(opencode, "ida-pro-mcp", _cfg(), InstallReport(), False)
    opencode_data = json.loads(opencode.read_text(encoding="utf-8"))
    assert opencode_data["mcp"]["ida-pro-mcp"]["command"][0] == "python"
    bad_opencode = tmp_path / "bad-opencode.json"
    bad_opencode.write_text('{"mcp": []}', encoding="utf-8")
    bad_report = InstallReport()
    assert clients.update_opencode_config(bad_opencode, "x", _cfg(), bad_report, False) is False
    malformed_opencode = tmp_path / "malformed-opencode.json"
    malformed_opencode.write_text("{nope}", encoding="utf-8")
    assert clients.update_opencode_config(malformed_opencode, "x", _cfg(), InstallReport(), False) is False


def test_toml_yaml_rollback_and_remove_paths(tmp_path, monkeypatch):
    report = InstallReport()
    toml = tmp_path / "config.toml"
    assert clients.update_toml_config(toml, "ida-pro-mcp", _cfg(), report, False)
    assert "ida-pro-mcp" in toml.read_text(encoding="utf-8")
    invalid_toml = tmp_path / "invalid.toml"
    invalid_toml.write_text("[broken", encoding="utf-8")
    invalid_report = InstallReport()
    assert clients.update_toml_config(invalid_toml, "x", _cfg(), invalid_report, False) is False
    non_table = tmp_path / "non-table.toml"
    non_table.write_text('mcp_servers = "wrong"', encoding="utf-8")
    assert clients.update_toml_config(non_table, "x", _cfg(), InstallReport(), False) is False
    dry_toml = tmp_path / "dry.toml"
    assert clients.update_toml_config(dry_toml, "x", _cfg(), InstallReport(), True)
    assert not dry_toml.exists()

    yaml_path = tmp_path / "config.yaml"
    assert clients.update_yaml_config(yaml_path, "ida-pro-mcp", _cfg(), InstallReport(), False)
    assert "ida-pro-mcp" in yaml_path.read_text(encoding="utf-8")
    yaml_bad = tmp_path / "yaml-bad.yaml"
    yaml_bad.write_text("mcp_servers: []", encoding="utf-8")
    assert clients.update_yaml_config(yaml_bad, "x", _cfg(), InstallReport(), False) is False
    yaml_scalar = tmp_path / "yaml-scalar.yaml"
    yaml_scalar.write_text("- one\n- two\n", encoding="utf-8")
    assert clients.update_yaml_config(yaml_scalar, "x", _cfg(), InstallReport(), False) is False

    original = tmp_path / "original.json"
    original.write_text("old", encoding="utf-8")
    backup_report = InstallReport()
    clients.backup_file(original, backup_report, False)
    backup = Path(backup_report.backups[0]["backup"])
    assert backup.read_text(encoding="utf-8") == "old"
    original.write_text("new", encoding="utf-8")
    clients.rollback_from_backups(backup_report)
    assert original.read_text(encoding="utf-8") == "old"
    created = tmp_path / "created"
    created.write_text("x", encoding="utf-8")
    backup_report.add_created(created)
    clients.rollback_from_backups(backup_report)
    assert not created.exists()
    missing_backup_report = InstallReport()
    missing_backup_report.add_backup(tmp_path / "not-there", tmp_path / "missing.bak")
    clients.rollback_from_backups(missing_backup_report)

    # Exercise removal for JSON, OpenCode, TOML, and YAML using a synthetic
    # client map; each updater sees the same canonical server name.
    root = tmp_path / "clients"
    root.mkdir()
    json_path = root / "j.json"
    json_path.write_text(json.dumps({"mcpServers": {"ida-pro-mcp": _cfg()}}), encoding="utf-8")
    open_path = root / "o.json"
    open_path.write_text(json.dumps({"mcp": {"ida-pro-mcp": {"type": "local"}}}), encoding="utf-8")
    toml_path = root / "t.toml"
    toml_path.write_text('[mcp_servers."ida-pro-mcp"]\ncommand = "python"\n', encoding="utf-8")
    yaml_path = root / "y.yaml"
    yaml_path.write_text("mcp_servers:\n  ida-pro-mcp:\n    command: python\n", encoding="utf-8")
    paths = {"JSON": json_path, "OpenCode": open_path, "TOML": toml_path, "YAML": yaml_path}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    monkeypatch.setattr(
        clients, "_client_meta", lambda _source: {"YAML": {"yaml": {"top_level_key": "mcp_servers"}}}
    )
    cleaned = clients.remove_server_entry_from_clients(root, InstallReport(), False)
    assert set(cleaned) == set(paths)
    assert "ida-pro-mcp" not in json.loads(json_path.read_text(encoding="utf-8"))["mcpServers"]
    assert "ida-pro-mcp" not in json.loads(open_path.read_text(encoding="utf-8"))["mcp"]


def test_configure_clients_dispatches_formats_and_records_failures(tmp_path, monkeypatch):
    paths = {
        "OpenCode": tmp_path / "o.json",
        "TOML": tmp_path / "t.toml",
        "YAML": tmp_path / "y.yaml",
        "JSON": tmp_path / "j.json",
        "Broken": tmp_path / "b.json",
    }
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    monkeypatch.setattr(
        clients,
        "_client_meta",
        lambda _source: {"YAML": {"yaml": {"top_level_key": "servers"}}, "JSON": {"json": {"nested_key": "outer"}}},
    )
    calls = []

    def fake_update(path, *args, **kwargs):
        calls.append((Path(path).name, kwargs))
        return Path(path).name != "b.json"

    monkeypatch.setattr(clients, "update_opencode_config", fake_update)
    monkeypatch.setattr(clients, "update_toml_config", fake_update)
    monkeypatch.setattr(clients, "update_yaml_config", fake_update)
    monkeypatch.setattr(clients, "update_json_config", fake_update)
    report = InstallReport()
    configured = clients.configure_clients(tmp_path, _cfg(), report, False)
    assert set(configured) == {"OpenCode", "TOML", "YAML", "JSON"}
    assert report.metadata["client_update_failures"] == ["Broken"]
