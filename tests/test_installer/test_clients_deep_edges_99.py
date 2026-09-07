"""Comprehensive tests covering installer/clients.py edge cases and failure modes."""

from __future__ import annotations

import builtins
import json
import sys
import types
from pathlib import Path

import pytest

from ida_pro_mcp.installer import clients
from ida_pro_mcp.installer.common import InstallReport


def _cfg() -> dict:
    return {
        "command": "python",
        "args": ["-m", "ida_pro_mcp"],
        "env": {"TEST_ENV": "1"},
    }


def test_load_client_map_no_candidates(tmp_path, monkeypatch):
    """When candidate configs do not exist, load_client_map returns empty dict."""
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    assert clients.load_client_map(tmp_path) == {}


def test_backup_file_directory_rejected(tmp_path):
    """backup_file raises RuntimeError if target path exists as a directory."""
    d = tmp_path / "config_dir"
    d.mkdir()
    report = InstallReport()
    with pytest.raises(RuntimeError, match="Refusing non-regular client config path"):
        clients.backup_file(d, report, dry_run=False)


def test_validate_config_path_symlink_and_non_regular(tmp_path):
    """_validate_config_path raises ConfigParseError on symlink or non-regular file."""
    regular = tmp_path / "regular.json"
    regular.write_text("{}", encoding="utf-8")
    sym = tmp_path / "symlink.json"
    sym.symlink_to(regular)
    with pytest.raises(clients.ConfigParseError, match="Refusing to replace symlinked client config"):
        clients._validate_config_path(sym)

    d = tmp_path / "a_directory"
    d.mkdir()
    with pytest.raises(clients.ConfigParseError, match="Refusing non-regular client config path"):
        clients._validate_config_path(d)


def test_load_json_config_io_error_and_jsonc_non_dict(tmp_path, monkeypatch):
    """_load_json_config raises ConfigParseError on OSError and when JSONC payload is not a dict."""
    f = tmp_path / "unreadable.json"
    f.write_text("{}", encoding="utf-8")

    def broken_read(self, *args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "read_text", broken_read)
    with pytest.raises(clients.ConfigParseError, match="Could not read"):
        clients._load_json_config(f)

    monkeypatch.undo()

    # JSONC with comments that parses into a list rather than a dict
    jsonc_list = tmp_path / "jsonc_list.json"
    jsonc_list.write_text("/* comment */\n[1, 2, 3]", encoding="utf-8")
    with pytest.raises(clients.ConfigParseError, match="must contain a top-level JSON object"):
        clients._load_json_config(jsonc_list, allow_comments=True)


def test_update_toml_config_tomllib_and_tomli_w_fallbacks(tmp_path, monkeypatch):
    """update_toml_config exercises tomli fallback on ImportError and tomli_w missing."""
    import tomllib
    fake_tomli = types.ModuleType("tomli")
    fake_tomli.loads = tomllib.loads
    monkeypatch.setitem(sys.modules, "tomli", fake_tomli)

    orig_import = builtins.__import__

    def fake_import_tomllib(name, *args, **kwargs):
        if name == "tomllib":
            raise ImportError("no tomllib")
        if name == "tomli_w":
            raise ImportError("no tomli_w")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import_tomllib)

    toml_file = tmp_path / "client.toml"
    toml_file.write_text("[mcp_servers]\n", encoding="utf-8")
    report = InstallReport()
    ok = clients.update_toml_config(toml_file, "ida-pro-mcp", _cfg(), report, dry_run=False)
    assert ok is True
    content = toml_file.read_text(encoding="utf-8")
    assert "ida-pro-mcp" in content
    assert report.modified_files


def test_update_yaml_config_yaml_safe_load_error_and_fallback(tmp_path, monkeypatch):
    """update_yaml_config handles yaml safe_load exceptions, PyYAML missing fallback."""
    import yaml

    yaml_file = tmp_path / "client.yaml"
    yaml_file.write_text("some: content", encoding="utf-8")

    def broken_safe_load(content):
        raise ValueError("corrupt yaml syntax")

    monkeypatch.setattr(yaml, "safe_load", broken_safe_load)
    report = InstallReport()
    ok = clients.update_yaml_config(yaml_file, "ida-pro-mcp", _cfg(), report, dry_run=False)
    assert ok is False
    assert any("Could not parse" in err for err in report.errors)

    monkeypatch.undo()

    # Now test when yaml module is not installed (ImportError)
    orig_import = builtins.__import__

    def fake_import_no_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("no PyYAML")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import_no_yaml)

    # 1. Fallback succeeds when file is valid JSONC
    jsonc_yaml = tmp_path / "jsonc.yaml"
    jsonc_yaml.write_text("// comment\n{\"mcp_servers\": {}}", encoding="utf-8")
    rep1 = InstallReport()
    ok1 = clients.update_yaml_config(jsonc_yaml, "ida-pro-mcp", _cfg(), rep1, dry_run=False)
    assert ok1 is True
    data = json.loads(jsonc_yaml.read_text(encoding="utf-8"))
    assert "ida-pro-mcp" in data["mcp_servers"]

    # 2. Fallback fails when file is not valid JSON
    invalid_json_yaml = tmp_path / "invalid.yaml"
    invalid_json_yaml.write_text("plain yaml text: not json", encoding="utf-8")
    rep2 = InstallReport()
    ok2 = clients.update_yaml_config(invalid_json_yaml, "ida-pro-mcp", _cfg(), rep2, dry_run=False)
    assert ok2 is False
    assert any("PyYAML not installed" in err for err in rep2.errors)


def test_configure_clients_handles_unexpected_exception(tmp_path, monkeypatch):
    """configure_clients catches unexpected updater exceptions and records warnings."""
    paths = {"ExplodingClient": tmp_path / "explode.json"}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)

    def explode(*args, **kwargs):
        raise RuntimeError("catastrophic failure")

    monkeypatch.setattr(clients, "update_json_config", explode)
    report = InstallReport()
    configured = clients.configure_clients(tmp_path, _cfg(), report, dry_run=False)
    assert configured == []
    assert report.metadata["client_update_failures"] == ["ExplodingClient"]
    assert any("catastrophic failure" in w for w in report.warnings)


def test_rollback_from_backups_directory_backup_rejected(tmp_path):
    """rollback_from_backups raises RuntimeError if backup is a directory."""
    target = tmp_path / "target.json"
    backup_dir = tmp_path / "backup_dir"
    backup_dir.mkdir()
    report = InstallReport()
    report.add_backup(target, backup_dir)
    with pytest.raises(RuntimeError, match="Rollback backup is not a regular file"):
        clients.rollback_from_backups(report)


def test_remove_server_entry_nonexistent_paths(tmp_path, monkeypatch):
    """remove_server_entry_from_clients ignores non-existent paths."""
    missing = tmp_path / "does_not_exist.json"
    paths = {"Ghost": missing}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    report = InstallReport()
    cleaned = clients.remove_server_entry_from_clients(tmp_path, report, dry_run=False)
    assert cleaned == []


def test_remove_server_entry_toml_fallbacks(tmp_path, monkeypatch):
    """remove_server_entry_from_clients exercises tomli and tomli_w fallbacks."""
    import tomllib
    fake_tomli = types.ModuleType("tomli")
    fake_tomli.loads = tomllib.loads
    monkeypatch.setitem(sys.modules, "tomli", fake_tomli)

    orig_import = builtins.__import__

    def fake_import_tomllib(name, *args, **kwargs):
        if name == "tomllib":
            raise ImportError("no tomllib")
        if name == "tomli_w":
            raise ImportError("no tomli_w")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import_tomllib)

    toml_file = tmp_path / "test.toml"
    toml_file.write_text('[mcp_servers."ida-pro-mcp"]\ncommand = "python"\n', encoding="utf-8")
    paths = {"TOMLClient": toml_file}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    report = InstallReport()
    cleaned = clients.remove_server_entry_from_clients(tmp_path, report, dry_run=False)
    assert cleaned == ["TOMLClient"]
    assert "ida-pro-mcp" not in toml_file.read_text(encoding="utf-8")


def test_remove_server_entry_yaml_exception_handling(tmp_path, monkeypatch):
    """remove_server_entry_from_clients passes when yaml safe_load fails."""
    yaml_file = tmp_path / "corrupt.yaml"
    yaml_file.write_text("invalid: : yaml", encoding="utf-8")
    paths = {"YAMLClient": yaml_file}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    monkeypatch.setattr(
        clients, "_client_meta", lambda _source: {"YAMLClient": {"yaml": {"top_level_key": "mcp_servers"}}}
    )
    report = InstallReport()
    cleaned = clients.remove_server_entry_from_clients(tmp_path, report, dry_run=False)
    assert cleaned == []


def test_remove_server_entry_json_nested_keys_and_missing_top_key(tmp_path, monkeypatch):
    """remove_server_entry_from_clients with nested_key traversing non-dicts or missing keys."""
    # 1. Nested key where intermediate node is not a dict
    f1 = tmp_path / "nested_non_dict.json"
    f1.write_text(json.dumps({"mcp": [1, 2, 3]}), encoding="utf-8")

    # 2. Nested key succeeds
    f2 = tmp_path / "nested_ok.json"
    f2.write_text(json.dumps({"mcp": {"servers": {"ida-pro-mcp": {"cmd": "run"}}}}), encoding="utf-8")

    # 3. Top key not present in config
    f3 = tmp_path / "no_top_key.json"
    f3.write_text(json.dumps({"otherKey": {}}), encoding="utf-8")

    paths = {
        "Client1": f1,
        "Client2": f2,
        "Client3": f3,
    }
    meta = {
        "Client1": {"json": {"nested_key": "mcp.servers"}},
        "Client2": {"json": {"nested_key": "mcp.servers"}},
        "Client3": {"json": {"top_level_key": "mcpServers"}},
    }
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    monkeypatch.setattr(clients, "_client_meta", lambda _source: meta)

    report = InstallReport()
    cleaned = clients.remove_server_entry_from_clients(tmp_path, report, dry_run=False)
    assert cleaned == ["Client2"]
    data2 = json.loads(f2.read_text(encoding="utf-8"))
    assert "ida-pro-mcp" not in data2["mcp"]["servers"]


def test_remove_server_entry_unhandled_exception_recorded_as_warning(tmp_path, monkeypatch):
    """remove_server_entry_from_clients adds warning if unexpected exception occurs."""
    broken = tmp_path / "broken.json"
    broken.write_text("{bad json", encoding="utf-8")
    paths = {"BadClient": broken}
    monkeypatch.setattr(clients, "get_config_paths", lambda _source: paths)
    report = InstallReport()
    cleaned = clients.remove_server_entry_from_clients(tmp_path, report, dry_run=False)
    assert cleaned == []
    assert any("Failed to remove ida-pro-mcp from BadClient" in w for w in report.warnings)
