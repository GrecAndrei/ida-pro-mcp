from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_installer_clients_uses_shared_update_helpers():
    p = ROOT / "src" / "ida_pro_mcp" / "installer" / "clients.py"
    text = p.read_text(encoding="utf-8")
    assert "LEGACY_SERVER_NAMES = (" in text
    assert "def _prepare_config_path(path: Path, report: InstallReport, dry_run: bool) -> None:" in text
    assert "def _load_json_config(path: Path, *, allow_comments: bool = True) -> dict:" in text
    assert "def _upsert_server_entry(container: dict, server_name: str, server_cfg: dict) -> None:" in text
    assert "_prepare_config_path(path, report, dry_run)" in text
    assert "_upsert_server_entry(config[\"mcpServers\"], server_name, server_cfg)" in text
    assert "_upsert_server_entry(config[\"mcp\"], server_name, opencode_entry)" in text
    assert "_upsert_server_entry(config[\"mcp_servers\"], server_name, server_cfg)" in text
