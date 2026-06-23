from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_install_mcp_servers_uses_shared_container_and_legacy_migration_helpers():
    p = ROOT / "src" / "ida_pro_mcp" / "server.py"
    text = p.read_text(encoding="utf-8")
    assert "from ida_pro_mcp.installer.clients import LEGACY_SERVER_NAMES" in text
    assert "def ensure_server_container(config: dict, client_name: str, is_toml: bool):" in text
    assert "def migrate_legacy_server_keys(mcp_servers: dict, canonical_name: str) -> None:" in text
    assert "for key in LEGACY_SERVER_NAMES" in text
    assert "mcp_servers = ensure_server_container(config, name, is_toml)" in text
    assert "migrate_legacy_server_keys(mcp_servers, mcp.name)" in text
