from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_legacy_server_names_centralized_module_exists():
    p = ROOT / "src" / "ida_pro_mcp" / "installer" / "clients.py"
    text = p.read_text(encoding="utf-8")
    assert "LEGACY_SERVER_NAMES" in text
    assert "github.com/GrecAndrei/ida-pro-mcp" in text
