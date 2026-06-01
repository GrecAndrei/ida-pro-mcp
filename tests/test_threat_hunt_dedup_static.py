from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_threat_hunt_legacy_c2_route_targets_canonical_string_ops():
    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "elif tool == \"c2_detect\" and action:" in text
    assert "\"string_ops\"," in text
