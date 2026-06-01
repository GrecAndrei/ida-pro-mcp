from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_threat_hunt_legacy_c2_route_targets_canonical_string_ops():
    schema_p = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas_data.py"
    schema_text = schema_p.read_text(encoding="utf-8")
    assert "THREAT_LEGACY_REDIRECT_TOOLS" in schema_text
    assert "\"c2_detect\": \"string_ops\"" in schema_text

    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "THREAT_LEGACY_REDIRECT_TOOLS" in text
    assert "redirect_tool = THREAT_LEGACY_REDIRECT_TOOLS[tool]" in text


def test_threat_hunt_legacy_taint_route_targets_tracing_module():
    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "THREAT_LEGACY_VULN_TOOLS | {\"taint\"}" in text
    assert "if tool == \"taint\" and action:" in text
    assert "\"taint\"," in text
    assert "mapped_module = \"tracing\"" in text


def test_threat_hunt_legacy_vuln_fallback_uses_canonical_gadget_actions():
    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "(\"gadgets\", \"rop\", {})" in text
    assert "(\"gadgets\", \"mitigations\", {})" in text
    assert "(\"gadgets\", \"find_rop\", {})" not in text


def test_threat_hunt_legacy_route_uses_shared_passthrough_helper():
    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "def _legacy_passthrough_args(args: dict) -> dict:" in text
    assert "passthrough = self._legacy_passthrough_args(args)" in text


def test_threat_hunt_no_redundant_string_ops_passthrough_branch():
    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "elif tool == \"string_ops\" and action:" not in text


def test_threat_hunt_conditional_passthrough_is_table_driven():
    schema_p = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas_data.py"
    schema_text = schema_p.read_text(encoding="utf-8")
    assert "THREAT_LEGACY_CONDITIONAL_PASSTHROUGH" in schema_text
    assert "\"summarize\":" in schema_text
    assert "\"agent\":" in schema_text

    p = ROOT / "src" / "ida_pro_mcp" / "host" / "server_threat_hunt.py"
    text = p.read_text(encoding="utf-8")
    assert "elif tool in THREAT_LEGACY_CONDITIONAL_PASSTHROUGH and action:" in text
    assert "allowed_actions = THREAT_LEGACY_CONDITIONAL_PASSTHROUGH.get(tool)" in text
    assert "elif tool == \"classify\" and action:" not in text
    assert "elif tool == \"summarize\" and action in {" not in text
    assert "elif tool == \"agent\" and action in {\"search_all\", \"find_references\"}:" not in text
