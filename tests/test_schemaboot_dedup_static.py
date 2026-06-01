from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_schemaboot_where_clause_uses_hybrid_builder_single_source():
    p = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "schemaboot.py"
    text = p.read_text(encoding="utf-8")
    assert "def _build_where_clause(" in text
    assert "HybridQueryBuilder.build_legacy(normalized)" in text
    assert "operator_format = any(" not in text
    assert "Legacy format handling" not in text
