from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_schemaboot_where_clause_uses_hybrid_builder_single_source():
    # 1. Inside IDA, schemaboot.py is now a pure JSON metadata extractor, so it shouldn't contain SQL query building.
    p_tool = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "schemaboot.py"
    text_tool = p_tool.read_text(encoding="utf-8")
    assert "def _build_where_clause(" not in text_tool
    assert "HybridQueryBuilder" not in text_tool

    # 2. On the host, structural_index.py executes queries using the single-source HybridQueryBuilder.
    p_host = ROOT / "src" / "ida_pro_mcp" / "host" / "intelligence" / "structural_index.py"
    text_host = p_host.read_text(encoding="utf-8")
    assert "HybridQueryBuilder.build_legacy(normalized)" in text_host
