from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CODE_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"


def test_code_decompile_and_smart_decompile_use_shared_enrichment_helper():
    text = CODE_PATH.read_text(encoding="utf-8")
    assert "_build_decompile_enrichment(" in text
    assert "elif action == \"smart_decompile\":" in text
    assert "enrichment = _build_decompile_enrichment(" in text
    assert "_register_survey_if_needed" not in text
    assert "SurveyStore" not in text
