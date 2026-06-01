import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.schemas import ADVERTISED_TOOLS, HIDDEN_TOOLS_IN_LIST, TOOLS  # noqa: E402


def _must_match(pattern: str, text: str, label: str) -> re.Match[str]:
    m = re.search(pattern, text)
    assert m, f"{label}: expected pattern not found: {pattern}"
    return m


def test_tools_reference_reports_live_tools_count():
    p = ROOT / "docs" / "TOOLS_REFERENCE.md"
    text = p.read_text(encoding="utf-8")
    m = _must_match(r"Current canonical tool surface:\s+\*\*(\d+) tools\*\*", text, str(p))
    assert int(m.group(1)) == len(TOOLS)


def test_technical_reference_reports_live_schema_surface_counts():
    p = ROOT / "docs" / "TECHNICAL_REFERENCE.md"
    text = p.read_text(encoding="utf-8")
    tools_m = _must_match(r"`TOOLS`\s+[-—]\s+ordered list of all\s+(\d+)\s+tool names", text, str(p))
    adv_m = _must_match(r"`ADVERTISED_TOOLS`\s+[-—]\s+(\d+)\s+tools shown in\s+`tools/list`", text, str(p))
    hidden_m = _must_match(r"`HIDDEN_TOOLS_IN_LIST`\s+[-—]\s+(\d+)\s+tools callable via alias/name but hidden from listings", text, str(p))

    assert int(tools_m.group(1)) == len(TOOLS)
    assert int(adv_m.group(1)) == len(ADVERTISED_TOOLS)
    assert int(hidden_m.group(1)) == len(HIDDEN_TOOLS_IN_LIST)


def test_prompts_prefer_canonical_string_ops_for_c2_flows():
    p = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "prompts.py"
    text = p.read_text(encoding="utf-8")
    assert "c2_detect(action=" not in text
    assert "string_ops(action=\"indicators\")" in text


def test_tools_reference_does_not_mark_canonical_tools_as_legacy_only():
    p = ROOT / "docs" / "TOOLS_REFERENCE.md"
    text = p.read_text(encoding="utf-8")
    assert "Tools not in `TOOLS` but still reachable through compatibility routing:" in text
    legacy_line = next(
        line for line in text.splitlines()
        if line.startswith("Tools not in `TOOLS` but still reachable through compatibility routing:")
    )
    assert "`taint`" not in legacy_line
