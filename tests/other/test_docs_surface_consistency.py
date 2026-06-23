import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Tool-count synchronization is covered by tests/test_tool_count_sync.py
# (which also exercises the tools/sync_tool_counts.py master script).
_ = (os, re, sys, Path, ROOT, SRC)  # keep imports for remaining tests


def test_prompts_prefer_canonical_string_ops_for_c2_flows():
    p = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "prompts.py"
    text = p.read_text(encoding="utf-8")
    assert "c2_detect(action=" not in text
    assert "string_ops(action=\"indicators\")" in text


def test_llm_helpers_prefer_canonical_string_ops_for_c2_flows():
    p = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "llm_helpers.py"
    text = p.read_text(encoding="utf-8")
    assert "c2_detect(action=" not in text
    assert "string_ops(action='indicators')" in text


def test_tools_reference_does_not_mark_canonical_tools_as_legacy_only():
    p = ROOT / "docs" / "TOOLS_REFERENCE.md"
    text = p.read_text(encoding="utf-8")
    assert "Tools not in `TOOLS` but still reachable through compatibility routing:" in text
    legacy_line = next(
        line for line in text.splitlines()
        if line.startswith("Tools not in `TOOLS` but still reachable through compatibility routing:")
    )
    assert "`taint`" not in legacy_line
    assert "`c2_detect`" not in legacy_line
