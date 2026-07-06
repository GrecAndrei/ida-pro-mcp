"""Tests that support modules were moved out of tools/ and into support/."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"
SUPPORT_DIR = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "support"


def test_moved_modules_no_longer_in_tools() -> None:
    moved = {"arch_utils.py", "firmware_heuristics.py", "semantic_matching.py",
             "query_lang.py", "_api_categories.py"}
    for name in moved:
        assert not (TOOLS_DIR / name).exists(), f"{name} still in tools/"


def test_moved_modules_exist_in_support() -> None:
    moved = {"arch_utils.py", "firmware_heuristics.py", "semantic_matching.py",
             "query_lang.py", "_api_categories.py"}
    for name in moved:
        assert (SUPPORT_DIR / name).exists(), f"{name} missing from support/"
