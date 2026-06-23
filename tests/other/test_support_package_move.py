"""Regression tests for the support/ package move."""
from __future__ import annotations

from pathlib import Path

SUPPORT_DIR = Path(__file__).resolve().parents[2] / "src" / "ida_pro_mcp" / "ida_mcp" / "support"
TOOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"


def test_support_dir_exists() -> None:
    assert SUPPORT_DIR.is_dir(), f"support/ not found at {SUPPORT_DIR}"


def test_support_init_exists() -> None:
    init_file = SUPPORT_DIR / "__init__.py"
    assert init_file.exists(), "support/__init__.py missing"
    content = init_file.read_text(encoding="utf-8")
    assert len(content.strip()) > 0, "support/__init__.py is empty"


def test_moved_modules_no_longer_in_tools() -> None:
    moved = {"arch_utils.py", "firmware_heuristics.py", "semantic_matching.py",
             "hybrid_search.py", "query_lang.py", "_api_categories.py"}
    for name in moved:
        assert not (TOOLS_DIR / name).exists(), f"{name} still in tools/"


def test_moved_modules_exist_in_support() -> None:
    moved = {"arch_utils.py", "firmware_heuristics.py", "semantic_matching.py",
             "hybrid_search.py", "query_lang.py", "_api_categories.py"}
    for name in moved:
        assert (SUPPORT_DIR / name).exists(), f"{name} missing from support/"
