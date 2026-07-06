"""
Docs are in sync: all tools are documented and no removed tools appear.
Created: 2025-07-06
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
DOCS = REPO_ROOT / "docs"

assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None


@pytest.fixture(scope="module")
def schemas_data():
    return importlib.import_module("ida_pro_mcp.host.schemas_data")


class TestDocsSync:
    def test_tools_reference_exists(self):
        p = DOCS / "TOOLS_REFERENCE.md"
        assert p.exists(), "TOOLS_REFERENCE.md missing"

    def test_tools_reference_has_all_tools(self, schemas_data):
        p = DOCS / "TOOLS_REFERENCE.md"
        if not p.exists():
            pytest.skip("TOOLS_REFERENCE.md missing")
        text = p.read_text()
        for tool in schemas_data.TOOLS:
            assert f"### {tool}" in text or f"## {tool}" in text or f"`{tool}`" in text, \
                f"Tool '{tool}' not documented in TOOLS_REFERENCE.md"

    def test_technical_reference_exists(self):
        p = DOCS / "TECHNICAL_REFERENCE.md"
        assert p.exists(), "TECHNICAL_REFERENCE.md missing"

    def test_no_removed_tools_in_docs(self, schemas_data):
        """Removed tools must not appear in docs."""
        removed = {"query", "agent", "llm_helpers", "colorize", "predictor"}
        p = DOCS / "TOOLS_REFERENCE.md"
        if not p.exists():
            pytest.skip("TOOLS_REFERENCE.md missing")
        text = p.read_text()
        for tool in removed:
            # Check as standalone tool reference, not as substring
            assert f"`{tool}`" not in text, f"Removed tool '{tool}' still in TOOLS_REFERENCE.md"
