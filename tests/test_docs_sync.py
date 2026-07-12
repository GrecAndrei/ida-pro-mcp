"""
Docs are in sync: all tools are documented and no removed tools appear.
Created: 2025-07-06
"""

from __future__ import annotations

import importlib
import re
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
    def test_readme_tool_count_matches_registry(self, schemas_data):
        text = (REPO_ROOT / "README.md").read_text()
        assert f"{len(schemas_data.TOOLS)} tools, hundreds of actions" in text

    def test_tools_reference_exists(self):
        p = DOCS / "TOOLS_REFERENCE.md"
        assert p.exists(), "TOOLS_REFERENCE.md missing"

    def test_tools_reference_matches_registry(self, schemas_data):
        p = DOCS / "TOOLS_REFERENCE.md"
        if not p.exists():
            pytest.skip("TOOLS_REFERENCE.md missing")
        text = p.read_text()
        headings = re.findall(r"^### ([a-z_]+)$", text, flags=re.MULTILINE)
        summary_rows = re.findall(
            r"^\| `([a-z_]+)` \|", text, flags=re.MULTILINE,
        )
        assert set(headings) == set(schemas_data.TOOLS)
        assert len(headings) == len(set(headings)), "Duplicate tool sections"
        assert set(summary_rows) == set(schemas_data.TOOLS)
        assert len(summary_rows) == len(set(summary_rows)), "Duplicate summary rows"
        assert (
            f"Total tools: **{len(schemas_data.TOOLS)}** | "
            f"Advertised: **{len(schemas_data.ADVERTISED_TOOLS)}**"
        ) in text

    def test_technical_reference_exists(self):
        p = DOCS / "TECHNICAL_REFERENCE.md"
        assert p.exists(), "TECHNICAL_REFERENCE.md missing"

    def test_active_wiki_uses_canonical_tools(self, schemas_data):
        wiki = DOCS / "wiki"
        active_pages = [wiki / "INDEX.md"]
        for section in ("core", "workflows", "skills"):
            active_pages.extend((wiki / section).glob("*.md"))
        text = "\n".join(p.read_text() for p in active_pages)

        referenced = set(
            re.findall(r'\{\s*"name":\s*"([a-z_]+)"', text),
        )
        referenced.update(re.findall(r"\b([a-z_]+)\(action=", text))
        referenced.update(
            re.findall(
                r'^\s*"([a-z_]+):[a-z_]+(?: |")',
                text,
                flags=re.MULTILINE,
            ),
        )
        assert referenced <= set(schemas_data.TOOLS)

        index_text = (wiki / "INDEX.md").read_text()
        indexed_tools = set(re.findall(r"tools/([a-z_]+)\.md", index_text))
        assert indexed_tools <= set(schemas_data.TOOLS)
        for tool in indexed_tools:
            assert (wiki / "tools" / f"{tool}.md").exists()

    def test_no_removed_tools_in_docs(self, schemas_data):
        """Removed tools must not appear in docs."""
        removed = {
            "query", "agent", "llm_helpers", "colorize", "predictor", "filter",
            "yara_hunt", "threat_hunt",
        }
        p = DOCS / "TOOLS_REFERENCE.md"
        if not p.exists():
            pytest.skip("TOOLS_REFERENCE.md missing")
        text = p.read_text()
        for tool in removed:
            # Check as standalone tool reference, not as substring
            assert f"`{tool}`" not in text, f"Removed tool '{tool}' still in TOOLS_REFERENCE.md"
