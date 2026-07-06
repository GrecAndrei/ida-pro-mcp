"""
Tool registry matches code: every tool in schemas has a module and vice versa.
Created: 2025-07-06
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None


@pytest.fixture(scope="module")
def schemas_data():
    return importlib.import_module("ida_pro_mcp.host.schemas_data")


@pytest.fixture(scope="module")
def tool_registry():
    return importlib.import_module("ida_pro_mcp.host.server.tool_registry")


class TestToolsListIntegrity:
    def test_tools_list_nonempty(self, schemas_data):
        assert len(schemas_data.TOOLS) > 10

    def test_advertised_subset_of_tools(self, schemas_data):
        for t in schemas_data.ADVERTISED_TOOLS:
            assert t in schemas_data.TOOLS, f"Advertised tool '{t}' not in TOOLS"

    def test_tools_no_duplicates(self, schemas_data):
        assert len(schemas_data.TOOLS) == len(set(schemas_data.TOOLS))


class TestToolActionsMatchRegistry:
    def test_all_tools_have_actions(self, schemas_data, tool_registry):
        actions = tool_registry.tool_actions()
        for tool in schemas_data.TOOLS:
            assert tool in actions, f"Tool '{tool}' missing from TOOL_ACTIONS"
            assert len(actions[tool]) > 0, f"Tool '{tool}' has empty action list"

    def test_no_ghost_tools_in_actions(self, schemas_data, tool_registry):
        actions = tool_registry.tool_actions()
        for tool in actions:
            assert tool in schemas_data.TOOLS, f"TOOL_ACTIONS has '{tool}' which is not in TOOLS"

    def test_actions_match_schema_literal(self, schemas_data, tool_registry):
        """TOOL_ACTIONS in schemas_data must match tool_registry.tool_actions()."""
        tr_actions = tool_registry.tool_actions()
        assert isinstance(tr_actions, dict)
        assert len(tr_actions) > 10
        for tool in schemas_data.TOOLS:
            assert tool in tr_actions, f"Tool '{tool}' missing from tool_registry.tool_actions()"


class TestToolDescriptionsPresent:
    def test_all_tools_have_descriptions(self, schemas_data):
        for tool in schemas_data.TOOLS:
            assert tool in schemas_data.TOOL_DESCRIPTIONS, f"Tool '{tool}' missing description"
            desc = schemas_data.TOOL_DESCRIPTIONS[tool]
            assert len(desc) > 10, f"Description for '{tool}' too short"


class TestToolModulesExist:
    def test_ida_tools_have_modules(self, schemas_data):
        """Every tool in TOOLS must have a module file or be in the known host-only set."""
        tools_dir = SRC / "ida_pro_mcp" / "ida_mcp" / "tools"
        # Host-side tools with no IDA module
        host_only = {"session", "truncation", "bookmarks", "background", "workflow", "project", "multi_session", "threat_hunt"}
        # Module map: tool name -> module file name (read directly from source)
        module_map = {}
        init_file = SRC / "ida_pro_mcp" / "ida_mcp" / "tools" / "__init__.py"
        if init_file.exists():
            init_src = init_file.read_text(encoding="utf-8")
            # Find _TOOL_MODULE_MAP = { ... }
            import re
            match = re.search(r'_TOOL_MODULE_MAP\s*=\s*\{(.*?)\}', init_src, re.DOTALL)
            if match:
                for m in re.finditer(r'"(\w+)":\s*"(\w+)"', match.group(1)):
                    module_map[m.group(1)] = m.group(2)
        for tool in schemas_data.TOOLS:
            if tool in host_only:
                continue
            mod = module_map.get(tool, tool)
            py_file = tools_dir / f"{mod}.py"
            init_file = tools_dir / mod / "__init__.py"
            assert py_file.exists() or init_file.exists(), \
                f"Tool '{tool}' has no module ({mod}.py or {mod}/__init__.py)"
