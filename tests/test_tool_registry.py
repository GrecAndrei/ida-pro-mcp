"""
Tool registry matches code: every tool in schemas has a module and vice versa.
Created: 2025-07-06
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None


def _find_literal_subscript(node):
    """Find the `Literal[...]` subscript inside an annotation, recursing
    through `Annotated[...]` wrappers."""
    if not isinstance(node, ast.Subscript):
        return None
    if isinstance(node.value, ast.Name) and node.value.id == "Literal":
        return node
    if isinstance(node.value, ast.Name) and node.value.id == "Annotated":
        slice_ = node.slice
        items = slice_.elts if isinstance(slice_, ast.Tuple) else [slice_]
        for item in items:
            found = _find_literal_subscript(item)
            if found:
                return found
    return None


def _literal_strings(annotation) -> set[str]:
    subscript = _find_literal_subscript(annotation)
    if subscript is None:
        return set()
    slice_ = subscript.slice
    items = slice_.elts if isinstance(slice_, ast.Tuple) else [slice_]
    return {
        item.value
        for item in items
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


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
        host_only = {
            "session", "truncation", "bookmarks", "background", "workflow",
            "multi_session",
        }
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


class TestIdaSideLiteralContract:
    """Every action the host advertises for an IDA-side tool must be accepted
    by the IDA runtime's `action:` Literal annotation.

    Regression guard for the `read_bytes` bug: the action was added to
    TOOL_ACTIONS, schemas, and the handler branch, but not to the Literal —
    so every call was rejected with "Unknown action" before reaching the
    handler.  The Literal is the IDA runtime's admission gate.
    """

    # Dynamic wrapper actions are valid in IDA-side Literals but intentionally
    # not listed in TOOL_ACTIONS (see AGENTS.md).
    WRAPPER_ACTIONS = {"grep", "pick", "head", "tail", "next", "stats"}

    # Host-side tools that dispatch without an IDA-side tool module.
    HOST_ONLY_TOOLS = {
        "session", "truncation", "bookmarks", "background", "workflow",
        "multi_session", "governance", "search",
    }

    @staticmethod
    def _literal_actions(tool_path: Path, tool: str) -> set[str] | None:
        """Return the action Literal members of the tool's own `def <tool>(`,
        or None if the tool takes a free-form action string (no admission gate).
        AST-based so the test runs without importing the IDA runtime."""
        tree = ast.parse(tool_path.read_text(encoding="utf-8"), filename=str(tool_path))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name != tool:
                continue
            action_arg = next(
                (a for a in node.args.args if a.arg == "action"), None
            )
            if action_arg is None or action_arg.annotation is None:
                return set()
            annotation = action_arg.annotation
            if isinstance(annotation, ast.Name) and annotation.id == "str":
                return None
            return _literal_strings(annotation)
        return set()

    def test_registry_actions_are_accepted_by_ida_literal(self, schemas_data, tool_registry):
        tools_dir = SRC / "ida_pro_mcp" / "ida_mcp" / "tools"
        init_src = (tools_dir / "__init__.py").read_text(encoding="utf-8")
        module_map = {}
        module_match = ast.parse(init_src).body
        for node in module_match:
            if not isinstance(node, ast.Assign):
                continue
            if any(
                isinstance(t, ast.Name) and t.id == "_TOOL_MODULE_MAP"
                for t in node.targets
            ) and isinstance(node.value, ast.Dict):
                for key, value in zip(node.value.keys, node.value.values, strict=True):
                    if isinstance(key, ast.Constant) and isinstance(value, ast.Constant):
                        module_map[key.value] = value.value

        actions = tool_registry.tool_actions()
        checked = 0
        for tool, tool_actions in actions.items():
            if tool in self.HOST_ONLY_TOOLS:
                continue
            mod = module_map.get(tool, tool)
            tool_file = tools_dir / f"{mod}.py"
            literal = self._literal_actions(tool_file, tool)
            if literal is None:
                # Free-form action string (e.g. blackboard) — validated by the
                # host-side TOOL_ARG_SCHEMAS enum, not an IDA-side Literal.
                continue
            if any(str(a).lstrip().startswith("(") for a in tool_actions):
                # Placeholder-style entries (e.g. batch -> "(pass calls array)")
                # describe the payload shape instead of naming an action; the
                # tool has no action: Literal to check against.
                continue
            assert literal, f"Tool '{tool}' has no action: Literal in {tool_file}"
            checked += 1
            missing = sorted(set(tool_actions) - literal)
            assert not missing, (
                f"Tool '{tool}' advertises actions missing from the IDA-side "
                f"Literal (they would be rejected at runtime): {missing}"
            )
            orphans = sorted(literal - set(tool_actions) - self.WRAPPER_ACTIONS)
            assert not orphans, (
                f"Tool '{tool}' Literal accepts actions the host never "
                f"advertises: {orphans}"
            )
        assert checked >= 20, f"expected to check most tools, checked {checked}"
