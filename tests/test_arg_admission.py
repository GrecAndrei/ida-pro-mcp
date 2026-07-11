"""Pin: critical tool kwargs are admitted by TOOL_ARG_SCHEMAS.

Prevents silent-breakage regression when dispatch rejected unknown keys
(0.9.0) or previously stripped them.
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


# Must stay admitted — handlers / agents depend on them.
CRITICAL = {
    "search": {
        "pattern", "query", "action", "limit", "mode", "recipe", "intent",
        "semantic_min_score", "constraints", "include_items", "timeout_ms",
        "target", "ea", "addr",
    },
    "funcs": {
        "action", "addr", "force", "limit", "min_score", "threshold", "top_k",
        "ea", "start", "function", "target", "end_ea", "stop",
    },
    "misc": {"action", "module", "modules", "path", "content", "code", "expr"},
    "intelligence": {"action", "query", "limit", "top_k", "threshold", "addr"},
}


def test_critical_kwargs_admitted(schemas_data):
    missing = []
    for tool, keys in CRITICAL.items():
        sch = schemas_data.TOOL_ARG_SCHEMAS.get(tool) or {}
        for k in keys:
            if k not in sch:
                missing.append(f"{tool}.{k}")
    assert not missing, f"schema missing admitted keys: {missing}"


def test_advertised_tools_subset(schemas_data):
    assert len(schemas_data.ADVERTISED_TOOLS) <= 20
    for t in schemas_data.ADVERTISED_TOOLS:
        assert t in schemas_data.TOOLS


def test_advertised_actions_subset_of_full(schemas_data):
    full = schemas_data.TOOL_ACTIONS
    for tool, actions in schemas_data.ADVERTISED_ACTIONS.items():
        assert tool in full
        missing = sorted(set(actions) - set(full[tool]))
        assert not missing, f"{tool}: advertised actions not in TOOL_ACTIONS: {missing}"


def test_compact_enum_uses_advertised():
    schemas = importlib.import_module("ida_pro_mcp.host.schemas")
    compact = schemas.ADVERTISED_ACTIONS.get("search", [])
    full = schemas.TOOL_ACTIONS.get("search", [])
    assert "find" in compact and "nl" in compact
    assert len(compact) < len(full)
