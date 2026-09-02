"""Unit tests for scripts/check_schema_integrity.py."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import check_schema_integrity


def test_schema_integrity_main_success(capsys):
    """Test standard main execution exits with code 0."""
    from ida_pro_mcp.host import schemas, schemas_data
    from ida_pro_mcp.host.server import tool_registry

    schemas_data.TOOL_ACTIONS = tool_registry.tool_actions()
    schemas.TOOL_ACTIONS = tool_registry.tool_actions()
    rc = check_schema_integrity.main()
    assert rc == 0
    captured = capsys.readouterr()
    assert "Schema integrity OK" in captured.out


def test_schema_integrity_tools_duplicates(monkeypatch, capsys):
    """Test detection of duplicate tools in TOOLS."""
    from ida_pro_mcp.host import schemas_data

    monkeypatch.setattr(schemas_data, "TOOLS", list(schemas_data.TOOLS) + [schemas_data.TOOLS[0]])
    rc = check_schema_integrity.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "TOOLS contains duplicates" in captured.err


def test_schema_integrity_missing_actions_and_descriptions(monkeypatch, capsys):
    """Test detection of missing actions and descriptions."""
    from ida_pro_mcp.host import schemas_data

    monkeypatch.setattr(schemas_data, "TOOLS", list(schemas_data.TOOLS) + ["phantom_tool"])
    rc = check_schema_integrity.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "missing TOOL_ACTIONS entries" in captured.err
    assert "missing TOOL_DESCRIPTIONS entries" in captured.err


def test_schema_integrity_mismatches(monkeypatch, capsys):
    """Test detection of mismatch between schemas_data and tool_registry."""
    from ida_pro_mcp.host import schemas, schemas_data
    from ida_pro_mcp.host.server import tool_registry

    monkeypatch.setattr(tool_registry, "tool_actions", lambda: {"diff": ["act"]})
    monkeypatch.setattr(tool_registry, "advertised_tools", lambda: ["diff_tool"])

    rc = check_schema_integrity.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "schemas_data.TOOL_ACTIONS differs from tool_registry.tool_actions()" in captured.err
    assert "schemas.ADVERTISED_TOOLS differs from tool_registry.advertised_tools()" in captured.err


def test_schema_integrity_invalid_arg_schema_type(monkeypatch, capsys):
    """Test detection of non-dict arg schemas in TOOL_ARG_SCHEMAS."""
    from ida_pro_mcp.host import schemas_data

    bad_schemas = dict(schemas_data.TOOL_ARG_SCHEMAS)
    bad_schemas["session"] = ["not_a_dict"]  # invalid
    monkeypatch.setattr(schemas_data, "TOOL_ARG_SCHEMAS", bad_schemas)

    rc = check_schema_integrity.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "TOOL_ARG_SCHEMAS['session'] must be dict" in captured.err


def test_schema_integrity_agent_operations_violations(monkeypatch, capsys):
    """Test validation errors for agent operations (prefix, schema, backend mapping)."""
    from ida_pro_mcp.host import agent_operations
    from ida_pro_mcp.host.agent_operations import AgentOperation

    fake_op_bad_name = AgentOperation(
        name="bad_prefix",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool="session",
        backend_action="list",
    )
    fake_op_bad_schema = AgentOperation(
        name="ida_bad_schema",
        description="test",
        category="test",
        input_schema={"type": "string"},
        example={},
        backend_tool="session",
        backend_action="list",
    )
    fake_op_allow_extra = AgentOperation(
        name="ida_allow_extra",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        example={},
        backend_tool="session",
        backend_action="list",
    )
    fake_op_bad_props = AgentOperation(
        name="ida_bad_props",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": "not_dict", "additionalProperties": False},
        example={},
        backend_tool="session",
        backend_action="list",
    )
    fake_op_invalid_example = AgentOperation(
        name="ida_invalid_example",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {"req": {"type": "string"}}, "required": ["req"], "additionalProperties": False},
        example={},  # Missing required 'req'
        backend_tool="session",
        backend_action="list",
    )
    fake_op_missing_backend = AgentOperation(
        name="ida_missing_backend",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool=None,
        backend_action=None,
    )
    fake_op_unknown_tool = AgentOperation(
        name="ida_unknown_tool",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool="unknown_tool_xyz",
        backend_action="list",
    )
    fake_op_unknown_action = AgentOperation(
        name="ida_unknown_action",
        description="test",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool="session",
        backend_action="unknown_action_xyz",
    )
    fake_op_dup1 = AgentOperation(
        name="ida_dup",
        description="test1",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool="session",
        backend_action="list",
    )
    fake_op_dup2 = AgentOperation(
        name="ida_dup",
        description="test2",
        category="test",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        example={},
        backend_tool="session",
        backend_action="list",
    )

    all_ops = [
        fake_op_bad_name,
        fake_op_bad_schema,
        fake_op_allow_extra,
        fake_op_bad_props,
        fake_op_invalid_example,
        fake_op_missing_backend,
        fake_op_unknown_tool,
        fake_op_unknown_action,
        fake_op_dup1,
        fake_op_dup2,
    ]

    monkeypatch.setattr(agent_operations, "list_agent_operations", lambda: all_ops)

    rc = check_schema_integrity.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert "agent operation registry contains duplicate names" in captured.err
    assert "must start with 'ida_'" in captured.err
    assert "must have an object input schema" in captured.err
    assert "must reject unknown arguments" in captured.err
    assert "must define properties as an object" in captured.err
    assert "has an invalid example" in captured.err
    assert "is missing a backend mapping" in captured.err
    assert "maps to unknown tool" in captured.err
    assert "maps to unknown action" in captured.err
