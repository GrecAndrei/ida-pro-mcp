#!/usr/bin/env python3
"""Validate tool schema metadata consistency.

This script is intended for CI to ensure schema artifacts are kept in sync
with the single metadata source (`schemas_data.py`).
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))

    from ida_pro_mcp.host import schemas
    from ida_pro_mcp.host.agent_operations import list_agent_operations
    from ida_pro_mcp.host.schemas_data import (  # pylint: disable=import-error
        TOOL_ACTIONS,
        TOOL_ARG_SCHEMAS,
        TOOL_DESCRIPTIONS,
        TOOLS,
    )
    from ida_pro_mcp.host.server.tool_registry import advertised_tools, tool_actions

    errors: list[str] = []
    tool_set = set(TOOLS)
    if len(tool_set) != len(TOOLS):
        errors.append("TOOLS contains duplicates")

    missing_actions = sorted(tool_set - set(TOOL_ACTIONS.keys()))
    if missing_actions:
        errors.append(f"missing TOOL_ACTIONS entries: {missing_actions}")

    missing_descriptions = sorted(tool_set - set(TOOL_DESCRIPTIONS.keys()))
    if missing_descriptions:
        errors.append(f"missing TOOL_DESCRIPTIONS entries: {missing_descriptions}")

    if tool_actions() != TOOL_ACTIONS:
        errors.append("schemas_data.TOOL_ACTIONS differs from tool_registry.tool_actions()")
    if tool_actions() != schemas.TOOL_ACTIONS:
        errors.append("schemas.TOOL_ACTIONS differs from tool_registry.tool_actions()")
    if list(schemas.ADVERTISED_TOOLS) != advertised_tools():
        errors.append("schemas.ADVERTISED_TOOLS differs from tool_registry.advertised_tools()")

    # Not all tools need explicit arg schema, but if present it must be dict-like.
    for tool, schema in TOOL_ARG_SCHEMAS.items():
        if not isinstance(schema, dict):
            errors.append(f"TOOL_ARG_SCHEMAS[{tool!r}] must be dict")

    # The public agent surface is intentionally smaller than the legacy
    # tool/action backend. Validate the translation contract here so a new
    # operation cannot be advertised without a valid backend destination.
    operations = list_agent_operations()
    operation_names = [operation.name for operation in operations]
    if len(set(operation_names)) != len(operation_names):
        errors.append("agent operation registry contains duplicate names")
    for operation in operations:
        schema = operation.input_schema
        if not operation.name.startswith("ida_"):
            errors.append(f"agent operation {operation.name!r} must start with 'ida_'")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            errors.append(f"agent operation {operation.name!r} must have an object input schema")
            continue
        if schema.get("additionalProperties") is not False:
            errors.append(f"agent operation {operation.name!r} must reject unknown arguments")
        if not isinstance(schema.get("properties"), dict):
            errors.append(f"agent operation {operation.name!r} must define properties as an object")
        validation_error = operation.validate(operation.example)
        if validation_error:
            errors.append(f"agent operation {operation.name!r} has an invalid example: {validation_error}")
        if operation.help_only:
            continue
        if not operation.backend_tool or not operation.backend_action:
            errors.append(f"agent operation {operation.name!r} is missing a backend mapping")
        elif operation.backend_tool not in TOOL_ACTIONS:
            errors.append(
                f"agent operation {operation.name!r} maps to unknown tool {operation.backend_tool!r}"
            )
        elif operation.backend_action not in TOOL_ACTIONS[operation.backend_tool]:
            errors.append(
                f"agent operation {operation.name!r} maps to unknown action "
                f"{operation.backend_tool}.{operation.backend_action}"
            )

    if errors:
        print("Schema integrity check failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    print(f"Schema integrity OK: {len(tool_set)} legacy tools, {len(operations)} agent operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
