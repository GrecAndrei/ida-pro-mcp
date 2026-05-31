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

    from ida_pro_mcp.host.schemas_data import (  # pylint: disable=import-error
        TOOL_ACTIONS,
        TOOL_DESCRIPTIONS,
        TOOL_ARG_SCHEMAS,
        TOOLS,
    )

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

    # Not all tools need explicit arg schema, but if present it must be dict-like.
    for tool, schema in TOOL_ARG_SCHEMAS.items():
        if not isinstance(schema, dict):
            errors.append(f"TOOL_ARG_SCHEMAS[{tool!r}] must be dict")

    if errors:
        print("Schema integrity check failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    print(f"Schema integrity OK: {len(tool_set)} tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
