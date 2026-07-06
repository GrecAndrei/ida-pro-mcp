# AGENTS.md

## Project

IDA Pro MCP — JSON-RPC stdio server exposing IDA Pro RE capabilities to LLMs.
Tool-action model: each tool exposes multiple actions.

## Test Registry

Every test file MUST declare what it interacts with:

```python
"""
@@TEST_REGISTRY@@
interacts:
  - tool:<name>
  - tool_actions:<name>
  - dispatch:<name>
  - schema:<NAME>
format: v1
description: What this tests
created: YYYY-MM-DD
"""
```

Entity types: `tool:X` (module), `tool_actions:X` (action list),
`dispatch:X` (handler/route), `schema:X` (TOOLS, ADVERTISED_TOOLS, TOOL_ACTIONS).

```bash
python scripts/test_registry_check.py              # check
python scripts/test_registry_check.py --discover   # auto-detect bindings
python scripts/test_registry_check.py --strict     # fail on violations (pre-commit)
python scripts/test_registry_check.py --mark-fp "tests/foo.py" --entities "tool:search" --reason "why"
python scripts/test_registry_check.py --update-hashes  # accept current state
```

**Rule:** If you change a code entity, all tests binding to it must also change
or be marked as false positive with a reason.

## Adding a Tool

1. Create `ida_mcp/tools/<name>.py` with `@tool` function
2. Add to `_TOOL_ACTIONS` in `host/server/tool_registry.py`
3. Add to `TOOLS` + `ADVERTISED_TOOLS` in `host/schemas_data.py`
4. Add description to `TOOL_DESCRIPTIONS`
5. Add to `ida_mcp/tools/__init__.py::__all__`
6. If host-side only: add `tool_name == "<name>"` branch in `server_dispatch.py`
7. Create test with `@@TEST_REGISTRY@@` header
8. `python scripts/test_registry_check.py --discover`

## Removing a Tool

1. `grep -rn '"<name>"' src/ docs/ tests/ .agents/ --include="*.py" --include="*.md"`
2. Delete tool file, remove from all registry files, remove tests
3. `python scripts/test_registry_check.py --discover`

## Key Files

| File | Purpose |
|------|---------|
| `host/server/tool_registry.py` | `_TOOL_ACTIONS` dict |
| `host/schemas_data.py` | `TOOLS`, `ADVERTISED_TOOLS`, `TOOL_DESCRIPTIONS` |
| `host/server/server_dispatch.py` | Tool routing and handlers |
| `ida_mcp/tools/__init__.py` | `__all__` list, `_TOOL_MODULE_MAP` |
| `.test-registry.json` | Test binding registry |

## Invariants

- Every tool in `TOOLS` has entry in `_TOOL_ACTIONS`
- Every tool in `ADVERTISED_TOOLS` is in `TOOLS`
- Every tool has description in `TOOL_DESCRIPTIONS`
- `tool_registry_check.py --strict` passes

## Conventions

- No marketing jargon in descriptions
- Descriptions: one sentence + "Actions: a, b, c"
- `@tool` decorator on IDA-side functions, `@idaread` for read-only
- Wrapper actions (grep/pick/head/tail/next/stats) are dynamic — don't list in `_TOOL_ACTIONS`

## Pre-commit

`python scripts/test_registry_check.py --strict` runs on every commit.
