# IDA MCP Tool Doc: `ctree`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `ctree` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Hex-Rays AST (CTree) analysis. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow.

## Actions
- `get` (read/discovery)
- `traverse` (tool-specific)
- `find_calls` (tool-specific)
- `find_vars` (tool-specific)
- `find_strings` (tool-specific)
- `find_conditions` (tool-specific)
- `get_logic_flow` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/ctree')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow`
- `addr`: `string`
- `depth`: `integer`
- `query`: `string`

## Minimal Call Shapes
```json
{
  "name": "ctree",
  "arguments": {
    "action": "get"
  }
}
```
```json
{
  "name": "ctree",
  "arguments": {
    "action": "grep",
    "source_action": "get",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
