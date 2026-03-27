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

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/ctree')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow`
- `addr`: `string`
- `depth`: `integer`
- `query`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

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
