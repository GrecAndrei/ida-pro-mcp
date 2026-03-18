# IDA MCP Tool Doc: `segments`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `segments` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Segment management. Actions: list, add, delete, set_attr, set_perms, move, info.

## Actions
- `list` (read/discovery)
- `add` (write/mutate)
- `delete` (destructive)
- `set_attr` (tool-specific)
- `set_perms` (tool-specific)
- `move` (tool-specific)
- `info` (read/discovery)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/segments')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `list, add, delete, set_attr, set_perms, move, info`
- `attr`: `string`
- `count`: `integer`
- `end`: `string`
- `name`: `string`
- `offset`: `integer`
- `sclass`: `string`
- `start`: `string`
- `value`: `string|integer`

## Minimal Call Shapes
```json
{
  "name": "segments",
  "arguments": {
    "action": "list"
  }
}
```
```json
{
  "name": "segments",
  "arguments": {
    "action": "grep",
    "source_action": "list",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
