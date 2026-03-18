# IDA MCP Tool Doc: `memory`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `memory` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Direct database memory access. Actions: read, write, hexdump.

## Actions
- `read` (read/discovery)
- `write` (write/mutate)
- `hexdump` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/memory')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `read, write, hexdump`
- `addr`: `string`
- `data`: `string`
- `size`: `integer`
- `type`: `string` - allowed_count: `13`

## Minimal Call Shapes
```json
{
  "name": "memory",
  "arguments": {
    "action": "read"
  }
}
```
```json
{
  "name": "memory",
  "arguments": {
    "action": "grep",
    "source_action": "read",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
