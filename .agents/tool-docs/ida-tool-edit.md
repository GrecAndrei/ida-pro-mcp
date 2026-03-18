# IDA MCP Tool Doc: `edit`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `edit` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Unified write/edit hub. Quick actions: rename, comment, type, patch, create_func, bulk.

## Actions
- `rename` (write/mutate)
- `comment` (write/mutate)
- `type` (tool-specific)
- `patch` (tool-specific)
- `create_func` (tool-specific)
- `bulk` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/edit')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `rename, comment, type, patch, create_func, bulk`
- `args`: `object`
- `subaction`: `string`

## Minimal Call Shapes
```json
{
  "name": "edit",
  "arguments": {
    "action": "rename"
  }
}
```
```json
{
  "name": "edit",
  "arguments": {
    "action": "grep",
    "source_action": "rename",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
