# IDA MCP Tool Doc: `structs`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `structs` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Structure recovery and reconstruction. Actions: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable.

## Actions
- `recover` (tool-specific)
- `analyze_usage` (tool-specific)
- `list` (read/discovery)
- `create` (write/mutate)
- `add_member` (tool-specific)
- `apply` (write/mutate)
- `reconstruct_vtable` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/structs')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "structs",
  "arguments": {
    "action": "recover"
  }
}
```
```json
{
  "name": "structs",
  "arguments": {
    "action": "grep",
    "source_action": "recover",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
