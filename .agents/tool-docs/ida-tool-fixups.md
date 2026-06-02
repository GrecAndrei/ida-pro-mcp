# IDA MCP Tool Doc: `fixups`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `fixups` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Manage relocations/fixups (relocation table entries) in the IDB. Actions: list, get, add, delete.

## Actions
- `list` (read/discovery)
- `get` (read/discovery)
- `add` (write/mutate)
- `delete` (destructive)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/fixups')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `list, get, add, delete`
- `addr`: `string` - Address of the fixup
- `count`: `integer` - Max entries (0=all)
- `end`: `string` - End address for list range
- `fixup_type`: `integer` - Fixup type id (processor specific)
- `offset`: `integer` - Pagination offset
- `start`: `string` - Start address for list range
- `target`: `string` - Target address (for add)
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "fixups",
  "arguments": {
    "action": "list"
  }
}
```
```json
{
  "name": "fixups",
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
