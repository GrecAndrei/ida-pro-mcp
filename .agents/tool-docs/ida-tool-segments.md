# IDA MCP Tool Doc: `segments`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `segments` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
List, create, modify, and analyze binary segments and their permissions/attributes. Actions: list, add, delete, set_attr, set_perms, move, info, analyze, find_code, find_data, compare, merge, fixup_list, fixup_get, fixup_add, fixup_delete.

## Actions
- `list` (read/discovery)
- `add` (write/mutate)
- `delete` (destructive)
- `set_attr` (tool-specific)
- `set_perms` (tool-specific)
- `move` (tool-specific)
- `info` (read/discovery)
- `analyze` (analysis)
- `find_code` (tool-specific)
- `find_data` (tool-specific)
- `compare` (tool-specific)
- `merge` (tool-specific)
- `fixup_list` (tool-specific)
- `fixup_get` (tool-specific)
- `fixup_add` (tool-specific)
- `fixup_delete` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/segments')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `16`
- `attr`: `string`
- `count`: `integer`
- `end`: `string`
- `name`: `string`
- `offset`: `integer`
- `sclass`: `string`
- `start`: `string`
- `value`: `string|integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

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
