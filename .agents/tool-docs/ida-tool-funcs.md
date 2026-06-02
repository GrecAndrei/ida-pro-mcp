# IDA MCP Tool Doc: `funcs`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `funcs` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Function boundary management with regex/glob/substring filtering. Actions: create, delete, set_flags, info, metrics, find_similar, suggest_names. (Renames/comments/listings live on modify and data.)

## Actions
- `create` (write/mutate)
- `delete` (destructive)
- `set_flags` (write/mutate)
- `info` (read/discovery)
- `metrics` (tool-specific)
- `find_similar` (tool-specific)
- `suggest_names` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/funcs')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `create, delete, set_flags, info, metrics, find_similar, suggest_names`
- `addr`: `string`
- `comment`: `string`
- `count`: `integer`
- `end`: `string`
- `flags`: `integer`
- `force`: `boolean`
- `include_items`: `boolean`
- `include_prototype`: `boolean`
- `include_stack`: `boolean`
- `include_xrefs`: `boolean`
- `name`: `string`
- `named_only`: `boolean`
- `offset`: `integer`
- `query`: `string`
- `repeatable`: `boolean`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "funcs",
  "arguments": {
    "action": "create"
  }
}
```
```json
{
  "name": "funcs",
  "arguments": {
    "action": "grep",
    "source_action": "create",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
