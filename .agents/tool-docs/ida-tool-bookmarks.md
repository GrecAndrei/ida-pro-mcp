# IDA MCP Tool Doc: `bookmarks`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bookmarks` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find (supports regex/glob/substring in name, notes, tags, addr, category), export.

## Actions
- `add` (write/mutate)
- `list` (read/discovery)
- `delete` (destructive)
- `update` (tool-specific)
- `clear` (destructive)
- `find` (tool-specific)
- `export` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/bookmarks')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `add, list, delete, update, clear, find, export`
- `addr`: `string`
- `category`: `string`
- `id`: `integer`
- `name`: `string`
- `notes`: `string`
- `priority`: `integer`
- `query`: `string`
- `tags`: `array|string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "bookmarks",
  "arguments": {
    "action": "add"
  }
}
```
```json
{
  "name": "bookmarks",
  "arguments": {
    "action": "grep",
    "source_action": "add",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
