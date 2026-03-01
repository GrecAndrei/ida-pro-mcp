# IDA MCP Tool Doc: `bookmarks`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bookmarks` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find (supports regex/glob/substring in name, notes, tags, addr, category), export.

## Actions
- `add`
- `list`
- `delete`
- `update`
- `clear`
- `find`
- `export`
- `grep` (host wrapper): run another action, then grep its output lines.

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

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
