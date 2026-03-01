# IDA MCP Tool Doc: `segments`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `segments` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Segment management. Actions: list, add, delete, set_attr, set_perms, move, info.

## Actions
- `list`
- `add`
- `delete`
- `set_attr`
- `set_perms`
- `move`
- `info`
- `grep` (host wrapper): run another action, then grep its output lines.

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

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
