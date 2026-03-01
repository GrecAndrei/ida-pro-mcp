# IDA MCP Tool Doc: `funcs`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `funcs` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Function boundary management. Actions: create (auto-converts bytes to code, supports end address, flags, and force deletion of overlaps), delete (finds containing function if addr is inside one), set_flags, set_name (alias: rename), add_comment, list (supports regex/glob/substring query filtering), info (detailed function info with optional prototype and stack frame).

## Actions
- `create`
- `delete`
- `set_flags`
- `set_name`
- `rename`
- `add_comment`
- `list`
- `info`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `create, delete, set_flags, set_name, rename, add_comment, list, info`
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

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
