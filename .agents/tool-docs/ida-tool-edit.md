# IDA MCP Tool Doc: `edit`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `edit` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Unified write/edit hub. Quick actions: rename, comment, type, patch, create_func, bulk.

## Actions
- `rename`
- `comment`
- `type`
- `patch`
- `create_func`
- `bulk`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `rename, comment, type, patch, create_func, bulk`
- `args`: `object`
- `subaction`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
