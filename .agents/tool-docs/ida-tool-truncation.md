# IDA MCP Tool Doc: `truncation`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `truncation` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Continuation helper for auto-truncated responses. Actions: continue (retrieve next chunk by token/field).

## Actions
- `continue`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `continue`
- `count`: `integer`
- `field`: `string`
- `offset`: `integer`
- `token`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
