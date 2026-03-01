# IDA MCP Tool Doc: `emulate`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `emulate` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Static tracing and emulation. Actions: static_trace, appcall, decrypt_strings, eval_expr.

## Actions
- `static_trace`
- `appcall`
- `decrypt_strings`
- `eval_expr`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `static_trace, appcall, decrypt_strings, eval_expr`
- `addr`: `string`
- `args`: `array`
- `expr`: `string`
- `follow_calls`: `boolean`
- `func_name`: `string`
- `include_blocks`: `boolean`
- `max_depth`: `integer`
- `max_steps`: `integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
