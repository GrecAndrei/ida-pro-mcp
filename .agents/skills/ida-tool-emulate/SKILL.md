# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`emulate`

## Use This Skill When
- You need to call the `emulate` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Static tracing and emulation. Actions: static_trace, appcall, decrypt_strings, eval_expr.

## Actions
- `static_trace`
- `appcall`
- `decrypt_strings`
- `eval_expr`

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
