# IDA MCP Tool Doc: `emulate`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `emulate` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Static tracing and emulation. Actions: static_trace, appcall, decrypt_strings, eval_expr.

## Actions
- `static_trace` (tool-specific)
- `appcall` (tool-specific)
- `decrypt_strings` (tool-specific)
- `eval_expr` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/emulate')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

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

## Minimal Call Shapes
```json
{
  "name": "emulate",
  "arguments": {
    "action": "static_trace"
  }
}
```
```json
{
  "name": "emulate",
  "arguments": {
    "action": "grep",
    "source_action": "static_trace",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
