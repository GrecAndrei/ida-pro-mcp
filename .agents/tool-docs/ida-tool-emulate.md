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

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

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
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

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
