# IDA MCP Tool Doc: `batch`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `batch` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Executes multiple tool calls in a single request to reduce round trips. Pass a calls array of tool invocations.

## Actions
- `(pass calls array)` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/batch')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `calls`: `array`
- `dry_run`: `boolean`
- `script`: `string` - Macro DSL script. Alternative to 'calls'.
- `stop_on_error`: `boolean`
- `template`: `string` - Predefined template name
- `template_vars`: `object` - Variables for template expansion

## Minimal Call Shapes
```json
{
  "name": "batch",
  "arguments": {
    "action": "(pass calls array)"
  }
}
```
```json
{
  "name": "batch",
  "arguments": {
    "action": "grep",
    "source_action": "(pass calls array)",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
