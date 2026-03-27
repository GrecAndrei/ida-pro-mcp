# IDA MCP Tool Doc: `calc`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `calc` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Mathematical and address resolution. Actions: eval, offset, convert, resolve, deref, chain, align.

## Actions
- `eval` (tool-specific)
- `offset` (tool-specific)
- `convert` (tool-specific)
- `resolve` (tool-specific)
- `deref` (tool-specific)
- `chain` (tool-specific)
- `align` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/calc')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `eval, offset, convert, resolve, deref, chain, align`
- `addr`: `string`
- `expr`: `string`
- `offsets`: `array|string`
- `size`: `integer`
- `target`: `string`
- `type`: `string`
- `value`: `string|integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "calc",
  "arguments": {
    "action": "eval"
  }
}
```
```json
{
  "name": "calc",
  "arguments": {
    "action": "grep",
    "source_action": "eval",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
