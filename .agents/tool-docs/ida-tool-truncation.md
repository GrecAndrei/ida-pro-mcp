# IDA MCP Tool Doc: `truncation`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `truncation` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Continuation helper for auto-truncated responses. Actions: continue (retrieve next chunk by token/field).

## Actions
- `continue` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/truncation')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `continue`
- `count`: `integer`
- `field`: `string`
- `offset`: `integer`
- `token`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "truncation",
  "arguments": {
    "action": "continue"
  }
}
```
```json
{
  "name": "truncation",
  "arguments": {
    "action": "grep",
    "source_action": "continue",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
