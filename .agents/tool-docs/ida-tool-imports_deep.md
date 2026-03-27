# IDA MCP Tool Doc: `imports_deep`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `imports_deep` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Advanced import resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.

## Actions
- `thunks` (tool-specific)
- `delay` (tool-specific)
- `forwarded` (tool-specific)
- `ordinal` (tool-specific)
- `api_sets` (tool-specific)
- `resolve` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/imports_deep')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "imports_deep",
  "arguments": {
    "action": "thunks"
  }
}
```
```json
{
  "name": "imports_deep",
  "arguments": {
    "action": "grep",
    "source_action": "thunks",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
