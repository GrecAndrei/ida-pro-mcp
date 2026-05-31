# IDA MCP Tool Doc: `filter`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `filter` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
JQ-like deterministic filtering for tool outputs — prevents context overflow. Supports field extraction (.key), slicing ([0:10]), predicate filter ([?size > 100]), sort, unique, pluck, group_by, count, and first(N). Run any large list result through filter before returning to the LLM. Actions: filter.

## Actions
- `filter` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/filter')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `data`: `object` - Tool output dict to filter
- `query`: `string` - JQ-like filter expression (e.g. '.functions[?size > 100] | first(10)')

## Minimal Call Shapes
```json
{
  "name": "filter",
  "arguments": {
    "action": "filter"
  }
}
```
```json
{
  "name": "filter",
  "arguments": {
    "action": "grep",
    "source_action": "filter",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
