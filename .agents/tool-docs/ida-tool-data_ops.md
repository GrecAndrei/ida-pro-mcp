# IDA MCP Tool Doc: `data_ops`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `data_ops` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.

## Actions
- `make_data` (tool-specific)
- `make_array` (tool-specific)
- `make_string` (tool-specific)
- `undefine` (destructive)
- `make_code` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/data_ops')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "data_ops",
  "arguments": {
    "action": "make_data"
  }
}
```
```json
{
  "name": "data_ops",
  "arguments": {
    "action": "grep",
    "source_action": "make_data",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
