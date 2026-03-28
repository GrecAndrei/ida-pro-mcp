# IDA MCP Tool Doc: `taint`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `taint` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Static data flow and vulnerability analysis. Actions: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice.

## Actions
- `find_arg_usage` (tool-specific)
- `trace_return` (tool-specific)
- `find_sinks` (tool-specific)
- `data_flow` (tool-specific)
- `backward_trace` (tool-specific)
- `slice` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/taint')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice`
- `addr`: `string`
- `arg_num`: `integer`
- `depth`: `integer`
- `max_hits`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "taint",
  "arguments": {
    "action": "find_arg_usage"
  }
}
```
```json
{
  "name": "taint",
  "arguments": {
    "action": "grep",
    "source_action": "find_arg_usage",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
