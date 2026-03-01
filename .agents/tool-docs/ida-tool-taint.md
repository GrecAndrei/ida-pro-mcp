# IDA MCP Tool Doc: `taint`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `taint` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Static data flow and vulnerability analysis. Actions: find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice.

## Actions
- `find_arg_usage`
- `trace_return`
- `find_sinks`
- `data_flow`
- `backward_trace`
- `slice`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice`
- `addr`: `string`
- `arg_num`: `integer`
- `depth`: `integer`
- `max_hits`: `integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
