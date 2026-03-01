# IDA MCP Tool Doc: `data_ops`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `data_ops` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Data type conversion. Actions: make_data, make_array, make_string, undefine, make_code.

## Actions
- `make_data`
- `make_array`
- `make_string`
- `undefine`
- `make_code`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
