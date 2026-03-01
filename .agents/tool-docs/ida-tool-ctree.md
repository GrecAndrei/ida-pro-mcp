# IDA MCP Tool Doc: `ctree`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `ctree` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Hex-Rays AST (CTree) analysis. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow.

## Actions
- `get`
- `traverse`
- `find_calls`
- `find_vars`
- `find_strings`
- `find_conditions`
- `get_logic_flow`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow`
- `addr`: `string`
- `depth`: `integer`
- `query`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
