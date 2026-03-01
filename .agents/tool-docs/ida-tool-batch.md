# IDA MCP Tool Doc: `batch`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `batch` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Run multiple tool calls in a single request. Arguments: calls[], continue_on_error.

## Actions
- `run`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `calls`: `array`
- `continue_on_error`: `boolean`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
