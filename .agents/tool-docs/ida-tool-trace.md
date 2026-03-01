# IDA MCP Tool Doc: `trace`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `trace` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Execution tracing. Actions: get, clear, set_options.

## Actions
- `get`
- `clear`
- `set_options`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
