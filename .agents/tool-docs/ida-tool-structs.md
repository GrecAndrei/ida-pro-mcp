# IDA MCP Tool Doc: `structs`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `structs` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Structure recovery and reconstruction. Actions: recover, analyze_usage, list, create, add_member, apply, reconstruct_vtable.

## Actions
- `recover`
- `analyze_usage`
- `list`
- `create`
- `add_member`
- `apply`
- `reconstruct_vtable`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
