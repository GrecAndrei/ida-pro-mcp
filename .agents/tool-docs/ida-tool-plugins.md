# IDA MCP Tool Doc: `plugins`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `plugins` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Legacy alias for misc plugin actions. Prefer misc(action=plugin_list|plugin_run).

## Actions
- (none documented)
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
