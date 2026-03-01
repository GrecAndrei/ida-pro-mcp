# IDA MCP Tool Doc: `hooks`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `hooks` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Hook suggestion and script generation. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.

## Actions
- `suggest`
- `generate_frida`
- `generate_detours`
- `find_targets`
- `inline_hooks`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
