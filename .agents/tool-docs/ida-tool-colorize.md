# IDA MCP Tool Doc: `colorize`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `colorize` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.

## Actions
- `set_func`
- `set_range`
- `set_insn`
- `get`
- `clear`
- `palette`
- `highlight_pattern`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
