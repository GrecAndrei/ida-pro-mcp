# IDA MCP Tool Doc: `stack_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `stack_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Stack frame analysis. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.

## Actions
- `frame`
- `buffers`
- `canary`
- `alignment`
- `spills`
- `usage`
- `variables`
- `arrays`
- `uninitialized`
- `summary`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
