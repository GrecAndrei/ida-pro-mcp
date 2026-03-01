# IDA MCP Tool Doc: `compare`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `compare` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Function comparison and similarity. Actions: functions (side-by-side diff), blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.

## Actions
- `functions`
- `blocks`
- `apis`
- `strings`
- `constants`
- `structure`
- `semantics`
- `batch_compare`
- `find_clones`
- `changelog`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
