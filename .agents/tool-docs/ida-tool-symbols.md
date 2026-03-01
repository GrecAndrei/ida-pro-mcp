# IDA MCP Tool Doc: `symbols`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `symbols` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
PDB/DWARF symbol management. Actions: load_pdb, load_dwarf, status, apply, export.

## Actions
- `load_pdb`
- `load_dwarf`
- `status`
- `apply`
- `export`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
