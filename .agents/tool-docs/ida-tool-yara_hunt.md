# IDA MCP Tool Doc: `yara_hunt`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `yara_hunt` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
YARA pattern matching. Actions: scan, compile, list_rules.

## Actions
- `scan`
- `compile`
- `list_rules`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
