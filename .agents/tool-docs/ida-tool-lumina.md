# IDA MCP Tool Doc: `lumina`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `lumina` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Lumina server interaction. Actions: pull, push, status, history, search.

## Actions
- `pull`
- `push`
- `status`
- `history`
- `search`
- `get_metadata`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
