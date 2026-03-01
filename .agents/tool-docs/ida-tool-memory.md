# IDA MCP Tool Doc: `memory`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `memory` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Direct database memory access. Actions: read, write, hexdump.

## Actions
- `read`
- `write`
- `hexdump`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `read, write, hexdump`
- `addr`: `string`
- `data`: `string`
- `size`: `integer`
- `type`: `string` - allowed_count: `13`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
