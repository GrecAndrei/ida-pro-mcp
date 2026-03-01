# IDA MCP Tool Doc: `calc`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `calc` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Mathematical and address resolution. Actions: eval, offset, convert, resolve, deref, chain, align.

## Actions
- `eval`
- `offset`
- `convert`
- `resolve`
- `deref`
- `chain`
- `align`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `eval, offset, convert, resolve, deref, chain, align`
- `addr`: `string`
- `expr`: `string`
- `offsets`: `array|string`
- `size`: `integer`
- `target`: `string`
- `type`: `string`
- `value`: `string|integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
