# IDA MCP Tool Doc: `entropy`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `entropy` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Entropy and packing detection. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.

## Actions
- `section`
- `region`
- `packed_detect`
- `crypto_detect`
- `compare`
- `window`
- `summary`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `section, region, packed_detect, crypto_detect, compare, window, summary`
- `addr`: `string`
- `end_addr`: `string`
- `limit`: `integer`
- `size`: `integer`
- `step`: `integer`
- `threshold`: `number`
- `window`: `integer`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
