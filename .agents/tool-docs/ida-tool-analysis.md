# IDA MCP Tool Doc: `analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Analysis configuration and reanalysis. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze.

## Actions
- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze`
- `bitness`: `integer`
- `end`: `string`
- `endian`: `string`
- `flags`: `integer`
- `loader`: `string`
- `options`: `object`
- `processor`: `string`
- `start`: `string`
- `value`: `string|object`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
