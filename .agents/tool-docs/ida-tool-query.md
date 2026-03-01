# IDA MCP Tool Doc: `query`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `query` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Unified read-only query hub. Actions: data, search, idb, code, types, imports_deep, symbols, patterns.

## Actions
- `data`
- `search`
- `idb`
- `code`
- `types`
- `imports_deep`
- `symbols`
- `patterns`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `data, search, idb, code, types, imports_deep, symbols, patterns`
- `args`: `object`
- `subaction`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
