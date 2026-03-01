# IDA MCP Tool Doc: `types`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `types` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Type Library (TIL) and prototype management. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header.

## Actions
- `list`
- `get`
- `set_prototype`
- `parse_decl`
- `declare`
- `apply`
- `search_structs`
- `infer`
- `read_struct`
- `import_header`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
