# IDA MCP Tool Doc: `agent`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `agent` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
High-level analysis orchestrator. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack.

## Actions
- `analyze_function`
- `explore_address`
- `find_references`
- `search_all`
- `search_structs`
- `context_pack`
- `quick`
- `rename_suggestions`
- `batch_context`
- `similar`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar`
- `addr`: `string`
- `depth`: `integer`
- `include_pseudocode`: `boolean`
- `max_items`: `integer`
- `query`: `string`
- `use_cache`: `boolean`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
