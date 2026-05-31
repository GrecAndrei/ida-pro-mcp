# IDA MCP Tool Doc: `data`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `data` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Retrieve core IDB data. functions: list all functions — always includes xref count (capped 999). globals: global variables. strings: string literals — always includes xref count. imports: imported modules and functions. exports: exported entry points. lookup: resolve name↔address. bulk_query: multiple queries in one call. capability_matrix: binary capability matrix from imports + function classifications. string_xrefs: ranked string-to-function xref map with module clustering.

## Actions
- `functions` (tool-specific)
- `globals` (tool-specific)
- `strings` (tool-specific)
- `imports` (tool-specific)
- `exports` (tool-specific)
- `lookup` (tool-specific)
- `bulk_query` (tool-specific)
- `capability_matrix` (tool-specific)
- `string_xrefs` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/data')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `functions, globals, strings, imports, exports, lookup, bulk_query, capability_matrix, string_xrefs`
- `count`: `integer`
- `include_prototype`: `boolean`
- `include_xrefs`: `boolean`
- `items`: `array`
- `min_size`: `integer`
- `named_only`: `boolean`
- `offset`: `integer`
- `query`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "data",
  "arguments": {
    "action": "functions"
  }
}
```
```json
{
  "name": "data",
  "arguments": {
    "action": "grep",
    "source_action": "functions",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
