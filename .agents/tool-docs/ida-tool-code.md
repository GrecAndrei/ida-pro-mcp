# IDA MCP Tool Doc: `code`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `code` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Code logic, decompilation, and flow analysis. Actions: decompile, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func.

## Actions
- `decompile` (tool-specific)
- `disasm` (tool-specific)
- `xrefs_to` (tool-specific)
- `xrefs_from` (tool-specific)
- `xrefs_to_field` (tool-specific)
- `callees` (tool-specific)
- `callers` (tool-specific)
- `blocks` (tool-specific)
- `analyze` (analysis)
- `callgraph` (tool-specific)
- `export` (tool-specific)
- `find_paths` (analysis)
- `strings_in_func` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/code')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `13`
- `addr`: `string`
- `addrs`: `array|string`
- `disasm_style`: `string` - allowed: `csmini, classic, annotated`
- `end`: `string`
- `field_name`: `string`
- `format`: `string`
- `include_bytes`: `boolean`
- `limit`: `integer`
- `max_depth`: `integer`
- `max_items`: `integer`
- `target`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "code",
  "arguments": {
    "action": "decompile"
  }
}
```
```json
{
  "name": "code",
  "arguments": {
    "action": "grep",
    "source_action": "decompile",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
