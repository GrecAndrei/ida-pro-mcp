# IDA MCP Tool Doc: `query`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `query` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Unified query interface combining data, search, code, types, symbols, and natural-language queries. Actions: data, search, idb, code, types, imports_deep, symbols, patterns, nl, nl_batch.

## Actions
- `data` (tool-specific)
- `search` (read/discovery)
- `idb` (tool-specific)
- `code` (tool-specific)
- `types` (tool-specific)
- `imports_deep` (tool-specific)
- `symbols` (tool-specific)
- `patterns` (tool-specific)
- `nl` (tool-specific)
- `nl_batch` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/query')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `data, search, idb, code, types, imports_deep, symbols, patterns, nl, nl_batch`
- `args`: `object`
- `subaction`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "query",
  "arguments": {
    "action": "data"
  }
}
```
```json
{
  "name": "query",
  "arguments": {
    "action": "grep",
    "source_action": "data",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
