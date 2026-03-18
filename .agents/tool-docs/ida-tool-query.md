# IDA MCP Tool Doc: `query`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `query` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Unified read-only query hub. Actions: data, search, idb, code, types, imports_deep, symbols, patterns.

## Actions
- `data` (tool-specific)
- `search` (read/discovery)
- `idb` (tool-specific)
- `code` (tool-specific)
- `types` (tool-specific)
- `imports_deep` (tool-specific)
- `symbols` (tool-specific)
- `patterns` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/query')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `data, search, idb, code, types, imports_deep, symbols, patterns`
- `args`: `object`
- `subaction`: `string`

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
