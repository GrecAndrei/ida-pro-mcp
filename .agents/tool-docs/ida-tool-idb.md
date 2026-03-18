# IDA MCP Tool Doc: `idb`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `idb` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Database metadata and segment information. Actions: meta, summary, segments, entrypoints, bookmarks, overview.

## Actions
- `meta` (tool-specific)
- `summary` (read/discovery)
- `segments` (tool-specific)
- `entrypoints` (tool-specific)
- `bookmarks` (tool-specific)
- `overview` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/idb')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `meta, summary, segments, entrypoints, bookmarks, overview`
- `count`: `integer`
- `offset`: `integer`

## Minimal Call Shapes
```json
{
  "name": "idb",
  "arguments": {
    "action": "meta"
  }
}
```
```json
{
  "name": "idb",
  "arguments": {
    "action": "grep",
    "source_action": "meta",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
