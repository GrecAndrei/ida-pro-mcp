# IDA MCP Tool Doc: `idb`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `idb` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Query top-level IDB metadata: binary info, segments, entrypoints, bookmarks, and architecture profile guidance for raw binaries. Actions: meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile.

## Actions
- `meta` (tool-specific)
- `summary` (read/discovery)
- `segments` (tool-specific)
- `entrypoints` (tool-specific)
- `bookmarks` (tool-specific)
- `overview` (tool-specific)
- `architecture_profile` (tool-specific)
- `state` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/idb')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile, state`
- `audit_tail`: `integer`
- `count`: `integer`
- `offset`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

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
