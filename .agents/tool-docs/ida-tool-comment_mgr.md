# IDA MCP Tool Doc: `comment_mgr`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `comment_mgr` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Structured comment management with context-aware get/set and markdown import/export. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.

## Actions
- `get_context` (tool-specific)
- `set_structured` (tool-specific)
- `bulk_set` (tool-specific)
- `export_md` (tool-specific)
- `import_md` (tool-specific)
- `summary` (read/discovery)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/comment_mgr')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "comment_mgr",
  "arguments": {
    "action": "get_context"
  }
}
```
```json
{
  "name": "comment_mgr",
  "arguments": {
    "action": "grep",
    "source_action": "get_context",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
