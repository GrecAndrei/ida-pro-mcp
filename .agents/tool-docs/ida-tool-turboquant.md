# IDA MCP Tool Doc: `turboquant`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `turboquant` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Compatibility wrapper over the intelligence-backed function embedding index for fast semantic similarity queries over binary artifacts. Actions: ingest, query, stats, delete.

## Actions
- `ingest` (tool-specific)
- `query` (tool-specific)
- `stats` (tool-specific)
- `delete` (destructive)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/turboquant')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `ingest, query, stats, delete`
- `db_path`: `string` - Override path to TurboQuant bank file
- `query_key`: `string` - Function address or name to query
- `top_k`: `integer` - Number of similar functions to return
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "turboquant",
  "arguments": {
    "action": "ingest"
  }
}
```
```json
{
  "name": "turboquant",
  "arguments": {
    "action": "grep",
    "source_action": "ingest",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
