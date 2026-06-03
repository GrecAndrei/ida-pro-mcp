# IDA MCP Tool Doc: `schemaboot`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `schemaboot` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Structured semantic indexing with induced attribute-value schemas for function-level retrieval. Actions: ingest, query, refresh, stats, delete, get.

## Actions
- `extract` (tool-specific)
- `extract_single` (tool-specific)
- `ingest` (tool-specific)
- `query` (tool-specific)
- `get` (read/discovery)
- `stats` (tool-specific)
- `delete` (destructive)
- `refresh` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/schemaboot')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `extract, extract_single, ingest, query, get, stats, delete, refresh`
- `addr`: `string` - Function address for get/refresh
- `constraints`: `object` - Structured query constraints
- `include_apis`: `boolean` - Include API list in results
- `include_strings`: `boolean` - Include string refs in results
- `limit`: `integer` - Max results
- `offset`: `integer` - Skip first N results
- `order_by`: `string` - Column to order by (e.g., 'entropy DESC')
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "schemaboot",
  "arguments": {
    "action": "extract"
  }
}
```
```json
{
  "name": "schemaboot",
  "arguments": {
    "action": "grep",
    "source_action": "extract",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
