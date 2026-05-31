# IDA MCP Tool Doc: `knowledge`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `knowledge` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Cross-session firmware knowledge base: chip family identification, persistent symbol memory, and symbol transfer across binaries. Actions: chip_identify, symbol_lookup, import_symbols, export_session, chip_families.

## Actions
- `chip_identify` (tool-specific)
- `symbol_lookup` (tool-specific)
- `import_symbols` (tool-specific)
- `export_session` (tool-specific)
- `chip_families` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/knowledge')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `chip_identify, symbol_lookup, import_symbols, export_session, chip_families`
- `chip_family`: `string` - Optional chip family tag for export_session
- `db_path`: `string` - Override path to symbol knowledge SQLite DB
- `limit`: `integer` - Result limit
- `min_confidence`: `number` - Minimum confidence threshold for symbol import
- `query`: `string` - Fuzzy text query for symbol lookup
- `session_id`: `string` - Optional source session identifier for export_session
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "knowledge",
  "arguments": {
    "action": "chip_identify"
  }
}
```
```json
{
  "name": "knowledge",
  "arguments": {
    "action": "grep",
    "source_action": "chip_identify",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
