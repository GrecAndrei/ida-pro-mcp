# IDA MCP Tool Doc: `bridge_search`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `bridge_search` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Multi-hop bridge-conditioned search for discovering indirect relationships between entities. Actions: search, bridges.

## Actions
- `bridges` (tool-specific)
- `search` (read/discovery)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/bridge_search')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `bridges, search`
- `bridge_types`: `array` - Bridge types: ['apis'], ['strings'], or ['apis', 'strings']
- `func_ea`: `string` - Hex address of seed function (for action='bridges')
- `func_name`: `string` - Name of seed function (for action='bridges')
- `hops`: `integer` - Number of hops (2=standard, >2=extended)
- `query_constraints`: `object` - SchemaBoot-style constraints for seed selection
- `top_k`: `integer` - Max candidates to return
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "bridge_search",
  "arguments": {
    "action": "bridges"
  }
}
```
```json
{
  "name": "bridge_search",
  "arguments": {
    "action": "grep",
    "source_action": "bridges",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
