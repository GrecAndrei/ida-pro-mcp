# IDA MCP Tool Doc: `agent`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `agent` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
High-level analysis orchestrator. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack.

## Actions
- `analyze_function` (tool-specific)
- `explore_address` (tool-specific)
- `find_references` (tool-specific)
- `search_all` (tool-specific)
- `search_structs` (tool-specific)
- `context_pack` (tool-specific)
- `quick` (tool-specific)
- `rename_suggestions` (tool-specific)
- `batch_context` (tool-specific)
- `similar` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/agent')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar`
- `addr`: `string`
- `depth`: `integer`
- `include_pseudocode`: `boolean`
- `max_items`: `integer`
- `query`: `string`
- `use_cache`: `boolean`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "agent",
  "arguments": {
    "action": "analyze_function"
  }
}
```
```json
{
  "name": "agent",
  "arguments": {
    "action": "grep",
    "source_action": "analyze_function",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
