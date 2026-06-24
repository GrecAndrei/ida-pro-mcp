# IDA MCP Tool Doc: `agent`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `agent` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
High-level AI-assisted analysis combining search, context packing, multi-hop discovery, and CFG similarity. Actions: analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar, bridge_query, reflect, cluster, fingerprint, cfg_encode, cfg_similar, cfg_stats. NOTE: similar and cluster overlap functionally with intelligence.similar_functions (embedding-based nearest neighbors); for embedding-indexed similarity prefer intelligence.*, for the older 'structured context pack' workflow use agent.*. cfg_encode/cfg_similar/cfg_stats are agent-specific structural CFG features not present in graph.*.

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
- `bridge_query` (tool-specific)
- `reflect` (tool-specific)
- `cluster` (tool-specific)
- `fingerprint` (tool-specific)
- `cfg_encode` (tool-specific)
- `cfg_similar` (tool-specific)
- `cfg_stats` (tool-specific)

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
- `action`: `string` - allowed_count: `17`
- `addr`: `string`
- `db_path`: `string`
- `depth`: `integer`
- `func_limit`: `integer`
- `include_evidence`: `boolean`
- `include_pseudocode`: `boolean`
- `items`: `array`
- `k`: `integer`
- `limit`: `integer`
- `max_items`: `integer`
- `persist_blackboard`: `boolean`
- `persist_capsule`: `boolean`
- `query`: `string`
- `threshold`: `number`
- `top_k`: `integer`
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
