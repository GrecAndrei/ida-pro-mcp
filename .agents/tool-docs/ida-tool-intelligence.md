# IDA MCP Tool Doc: `intelligence`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `intelligence` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Intelligence subsystem: embedding-based classification, blackboard-driven indexing, and similarity search. Actions: intelligence_status, embedder_status, anchor_status, refresh_anchors, classify_text, classify_function, index_function, index_batch, similar_functions, semantic_search, blackboard_search, export_index_summary, evidence_card. Corpus is blackboard entries (curated hypotheses/IOCs/vulns), not raw decompiled functions — indexing never blocks IDA on full-binary pseudocode embedding. index_function needs a blackboard note at the address (write one first via blackboard(action='write')); index_batch pulls every blackboard entry (filtered by category, capped by max_items, gated by IDA_MCP_EMBED_CORPUS_GATE); similar_functions builds a query doc from the address's blackboard context and runs k-NN over the entry index. semantic_search and blackboard_search use the same vector index; the first is text→vector, the second is text→related_by_behavior on the blackboard store.

## Actions
- `intelligence_status` (tool-specific)
- `embedder_status` (tool-specific)
- `anchor_status` (tool-specific)
- `refresh_anchors` (tool-specific)
- `classify_text` (tool-specific)
- `classify_function` (tool-specific)
- `index_function` (tool-specific)
- `index_batch` (tool-specific)
- `similar_functions` (tool-specific)
- `semantic_search` (read/discovery)
- `blackboard_search` (tool-specific)
- `export_index_summary` (tool-specific)
- `evidence_card` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/intelligence')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `13`
- `addr`: `string`
- `block`: `boolean`
- `constraints`: `object` - Structured query constraints
- `deep_hash`: `boolean`
- `include_apis`: `boolean` - Include API list in results
- `include_resolved`: `boolean`
- `include_strings`: `boolean` - Include string refs in results
- `limit`: `integer`
- `max_items`: `integer`
- `offset`: `integer` - Skip first N results
- `order_by`: `string` - Column to order by (e.g., 'entropy DESC')
- `probe`: `boolean`
- `query`: `string`
- `similar_top_k`: `integer`
- `threshold`: `number`
- `top_k`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "intelligence",
  "arguments": {
    "action": "intelligence_status"
  }
}
```
```json
{
  "name": "intelligence",
  "arguments": {
    "action": "grep",
    "source_action": "intelligence_status",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
