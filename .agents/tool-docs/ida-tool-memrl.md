# IDA MCP Tool Doc: `memrl`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `memrl` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Compatibility wrapper over the intelligence-backed preference memory store for skill ranking, strategy suggestion, and usage feedback tracking. Actions: record, update, rank, stats, top, get_q, suggest, feedback.

## Actions
- `record` (tool-specific)
- `update` (tool-specific)
- `rank` (tool-specific)
- `stats` (tool-specific)
- `top` (tool-specific)
- `get_q` (tool-specific)
- `suggest` (tool-specific)
- `feedback` (tool-specific)
- `ingest` (tool-specific)
- `list_suggestions` (tool-specific)
- `get_suggestion` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/memrl')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `record, update, rank, stats, top, get_q, suggest, feedback, ingest, list_suggestions, get_suggestion`
- `alpha`: `number` - Learning rate for TD updates (default 0.15)
- `candidate_pool`: `array` - Candidates from Phase A for Phase B re-ranking
- `context_addr`: `string` - Address context for the suggestion
- `db_path`: `string` - Override path to MemRL SQLite DB
- `epsilon`: `number` - Epsilon-greedy exploration probability (default 0.0)
- `experience_key`: `string` - Identifier for the retrieved candidate
- `experience_meta`: `object` - Metadata dict for the experience
- `feedback_type`: `string` - Feedback type: accept, reject, partial, undo, skip
- `initial_q`: `number` - Initial Q-value for ingest (default 0.5)
- `intent_key`: `string` - Identifier for the query/analyst intent
- `lambda_explore`: `number` - Weight for Q-value vs similarity (0=pure similarity, 1=pure Q)
- `limit`: `integer` - Max items to return for list_suggestions
- `offset`: `integer` - Pagination offset for list_suggestions
- `query_embedding`: `array` - Query embedding for semantic search
- `reward`: `number` - Environmental feedback (+1 accept, +0.5 partial, 0 skip, -0.5 reject, -1 dangerous)
- `similarity_key`: `string` - Dict key to read similarity score from candidate_pool items
- `source_action`: `string` - Action that created the suggestion (rename, comment, etc.)
- `source_tool`: `string` - Tool that created the suggestion (modify, annotation, etc.)
- `suggestion_id`: `string` - Suggestion ID for feedback/get_suggestion actions
- `top_k`: `integer` - Number of results to return
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "memrl",
  "arguments": {
    "action": "record"
  }
}
```
```json
{
  "name": "memrl",
  "arguments": {
    "action": "grep",
    "source_action": "record",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
