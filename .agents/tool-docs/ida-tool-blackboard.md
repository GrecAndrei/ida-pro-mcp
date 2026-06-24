# IDA MCP Tool Doc: `blackboard`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `blackboard` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Persistent RE knowledge base: findings, hypotheses, IOCs, decisions, and knowledge graph. write/read/list/search/update/delete: CRUD for findings. frontier: ranked unvisited functions — read this when choosing what to analyze next. next_target: priority queue by confidence×recency×xrefs. decision_card: record a verified claim with evidence citations (required before write-surface tools in prove phase). contradict/resolve/add_evidence/calibrate: evidence lifecycle. Actions: write, read, list, search, update, delete, clear, stats, frontier, next_target, decision_card, working_set, state_health, contradict, resolve, add_evidence, calibrate, campaign_summary, propagate_labels, start_crawler, stop_crawler, phase_set, phase_status, policy_set, policy_check.

## Actions
- `policy_set` (tool-specific)
- `policy_status` (tool-specific)
- `policy_check` (tool-specific)
- `phase_status` (tool-specific)
- `phase_set` (tool-specific)
- `phase_tick` (tool-specific)
- `quest_board` (tool-specific)
- `quest_complete` (tool-specific)
- `memory_compile` (tool-specific)
- `phase_finalize` (tool-specific)
- `trace_ingest` (tool-specific)
- `trace_run` (tool-specific)
- `trace_status` (tool-specific)
- `proposal_create` (tool-specific)
- `proposal_list` (tool-specific)
- `proposal_accept` (tool-specific)
- `proposal_reject` (tool-specific)
- `decision_card` (tool-specific)
- `working_set` (tool-specific)
- `state_health` (tool-specific)
- `notes_export` (tool-specific)
- `notes_import` (tool-specific)
- `write` (write/mutate)
- `read` (read/discovery)
- `list` (read/discovery)
- `search` (read/discovery)
- `update` (tool-specific)
- `delete` (destructive)
- `clear` (destructive)
- `stats` (tool-specific)
- `prune` (tool-specific)
- `merge` (tool-specific)
- `contradict` (tool-specific)
- `resolve` (tool-specific)
- `next_target` (tool-specific)
- `frontier` (tool-specific)
- `coverage` (tool-specific)
- `propagate_labels` (tool-specific)
- `start_crawler` (tool-specific)
- `stop_crawler` (tool-specific)
- `crawler_status` (tool-specific)
- `accept` (tool-specific)
- `reject` (tool-specific)
- `add_evidence` (tool-specific)
- `calibrate` (tool-specific)
- `campaign_summary` (tool-specific)
- `auto_tag_propagate` (tool-specific)
- `accept_proposal` (tool-specific)
- `reject_proposal` (tool-specific)
- `add_system` (tool-specific)
- `add_struct` (tool-specific)
- `add_gap` (tool-specific)
- `fill_gap` (tool-specific)
- `add_state_machine` (tool-specific)
- `add_peripheral` (tool-specific)
- `add_attack_surface` (tool-specific)
- `kg_summary` (tool-specific)
- `kg_systems` (tool-specific)
- `kg_gaps` (tool-specific)
- `kg_structs` (tool-specific)
- `kg_state_machines` (tool-specific)
- `kg_attack_surface` (tool-specific)
- `kg_peripherals` (tool-specific)
- `export_symbols` (tool-specific)
- `import_symbols` (tool-specific)
- `semantic_index` (tool-specific)
- `semantic_rebuild` (tool-specific)
- `related_by_behavior` (tool-specific)
- `deref` (tool-specific)
- `chain` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/blackboard')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `70`
- `addr`: `string` - Associated address
- `binary_type`: `string`
- `call_stack`: `array`
- `category`: `string` - Category (default: general)
- `confidence`: `number` - Confidence score 0-1
- `content`: `string` - Content/body text
- `db_path`: `string` - Override path to blackboard SQLite DB
- `drivers`: `array`
- `entry_id`: `string` - Entry ID for read/update/delete
- `entry_points`: `array`
- `exit_points`: `array`
- `filled_by`: `string`
- `force`: `boolean` - Force semantic_rebuild to re-embed all matching entries
- `gap_id`: `string`
- `gap_type`: `string`
- `hints`: `array`
- `include_contradicted`: `boolean` - Include contradicted entries in semantic retrieval
- `include_resolved`: `boolean` - Include resolved entries in semantic retrieval
- `input_type`: `string`
- `limit`: `integer` - Max entries to return
- `members`: `array`
- `min_confidence`: `number` - Minimum confidence filter
- `offset`: `integer` - Pagination offset
- `periph_type`: `string`
- `query`: `string` - Semantic/behavior query for search and related_by_behavior
- `reachable_from`: `array`
- `resolved`: `boolean`
- `size_bytes`: `integer`
- `state_var`: `string`
- `states`: `array`
- `tag`: `string` - Filter by single tag
- `tags`: `array` - Tags for categorization
- `threshold`: `number` - Similarity threshold for semantic retrieval
- `title`: `string` - Title for write/update
- `top_k`: `integer` - Top-K results for semantic retrieval
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "blackboard",
  "arguments": {
    "action": "policy_set"
  }
}
```
```json
{
  "name": "blackboard",
  "arguments": {
    "action": "grep",
    "source_action": "policy_set",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
