# IDA MCP Tool Doc: `firmware_view`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `firmware_view` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Firmware triage: region scanning, pointer sweeps, table carving, deterministic detection logic, multi-region campaigns, and bootstrap orchestration. Actions: scan_region, auto_retype, pointer_sweep, recommend, table_candidates, smart_carve, rollback_last, review_contradictions, region_profile, pointer_clusters, carve_plan, campaign, segment_sweep, multi_region_campaign, campaign_checkpoint, campaign_resume, campaign_feedback, fingerprint_index_sync, fingerprint_index_query, detect_load_address, detect_vector_table, detect_mmio, rtos_scan, triage_snapshot, bootstrap.

## Actions
- `scan_region` (tool-specific)
- `auto_retype` (tool-specific)
- `pointer_sweep` (tool-specific)
- `recommend` (tool-specific)
- `table_candidates` (tool-specific)
- `smart_carve` (tool-specific)
- `rollback_last` (tool-specific)
- `review_contradictions` (tool-specific)
- `region_profile` (tool-specific)
- `pointer_clusters` (tool-specific)
- `carve_plan` (tool-specific)
- `campaign` (tool-specific)
- `segment_sweep` (tool-specific)
- `multi_region_campaign` (tool-specific)
- `campaign_checkpoint` (tool-specific)
- `campaign_resume` (tool-specific)
- `campaign_feedback` (tool-specific)
- `fingerprint_index_sync` (tool-specific)
- `fingerprint_index_query` (tool-specific)
- `detect_load_address` (tool-specific)
- `detect_vector_table` (tool-specific)
- `detect_mmio` (tool-specific)
- `rtos_scan` (tool-specific)
- `triage_snapshot` (tool-specific)
- `bootstrap` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/firmware_view')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "firmware_view",
  "arguments": {
    "action": "scan_region"
  }
}
```
```json
{
  "name": "firmware_view",
  "arguments": {
    "action": "grep",
    "source_action": "scan_region",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
