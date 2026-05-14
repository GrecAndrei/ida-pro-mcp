# firmware_view

Firmware triage and campaign orchestration for raw binary blobs — pointer recovery, region typing, table carving, and cross-image function fingerprinting.

## Actions
- `scan_region` — scan a memory region for structure hints; params: `start`, `end`
- `auto_retype` — automatically retype a region based on heuristics; params: `start`, `end`
- `pointer_sweep` — sweep a region for valid pointers; params: `start`, `end`
- `recommend` — suggest next firmware analysis actions based on current state
- `table_candidates` — find likely table/array structures; params: `start`, `end`
- `smart_carve` — carve embedded objects (compressed blobs, certificates, images); params: `start`, `end`
- `rollback_last` — undo the last `auto_retype` operation
- `review_contradictions` — list conflicting type assignments in current session
- `region_profile` — detailed profile of a region (entropy, pointer density, string density); params: `start`, `end`
- `pointer_clusters` — group discovered pointers into clusters; params: `start`, `end`
- `carve_plan` — generate a carving plan without executing it; params: `start`, `end`
- `campaign` — run a single-region analysis campaign; params: `start`, `end`
- `segment_sweep` — sweep all segments for firmware artifacts
- `multi_region_campaign` — main entry point for full firmware triage across all regions
- `campaign_checkpoint` — save campaign progress for later resumption
- `campaign_resume` — resume a previously checkpointed campaign; params: `checkpoint_id`
- `campaign_feedback` — provide feedback on campaign results to improve future runs; params: `checkpoint_id`, `feedback`
- `fingerprint_index_sync` — sync current binary's function fingerprints to the cross-image index
- `fingerprint_index_query` — query the fingerprint index for matches across images; params: `address` or `fingerprint`

## Examples
```json
{"name": "firmware_view", "arguments": {"action": "multi_region_campaign"}}
```
```json
{"name": "firmware_view", "arguments": {"action": "scan_region", "start": "0x08000000", "end": "0x08001000"}}
```
```json
{"name": "firmware_view", "arguments": {"action": "fingerprint_index_query", "address": "0x08000400"}}
```
```json
{"name": "firmware_view", "arguments": {"action": "campaign_resume", "checkpoint_id": "cp_001"}}
```
```json
{"name": "firmware_view", "arguments": {"action": "rollback_last"}}
```

## Notes
- **Always run `binary_info(action="headers")` or `binary_info(action="sections")` first** to understand the layout before using firmware_view on raw blobs.
- `multi_region_campaign` is the recommended starting point for firmware triage — it orchestrates scan, type, and carve across all regions.
- `fingerprint_index_sync` + `fingerprint_index_query` enable cross-image function matching (useful for shared library detection across firmware versions).
- Use `campaign_checkpoint` / `campaign_resume` for long-running analyses that may exceed session time.
- `rollback_last` undoes only the most recent `auto_retype` — use `review_contradictions` to inspect conflicting assignments before rolling back.
