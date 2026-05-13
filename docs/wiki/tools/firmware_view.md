# firmware_view

Firmware triage and campaign orchestration for multi-region binary analysis.

## Actions
- `scan_region` — scan a memory region for firmware patterns; params: `address`, `size`
- `region_profile` — profile a region (entropy, strings, code density); params: `address`, `size`
- `segment_sweep` — sweep all segments for firmware indicators
- `campaign` — start a firmware analysis campaign; params: `regions` (list)
- `multi_region_campaign` — campaign across multiple regions; params: `regions`
- `campaign_checkpoint` — save campaign progress; params: `campaign_id`
- `campaign_resume` — resume a saved campaign; params: `campaign_id`
- `campaign_feedback` — provide feedback on campaign results; params: `campaign_id`, `feedback`
- `fingerprint_index_sync` — sync fingerprint index from current analysis
- `fingerprint_index_query` — query fingerprint index; params: `fingerprint`

## Examples
```json
{"name": "firmware_view", "arguments": {"action": "scan_region", "address": "0x08000000", "size": 65536}}
```
```json
{"name": "firmware_view", "arguments": {"action": "campaign_resume", "campaign_id": "fw_001"}}
```

## Notes
- `campaign_resume` takes `campaign_id`, not an address.
- `segment_sweep` is a good first action for unknown firmware blobs.
- Campaigns persist state and can be checkpointed/resumed across sessions.
