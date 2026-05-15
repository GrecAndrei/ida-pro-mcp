# firmware_view

Firmware triage and campaign orchestration for raw binary blobs — pointer recovery, region typing, table carving, and cross-image function fingerprinting.

## Quick Start (no datasheet needed)

```json
{"name": "firmware_view", "arguments": {"action": "detect_load_address"}}
{"name": "firmware_view", "arguments": {"action": "detect_vector_table"}}
{"name": "firmware_view", "arguments": {"action": "detect_mmio"}}
```

These three actions solve the hardest problems in raw firmware RE without any external documentation.

---

## Actions

### detect_load_address *(new)*
Determine the correct base/load address for a flat binary without a datasheet.

- **Cortex-M**: reads bytes[0:4] (initial SP, must be in RAM 0x20000000+) and bytes[4:8] (reset vector, must be in flash). Identifies base as 0x08000000 (STM32), 0x00000000, or 0x10000000 with 0.92 confidence.
- **Generic**: tries common bases (0x08000000, 0x00000000, 0x80000000, etc.) and scores by how many 4-byte values become valid self-referential pointers.
- **Size hints**: maps binary size to likely MCU family (STM32F0/F1, STM32F4/nRF52, ESP32, Linux firmware).

Returns: `candidates[]` with `base`, `confidence`, `method`, `arch`, `reset_handler`. `recommended_base` for the best candidate.

### detect_vector_table *(new)*
Find the interrupt vector table and extract all entry points.

- **Cortex-M**: reads IVT at binary start, extracts up to 64 entries with standard names (Reset_Handler, NMI_Handler, HardFault_Handler, IRQ0-47_Handler). Detects Thumb mode (LSB=1).
- **MIPS**: identifies exception vectors at 0x80000000/0xBFC00000.
- **Generic**: finds dense cluster of valid function pointers near binary start.

Writes all entry points to the blackboard as `hypothesis` entries (confidence=0.85). Returns `entry_points[]` for immediate `smart_decompile` calls.

### detect_mmio *(new)*
Identify MMIO peripheral registers by finding pointer-like values that point outside the binary's address range.

Cross-references against known peripheral bases for STM32/nRF52/ESP32/RP2040/generic Cortex-M/MIPS KSEG1. Groups by 4KB page, counts accesses, tracks which functions access each peripheral. Identifies chip family by voting.

Writes peripheral map to blackboard as IOC entries (`ioc_type='mmio_input'`). Returns `peripherals[]` with `base`, `access_count`, `peripheral_name`, `chip_family`, `accessed_from[]`.

---

### scan_region
Scan a memory region for structure hints. Params: `start`, `end`.

### auto_retype
Automatically retype a region based on heuristics. Params: `start`, `end`.

### pointer_sweep
Sweep a region for valid pointers. Params: `start`, `end`.

### recommend
Suggest next firmware analysis actions based on current state.

### table_candidates
Find likely table/array structures. Params: `start`, `end`.

### smart_carve
Carve embedded objects (compressed blobs, certificates, images). Params: `start`, `end`, `apply` (bool).

### rollback_last
Undo the last `auto_retype` operation.

### review_contradictions
List conflicting type assignments in current session.

### region_profile
Detailed profile of a region (entropy, pointer density, string density). Params: `start`, `end`.

### pointer_clusters
Group discovered pointers into clusters. Params: `start`, `end`.

### carve_plan
Generate a carving plan without executing it. Params: `start`, `end`.

### campaign
Run a single-region analysis campaign. Params: `start`, `end`.

### segment_sweep
Sweep all segments for firmware artifacts.

### multi_region_campaign
Main entry point for full firmware triage across all regions.

### campaign_checkpoint / campaign_resume / campaign_feedback
Save, resume, and provide feedback on campaign progress.

### fingerprint_index_sync / fingerprint_index_query
Cross-image function fingerprinting.

---

## Recommended Workflow (no datasheet)

```
1. firmware_view(action='detect_load_address')     → is the binary rebased correctly?
2. firmware_view(action='detect_vector_table')     → find all entry points
3. code(action='smart_decompile', addrs='<Reset_Handler>')  → analyze entry point
4. firmware_view(action='detect_mmio')             → identify peripheral registers
5. taint(action='report')                          → trace MMIO/UART inputs to sinks
6. firmware_view(action='scan_region')             → profile all regions
7. firmware_view(action='carve_plan')              → get retyping plan
8. firmware_view(action='smart_carve', apply=true) → apply structure
9. firmware_view(action='campaign')                → full automated campaign
```

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
