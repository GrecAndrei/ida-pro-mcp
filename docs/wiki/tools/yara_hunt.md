# YARA_HUNT Tool Manual

Surgical pattern matching using YARA.

## Actions
### Supported Actions
- scan
- compile
- list_rules


### `compile`
Compile YARA rules.

### `scan`
Scan memory with YARA rules.
Scans the binary or a specific range using YARA rules.
*   **Args**: `rules` (raw rule text or file path), `addr` (optional), `size` (optional).
*   **Returns**: All string matches with their addresses.

### `list_rules`
List available YARA rules.
Lists pre-defined YARA rules in the `rules/` directory.

## Strategy
YARA is much more powerful than simple hex searching because it supports regex, case-insensitivity, and logical combinations. Use it for finding complex crypto constants or malware markers.

## Dependency Note
Requires `yara-python`. If missing, the tool will return a helpful installation error.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
