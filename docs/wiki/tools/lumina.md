# LUMINA Tool Manual

Cloud-based function recognition using Hex-Rays Lumina.

## Actions
### Supported Actions
- pull
- push
- status
- history
- search


### `history`
Show Lumina history.
Requires UI action availability in IDA.

### `pull`
Pull symbols from Lumina.
Retrieves metadata (names, comments, prototypes) from the Lumina server.
*   **Args**: `addr` (optional). If omitted, pulls for all functions.
*   **Best for**: Automatically naming standard library functions in stripped binaries.

### `push`
Push symbols to Lumina.
Contributes your analysis to the Lumina server.
*   **Args**: `addr` (specific function) or `push_all=True`.
*   **Note**: Requires the Lumina UI actions to be available in the current IDA build.

### `status`
Report current status and availability.
Checks action availability and basic module status.

### `search`
Search for matching content and return matching topics.
Searches the Lumina database by name or pattern.
Currently returns a “not implemented” error because it requires interactive UI or a Lumina client integration.

## Note on IDA 9.2
This tool checks for `ida_lumina` when present and falls back to UI actions when available.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
