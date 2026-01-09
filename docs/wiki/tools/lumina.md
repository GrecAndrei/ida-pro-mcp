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

### `pull`
Pull symbols from Lumina.
Retrieves metadata (names, comments, prototypes) from the Lumina server.
*   **Args**: `addr` (optional). If omitted, pulls for all functions.
*   **Best for**: Automatically naming standard library functions in stripped binaries.

### `push`
Push symbols to Lumina.
Contributes your analysis to the Lumina server.
*   **Args**: `addr` (specific function) or `push_all=True`.

### `status`
Report current status and availability.
Checks connection status and your Lumina account info.

### `search`
Search for matching content and return matching topics.
Searches the Lumina database by name or pattern.

## Note on IDA 9.2
This tool uses the modern `ida_lumina` module. It is much faster and more reliable than the legacy Lumina commands.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
