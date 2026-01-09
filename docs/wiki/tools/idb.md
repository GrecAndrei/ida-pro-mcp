# IDB Tool Manual

Low-level database metadata and entry point discovery.

## Actions
### Supported Actions
- meta
- segments
- cursor
- entrypoints


### `cursor`
Return current cursor position.

### `meta`
Return database metadata.
Returns global info about the database.
*   **Returns**: Module name, architecture, base address, file MD5/SHA256.

### `entrypoints`
List entrypoints.
Lists all program entry points (exported symbols and main).

### `segments`
Return segment metadata.
Lists all segments with their permissions (R/W/X) and ranges.

## Strategy
Use `meta` as your first call in every new session to understand the target environment (e.g. "Is this x64 or ARM?").
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
