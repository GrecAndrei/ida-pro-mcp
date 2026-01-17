# IDB Tool Manual

Low-level database metadata and entry point discovery.

## Actions
### Supported Actions
- meta
- summary
- segments
- entrypoints
- bookmarks

### `meta`
Return database metadata.
Returns global info about the database.
*   **Returns**: Module name, architecture, base address, file MD5/SHA256.

### `summary`
Return database summary.
Returns count of functions, segments, and analysis status.
*   **Returns**: Functions count, segments count, analysis_ok status.

### `entrypoints`
List entrypoints.
Lists all program entry points (exported symbols and main).

### `segments`
Return segment metadata.
Lists all segments with their permissions (R/W/X) and ranges.

### `bookmarks`
Return IDA bookmarks.
Lists all bookmarks set in the database.

## Strategy
Use `meta` as your first call in every new session to understand the target environment (e.g. "Is this x64 or ARM?"). Use `summary` for a quick overview of the analysis state.

**Note**: The `cursor` action is now available in the `nav` tool, not in `idb`.
---
Doc status: Updated actions to match actual implementation.
Last reviewed: 2026-01-11
