# IMPORTS_DEEP Tool Manual

Advanced import resolution, thunks, and API sets.

## Actions
### Supported Actions
- thunks
- delay
- forwarded
- ordinal
- api_sets
- resolve


### `delay`
Resolve delay-load imports.

### `ordinal`
Resolve ordinal imports.

### `thunks`
Resolve thunk imports.
Resolves jump thunks to their final API destination.

### `api_sets`
Resolve API set mappings.
Resolves Windows API Set redirections (e.g. `api-ms-win-core-file-l1-1-0.dll` -> `kernel32.dll`).

### `forwarded`
Resolve forwarded imports.
Detects exported functions that are actually forwarded to another DLL.

### `resolve`
Resolve VA and file offset information for an address.
Surgical resolution of an import at a specific address.
*   **Args**: `addr` (optional). If omitted, returns a list of the first 100 imported functions in the database.

## Strategy
If a function call points to `__imp_XXXX`, use `resolve` to get the real name and prototype.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
