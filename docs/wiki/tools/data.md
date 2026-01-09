# DATA Tool Manual

Binary data queries and enumeration.

## Actions
### Supported Actions
- functions
- globals
- strings
- imports
- exports
- lookup
- bulk_query


### `globals`
List global symbols with pagination and optional filtering.

### `exports`
List exported entrypoints.

### `functions`
List functions with pagination and optional filtering.
Lists all functions in the binary.
*   **Args**: `query` (filter), `offset`, `count` (pagination).
*   **Default**: Shows all functions. Use pagination for large binaries.

### `strings`
List string literals with pagination and optional filtering.
Lists all strings found by IDA.
*   **Note**: Use `search.string` for targeted searching; use this for global discovery.

### `imports` / `exports`
List imported modules and symbols.
Lists all DLL imports and exported symbols. 
*   **Strategy**: Best for mapping the external attack surface of a binary.

### `lookup`
Resolve name to address or address to name.
Resolves a name to an address (or vice versa).

### `bulk_query`
Run multiple data queries in one call.
Run multiple data queries in one call with per-item pagination controls.

## Pagination
Most `data` actions support `offset` and `count`. Always use these if the tool reports more than 100 items to avoid context window overflow.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
