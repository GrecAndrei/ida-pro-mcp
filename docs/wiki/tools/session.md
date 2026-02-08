# SESSION Tool Manual

Manage IDA Pro MCP sessions. Each session runs in its own headless IDA process and IDB file.

## Actions
### Supported Actions
- discover
- create
- get
- list
- switch
- close
- status
- rebuild


### `list`
List available items for this tool with optional paging where supported.

### `status`
Report current status and availability.

### `discover`
Scan for existing sessions or cached IDBs and return matches.
Finds existing session IDBs in the cache directory.
*   **Args**: none.
*   **Returns**: List of `.i64` session files.

### `create`
Create a new entity using the provided parameters.
Creates a new session for a binary.
*   **Args**: `binary_path` or `idb_path`, `use_existing` (optional), `force_new` (optional),
    `ida_args` (optional), plus analysis options like `processor`, `flags`, `bitness`,
    `endian`, `loader`, `value`/`loader_options`, `options`, `reanalyze`, `apply_once`,
    `analysis_actions`, `recover`, `backup_on_recover`, `aggressive_cleanup`.
*   **Returns**: session metadata with `session_id`, `idb_path`, and runtime flags.

### `switch`
Switch the active session context for subsequent calls.
Switches the active context to a different session.
*   **Args**: `session_id`.

### `close`
Close the requested resource or database.
Terminates a session and releases the file lock.
*   **Args**: `session_id`.

### `get`
Fetch a single session by ID, including runtime status.

### `rebuild`
Recreate the IDB for a session with updated analysis options.

## Best Practices
Use `discover` to reattach to prior session IDBs and avoid re-analysis.
### `list`
List available items for this tool with optional paging where supported.
Lists all tracked sessions for the current server instance.

### `status`
Report current status and availability.
Returns the currently selected session (if any).
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
