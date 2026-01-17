# SESSION Tool Manual

Manage IDA Pro MCP sessions. Each session runs in its own headless IDA process and IDB file.

## Actions
### Supported Actions
- discover
- create
- list
- switch
- close
- status


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
*   **Args**: `binary_path`, `use_existing` (optional).
*   **Returns**: `session_id` and `idb_path`.

### `switch`
Switch the active session context for subsequent calls.
Switches the active context to a different session.
*   **Args**: `session_id`.

### `close`
Close the requested resource or database.
Terminates a session and releases the file lock.
*   **Args**: `session_id`.

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
