# HISTORY Tool Manual

Database version control, snapshots, and undo management.

## Actions
### Supported Actions
- undo
- redo
- list
- snapshot
- restore
- diff


### `redo`
Redo the last undone change.

### `list`
List available items for this tool with optional paging where supported.

### `restore`
Restore a database snapshot.

### `snapshot`
Create a database snapshot.
Creates a named save point of the current database.
*   **Best for**: Creating a recovery point before performing risky bulk renames or script-heavy refactoring.
*   **IDA 9.2**: Uses native snapshot API if available.

### `undo` / `redo`
Undo the last database change.
Traditional undo stack manipulation.
*   **Args**: `count` (Number of steps).

### `diff`
Show snapshot diffs.
Shows a summary of modified functions since the database was opened.

## Strategy
Always call `history(action='snapshot', name='before_rename_session')` before letting an LLM do massive work. This gives you a one-click "undo" safety net.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
