# PROJECT Tool Manual

Project-level I/O and batch operations.

## Actions
### Supported Actions
- save
- close
- open
- load_binary
- list_recent
- get_cwd
- set_cwd
- list_dir
- exists
- read
- write
- sessions
- batch


### `close`
Close the requested resource or database.

### `load_binary`
Load a binary into a new database.

### `list_recent`
List recent projects.

### `get_cwd`
Get server working directory.

### `set_cwd`
Set server working directory.

### `list_dir`
List directory contents.

### `exists`
Check if a path exists.

### `read`
Read data or content from the specified source.

### `write`
Write data or content to the specified destination.

### `sessions`
List known session databases.

### `save`
Save the current database.
Saves the current database (.i64).

### `open`
Open the requested resource or database.
Opens a new file or database. Terminating the current session.

### `batch`
Analyzes multiple files in sequence.

## Best Practices
Always `save` before calling `python` or other dangerous tools.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
