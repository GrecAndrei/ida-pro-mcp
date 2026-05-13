# project

Project-level operations: save, open, close IDBs, manage working directory, and export casefiles.

## Actions
- `save` — save current IDB to disk
- `close` — close current IDB
- `open` — open an existing IDB. Params: `path`
- `load_binary` — load a new binary for analysis. Params: `path`, optional `loader`, `arch`
- `list_recent` — list recently opened files
- `get_cwd` — get current working directory
- `set_cwd` — set working directory. Params: `path`
- `list_dir` — list directory contents. Params: `path`, optional `pattern`
- `casefile_export` — export full analysis casefile (annotations, bookmarks, types). Optional `path`

## Examples
```json
{"name": "project", "arguments": {"action": "save"}}
```
```json
{"name": "project", "arguments": {"action": "casefile_export", "path": "/tmp/case.json"}}
```

## Notes
- `load_binary` creates a new IDB from a raw binary; use `session(action="create")` for session-managed workflows.
- `casefile_export` bundles all analysis artifacts for sharing or archival.
- `set_cwd` affects relative path resolution for subsequent file operations.
