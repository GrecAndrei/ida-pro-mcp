# SESSION Tool Manual

## What It Does
Manages host-side multi-session lifecycle (create/reuse/switch/rebuild/delete), tracks metadata, and defines the active context used by other tools.

## Actions
- `discover`: Reload/discover recoverable sessions.
- `create`: Create new session or reuse existing matching binary/IDB unless `force_new=true`.
- `get`: Get one session by `session_id` (includes runtime status).
- `list`: List sessions with optional query + pagination.
- `switch`: Set active session by `session_id` or `binary_path`.
- `close`: Permanently delete session artifacts and stop runtime.
- `status`: Show active session and total session count.
- `rebuild`: Delete/recreate session IDB with updated analysis options.
- `update`, `rename`, `duplicate`
- `export_session`, `import_session`
- `archive`, `unarchive`
- `tag`, `untag`, `find_by_tag`
- `add_note`, `clear_notes`, `search_notes`
- `cleanup_stale`, `stats`, `validate`
- `bulk_delete`, `bulk_tag`
- `recent`, `oldest`
- `snapshot`, `restore_snapshot`
- `merge`

Host-side companion tools in the same stdio server:
- `bookmarks` actions: `add`, `list`, `delete`, `update`, `clear`, `find`, `export` (requires an active session).
- `truncation` action: `continue` (resume fields from `_continue.token` in truncated responses).

## Key Parameters
- `action`: One of session actions above.
- `binary_path`, `idb_path`/`use_existing`: Inputs for `create`.
- `force_new`: Force new session even when matching session exists.
- `analysis_options` and related create/rebuild keys (`processor`, `loader`, `bitness`, `endian`, etc.).
- `ida_args`: String or array of strings passed to IDA runtime.
- `session_id`: Required by many session-targeted actions.
- `query`, `limit`, `offset`: Filters/pagination for listing/search.
- `bookmarks` common args: `addr`, `id`, `name`, `notes`, `category`, `priority`, `tags`, `query`.
- `truncation` args: `token` (required), plus optional `field`, `offset`, `count`.

## Examples
```json
{"name":"session","arguments":{"action":"create","binary_path":"/samples/a.out","tags":["triage"],"notes":"initial pass"}}
```

```json
{"name":"session","arguments":{"action":"list","query":"triage","limit":20,"offset":0}}
```

```json
{"name":"session","arguments":{"action":"switch","session_id":"A1B2C3D4"}}
```

```json
{"name":"bookmarks","arguments":{"action":"add","addr":"0x401000","name":"entry-check","tags":["triage","input"]}}
```

```json
{"name":"truncation","arguments":{"action":"continue","token":"AB12CD34","field":"results","offset":100,"count":50}}
```

## Failure Modes
- `create` requires `binary_path` or `idb_path`; invalid paths are rejected.
- `close` is destructive (session files and logs are removed).
- Many actions require `session_id` when there is no active session.
- Nonexistent `session_id` returns session-not-found.
- `rebuild` can fail if IDB deletion is blocked/locked.
- `restore_snapshot` fails if snapshot id is unknown (snapshots are in-memory, process-lifetime only).
