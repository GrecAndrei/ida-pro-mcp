# history

Undo/redo tracking and IDB snapshots for safe experimentation.

## Actions
- `undo` — undo last IDB modification
- `redo` — redo last undone modification
- `list` — list recent history entries. Optional `limit`
- `snapshot` — save a full IDB copy to `.ida_snapshots/` directory next to the IDB. Optional `label`
- `restore` — restore IDB from a snapshot. Params: `snapshot_id` or `label`
- `diff` — diff current state against a snapshot. Params: `snapshot_id`

## Examples
```json
{"name": "history", "arguments": {"action": "snapshot", "label": "before_bulk_rename"}}
```
```json
{"name": "history", "arguments": {"action": "restore", "label": "before_bulk_rename"}}
```

## Notes
- Always `snapshot` before large bulk edits for easy rollback.
- Snapshots are full IDB copies stored in `.ida_snapshots/` next to the active IDB file.
- `undo`/`redo` operate on IDA's internal undo stack (fine-grained, per-action).
