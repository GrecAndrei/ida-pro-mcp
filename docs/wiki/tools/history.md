# HISTORY Tool Manual

## What It Does
Wraps IDA undo/redo and snapshot-related capabilities, with lightweight snapshot lookup and a heuristic change report.

## Actions
- `undo`: Perform up to `count` undo steps.
- `redo`: Perform up to `count` redo steps.
- `list`: Check undo/redo availability and descriptions (if supported).
- `snapshot`: Create named snapshot (native if available, else save DB copy).
- `restore`: Look up snapshot metadata by name.
- `diff`: Heuristic list of non-default function names (not full DB diff).

## Key Parameters
- `action`: One of `undo|redo|list|snapshot|restore|diff`.
- `count`: Undo/redo step count.
- `name`: Snapshot identifier for `snapshot` and required for `restore`.

## Examples
```python
history(action="undo", count=3)
history(action="redo", count=1)
history(action="list")
history(action="snapshot", name="pre_patch")
history(action="restore", name="pre_patch")
history(action="diff")
```

## Failure Modes
- `restore` with missing `name` or unknown snapshot metadata file.
- Snapshot creation failure when native and copy fallback both fail.
- `diff` is intentionally limited and not authoritative.
- API differences across IDA versions reduce detail in `list`.
