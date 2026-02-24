# SEGMENTS Tool Manual

## What It Does
Creates, inspects, and edits segment layout/metadata, including permissions and rebasing operations.

## Actions
- `list`: Enumerate segments with pagination.
- `info`: Detailed segment metadata and item counts.
- `add`: Create a segment.
- `delete`: Remove a segment.
- `set_attr`: Set segment attribute field.
- `set_perms`: Set permissions by `rwx` string or integer.
- `move`: Relocate a segment start.

## Key Parameters
- `action`: One of `list|add|delete|set_attr|set_perms|move|info`.
- `start`: Segment address (source for `move`; lookup for `info`/`delete`/edits).
- `end`: Segment end (`add`) or new start (`move`).
- `name`: Segment name (`add` or `info` lookup).
- `sclass`: Segment class for `add` (default `DATA`).
- `attr`, `value`: Attribute key/value for `set_attr`.
- `offset`, `count`: Pagination for `list`.

## Examples
```python
segments(action="list", offset=0, count=20)
segments(action="info", name=".text")
segments(action="add", start="0x700000", end="0x701000", name="blob", sclass="DATA")
segments(action="set_perms", start="0x700000", value="rw")
segments(action="move", start="0x700000", end="0x710000")
segments(action="delete", start="0x710000")
```

## Failure Modes
- Missing required fields for mutating actions.
- Invalid address parsing.
- Segment lookup failure (`SEGMENT_NOT_FOUND`).
- Invalid attribute name in `set_attr`.
- Segment move may fail with IDA-specific move error codes (room/loader/chunk/orphan).
