# SEGMENTS Tool Manual

Low-level segment and section management.

## Actions
### Supported Actions
- list
- add
- delete
- set_attr
- set_perms
- move


### `delete`
Remove the specified item.

### `list`
List available items for this tool with optional paging where supported.
Lists all segments in the binary with their base, size, and permissions. Supports `offset` and `count`.

### `add` / `delete`
Create a new item using the provided parameters.
Creates or removes manual segments. Useful for mapping custom firmware blobs.

### `set_attr`
Update tool-specific attributes on the target object.
Modifies segment attributes (name, permissions, addressing mode).

### `set_perms`
Set segment permissions.
Sets segment permissions using a string like `rwx` or a numeric flag mask.

### `move`
Relocate a segment to a new address.
Rebases a segment to a new address.

## Strategy
If you are analyzing shellcode, use `add` to map the raw bytes into a new segment at the correct offset.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
