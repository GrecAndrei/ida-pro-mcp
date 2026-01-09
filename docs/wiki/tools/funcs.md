# FUNCS Tool Manual

Low-level function management.

## Actions
### Supported Actions
- create
- delete
- set_flags
- set_name
- add_comment
- list
- info


### `list`
List available items for this tool with optional paging where supported.

### `info`
Return function metadata and prototype.

### `create`
Create a new entity using the provided parameters.
Defines a new function at `addr`.

### `delete`
Remove the specified item.
Removes a function definition (undefines it).

### `set_flags`
Set function flags.
Sets function flags (e.g. `FUNC_NORET`, `FUNC_LIB`).

### `set_name`
Set function name.
Renames a function (alias for `modify.rename`).

### `add_comment`
Add a function comment.
Adds a function-level comment.

## Strategy
If `code.decompile` fails, check if the function is correctly defined. If not, use `create` to fix the ranges.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
