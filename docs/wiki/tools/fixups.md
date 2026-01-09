# FIXUPS Tool Manual

Management of binary relocations and fixups.

## Actions
### Supported Actions
- list
- get
- add
- delete


### `list`
List available items for this tool with optional paging where supported.
Lists all relocations in the current binary.

### `get`
Retrieve a detailed view for the requested item or address.
Retrieves detailed fixup info for a specific address.

### `add`
Create a new item using the provided parameters.
Manually adds a fixup (useful for custom loaders or manually mapped DLLs).

### `delete`
Remove the specified item.
Removes an existing fixup.

## Strategy
Check `list` when logic seems to reference absolute addresses that don't make sense; they might be relocation targets.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
