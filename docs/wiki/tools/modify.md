# MODIFY Tool Manual

Database annotations and patching.

## Actions
### Supported Actions
- rename
- comment
- set_type
- patch_asm


### `set_type`
Apply a type to the specified address or symbol.

### `rename`
Rename the specified symbol or address.
Renames a function, label, or data item.
*   **Best for**: Recording your analysis. "Always rename sub_XXXX as soon as you know what it does."

### `comment`
Create or update a comment at the specified address.
Adds a comment. Supports regular, repeatable, anterior (above), and posterior (below).

### `patch_asm`
Assembles and patches instructions.
*   **Args**: `addr`, `asm` (e.g. `mov eax, 1`).
*   **Best for**: Bypassing checks or modifying logic.

## Standard
For batch renames or many comments, always use the `bulk` tool. it is significantly faster and uses less context.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
