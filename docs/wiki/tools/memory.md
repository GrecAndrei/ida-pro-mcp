# MEMORY Tool Manual

Raw memory I/O.

## Actions
### Supported Actions
- read
- write


### `read`
Read data or content from the specified source.
Reads raw bytes from an address.
*   **Args**: `addr`, `size`.
*   **Returns**: Space-separated hex string.

### `write`
Write data or content to the specified destination.
Writes hex data to the database.
*   **Args**: `addr`, `data` (hex string).
*   **Warning**: This modifies the IDB. Use `modify.patch_asm` for code modifications where possible.

## Use Case
Use `read` when you need to inspect raw data that IDA hasn't interpreted yet (e.g. unknown struct fields or shellcode).
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
