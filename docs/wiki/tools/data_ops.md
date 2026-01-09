# DATA_OPS Tool Manual

Data item definition and array management.

## Actions
### Supported Actions
- make_data
- make_array
- make_string
- undefine
- make_code


### `make_data`
Define data at an address with the specified size/type.
Defines a data item (byte, word, dword, qword) at `addr`.

### `make_array`
Define an array at an address.
Creates an array of specific type and count.

### `make_string`
Define a string at an address.
Defines a string literal (auto-detects encoding).

### `undefine`
Undefine code/data at an address.
Removes data/code definitions at an address.

### `make_code`
Define code at an address.
Converts data at an address into instructions.

## Strategy
If `code.disasm` shows "db" (defined bytes) instead of instructions, use `make_code` to force disassembly.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
