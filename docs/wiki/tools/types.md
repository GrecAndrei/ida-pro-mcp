# TYPES Tool Manual

Manage C-style types, prototypes, and local variables.

## Actions
### Supported Actions
- list
- get
- set_prototype
- parse_decl
- declare
- apply
- search_structs
- infer
- read_struct
- import_header


### `set_prototype`
Set function prototype for a function.

### `parse_decl`
Parse and return a type declaration.

### `declare`
Declare a new type in the local type library.

### `search_structs`
Search structure names and fields for a query.

### `infer`
Infer types from usage.

### `read_struct`
Read a struct at a memory address.

### `apply`
Apply a struct or symbols at an address.
Applies a type to an address or local variable.
*   **Args**: `addr`, `decl`, `name` (for local), `kind` (function|global|local|stack).
*   **Strategy**: Essential for fixing up decompilation. If a variable is wrongly typed as `int`, use `apply` with `kind='local'` to fix it.

### `get`
Retrieve a detailed view for the requested item or address.
Retrieves the definition of a named type (struct/enum).

### `list`
List available items for this tool with optional paging where supported.
Lists all types in the Type Library (TIL). Use `query` to filter and `offset`/`count` for pagination.

### `import_header`
Import types from a C header.
Bulk imports struct/enum definitions from a C header string.
*   **Args**: `decl` (Full C header content).
*   **Best for**: Syncing knowledge from source code or documentation into IDA.

## IDA 9.2 Note
Type ordinal mapping has changed in IDA 9. This tool uses the modern `get_ordinal_qty` API for consistent results.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
