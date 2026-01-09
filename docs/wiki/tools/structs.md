# STRUCTS Tool Manual

Automatic structure recovery and management.

## Actions
### Supported Actions
- recover
- analyze_usage
- list
- create
- add_member
- apply
- reconstruct_vtable


### `analyze_usage`
Analyze struct usage across functions.

### `list`
List available items for this tool with optional paging where supported.

### `apply`
Apply a struct or symbols at an address.

### `recover`
Recover struct definitions from usage.
Heuristic analysis of a function to find potential structures. 
*   **Best for**: Functions that take an `a1` pointer and access `a1 + 0x10`, `a1 + 0x18`, etc.

### `add_member`
Add a member to a struct.
Adds a field to an existing struct. 
*   **Args**: `name` (struct name), `member_name`, `offset`, `member_type`.
*   **Pro Tip**: Use this to incrementally build a struct as you reverse engineer it.

### `create`
Create a new entity using the provided parameters.
Creates a new struct from a full C declaration string.

### `reconstruct_vtable`
Reconstruct a vtable for a class.
Heuristic reconstruction of C++ VTables.
*   **Args**: `addr` (Address of the VTable).
*   **Logic**: Scans for a contiguous block of function pointers and creates a corresponding VTable struct.

## Strategy
1.  Run `recover` on a function.
2.  Create the struct with `create`.
3.  Apply it to the function argument with `types.apply`.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
