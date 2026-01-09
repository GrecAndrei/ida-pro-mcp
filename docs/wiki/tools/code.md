# CODE Tool Manual

High-level analysis of code, flow, and decompilation.

## Actions
### Supported Actions
- decompile
- disasm
- xrefs_to
- xrefs_from
- xrefs_to_field
- callees
- callers
- blocks
- analyze
- callgraph
- export
- find_paths
- strings_in_func


### `disasm`
Return disassembly text for an address range.

### `xrefs_to`
List cross-references to the target address.

### `xrefs_from`
List cross-references originating from the target address.

### `xrefs_to_field`
Find references to a specific struct field.

### `callers`
List functions that call the target function.

### `blocks`
Return basic blocks for the target function.

### `export`
Export tool output in the requested format.

### `find_paths`
Find callgraph paths between two functions.

### `strings_in_func`
List string references used by a function.

### `decompile`
Return Hex-Rays pseudocode for a function.
Returns Hex-Rays pseudocode. Handles failures gracefully.
*   **Args**: `addrs` (str/list)

### `analyze`
Run a comprehensive function analysis bundle.
The "Master Triage" action. Combines decompilation, xrefs, and strings into one response.
*   **Best for**: First-look at a function.

### `callgraph`
Build a callgraph around the target function.
Generates a recursive caller/callee tree.
*   **Args**: `addrs`, `max_depth` (default 5).

### `callees` / `callers`
List functions called by the target function.
One-level jump to find what a function calls or who calls it.

## Edge Cases
*   **Thunks**: If a function is a simple jump (thunk), `decompile` might return very little. Use `idb.meta` to check segment flags.
*   **Non-standard stacks**: If decompilation fails due to "positive sp value", use `modify.comment` to mark the location for manual fixup.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
