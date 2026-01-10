# CTREE Tool Manual

Access the Hex-Rays Abstract Syntax Tree (AST) for deep logic analysis.

## Actions
### Supported Actions
- get
- traverse
- find_calls
- find_vars
- find_strings
- find_conditions
- get_logic_flow


### `traverse`
Traverse the ctree AST for a function.
*   **Args**: `addr`, `depth` (default 10), optional `query` filter.
*   **Output**: Depth-tagged nodes for fast structural scans.

### `find_strings`
Find string literals in the decompiled AST.
*   **Output**: Direct string literals plus object references that resolve to string data.

### `get_logic_flow`
Summarize the logic flow from the decompiled AST.

### `get`
Retrieve a detailed view for the requested item or address.
Dumps all AST nodes for a function.
*   **Context**: Includes the C-like text for each expression node.

### `find_calls`
Find call expressions in the decompiled AST.
Surgically extracts all function calls from the pseudocode, including arguments.
*   **Strategy**: Use this to find where a specific API (like `memcpy`) is used without reading 1000 lines of code.
*   **Args**: `query` filters call text/callee/args.

### `find_conditions`
Extracts `if`, `while`, and `for` logic.
*   **Strategy**: Best for finding decision points or "magic constant" checks.

### `find_vars`
Find variable usage in the decompiled AST.
Lists all local variables and their types, plus usage sites.

## Advanced Usage
When you need to know *exactly* how a variable is transformed, use `get` and look for the `ea` corresponding to the assignment.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
