# GRAPH Tool Manual

Export control flow and call graphs for visualization.

## Actions
### Supported Actions
- callgraph
- cfg
- xref_graph


### `xref_graph`
Return a cross-reference graph for a symbol.

### `cfg` (Control Flow Graph)
Return a control flow graph for a function.
Generates the basic block graph for a specific function.
*   **Args**: `addr`, `format` (json|mermaid).
*   **Mermaid**: Returns code that can be rendered as a flowchart.

### `callgraph`
Build a callgraph around the target function.
Traces function calls starting from an address.
*   **Args**: `addr`, `depth`, `direction` (up|down|both).

## Optimization for LLMs
Always prefer `format='mermaid'` when you need to reason about logic flow. It provides a topological map that is easier to parse than raw address lists.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
