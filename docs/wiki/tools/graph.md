# GRAPH Tool Manual

## What It Does
Builds call graphs, CFGs, and xref graphs with JSON, DOT, or Mermaid output for quick visualization and traversal.

## Actions
- `callgraph`: Traverse callee graph from a function start.
- `cfg`: Emit per-basic-block control-flow graph for one function.
- `xref_graph`: Traverse callers/callees around an address by direction.

## Key Parameters
- `action`: One of `callgraph|cfg|xref_graph`.
- `addr`: Required starting point.
- `depth`: Traversal depth limit.
- `direction`: Used by `xref_graph` (`down|up|both`).
- `format`: `json`, `dot`, or `mermaid`.

## Examples
```python
graph(action="callgraph", addr="0x401000", depth=2, format="mermaid")
graph(action="cfg", addr="0x401000", format="dot")
graph(action="xref_graph", addr="0x401000", direction="both", depth=3, format="json")
```

## Failure Modes
- Missing/invalid `addr`.
- Address not in function for function-oriented actions.
- Large graph growth with high `depth`.
- Unknown output `format`/`action` errors.
