# graph

Generates call graphs, control flow graphs, and cross-reference graphs in multiple output formats.

## Actions
- `callgraph` — generate call graph; params: `address` (optional root), `depth`
- `cfg` — generate control flow graph; params: `address`
- `xref_graph` — generate cross-reference graph; params: `address`, `depth`, `direction`

## Examples
```json
{"name": "graph", "arguments": {"action": "cfg", "address": "0x401000"}}
```
```json
{"name": "graph", "arguments": {"action": "callgraph", "address": "0x401000", "depth": 3}}
```

## Notes
- Outputs JSON, DOT, or Mermaid format (specify via `format` param).
- `callgraph` without an address generates the full binary call graph.
- `xref_graph` supports `direction`: "to", "from", or "both".
