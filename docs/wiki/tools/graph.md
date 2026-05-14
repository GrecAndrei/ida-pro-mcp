# graph

Generates call graphs, control flow graphs, and cross-reference graphs in multiple output formats.

## Actions
- `callgraph` — Generate call graph showing function call relationships; params: `address` (optional root), `depth`
- `cfg` — Generate control flow graph showing basic block flow; params: `address`
- `xref_graph` — Generate cross-reference graph; params: `address`, `depth`, `direction`
- `down` — Shortcut for xref graph in the "down" (callees/refs-from) direction; params: `address`, `depth`
- `up` — Shortcut for xref graph in the "up" (callers/refs-to) direction; params: `address`, `depth`
- `both` — Shortcut for xref graph in both directions; params: `address`, `depth`
- `json` — Output graph in JSON format; params: `address`, `type` (`callgraph`|`cfg`|`xref_graph`)
- `dot` — Output graph in Graphviz DOT format; params: `address`, `type`
- `mermaid` — Output graph in Mermaid diagram format; params: `address`, `type`

## Examples
```json
{"name": "graph", "arguments": {"action": "cfg", "address": "0x401000"}}
```
```json
{"name": "graph", "arguments": {"action": "callgraph", "address": "0x401000", "depth": 3}}
```
```json
{"name": "graph", "arguments": {"action": "up", "address": "0x401000", "depth": 2}}
```
```json
{"name": "graph", "arguments": {"action": "mermaid", "address": "0x401000", "type": "cfg"}}
```

## Notes
- `callgraph` without an address generates the full binary call graph (can be large).
- `cfg` shows basic block flow within a single function.
- `down`/`up`/`both` are convenience shortcuts for `xref_graph` with pre-set direction.
- `json`/`dot`/`mermaid` are output format variants — use these when you need a specific serialization rather than the default.
- For `xref_graph`, `direction` accepts: `"to"`, `"from"`, or `"both"`.
- Combine with `cfg_analysis` for deeper structural analysis of control flow patterns.
