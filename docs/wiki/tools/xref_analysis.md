# xref_analysis

Analyze cross-reference graphs: call chains, hub/leaf detection, dominators, influence, and dead code.

## Actions
- `call_chain` — find call chain between `source` and `target`; optional `depth`.
- `common_callers` — find functions that call all addresses in `addrs`.
- `common_callees` — find functions called by all addresses in `addrs`.
- `hub_functions` — identify functions with highest in/out degree; optional `count`.
- `leaf_functions` — identify functions with no outgoing calls; optional `count`.
- `recursive` — find recursive functions (direct or mutual recursion).
- `dominator` — compute dominator tree rooted at `address`.
- `influence` — compute influence set (transitive callees) of `address`; optional `depth`.
- `dead_functions` — find unreferenced/dead functions.
- `build_global_graph` — build and cache the full call graph for the binary.

## Examples
```json
{"name": "xref_analysis", "arguments": {"action": "hub_functions", "count": 10}}
```
```json
{"name": "xref_analysis", "arguments": {"action": "call_chain", "source": "0x401000", "target": "0x405000", "depth": 5}}
```

## Notes
- `build_global_graph` is expensive on large binaries; results are cached for subsequent queries.
- `hub_functions` is useful for identifying dispatch/main-loop functions.
- Alias: `plugins` → `misc`, `xfer_analysis` → `xref_analysis`.
