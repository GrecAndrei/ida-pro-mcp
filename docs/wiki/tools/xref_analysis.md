# XREF_ANALYSIS Tool Manual

## What It Does
Performs callgraph-centric analysis: pathing between functions, shared caller/callee sets, recursion/influence metrics, dependency graph extraction, and dead-function discovery.

## Actions
- `call_chain`: BFS shortest-path chain search from `addr` to `addr2`.
- `common_callers`: Intersection of callers across 2+ target functions.
- `common_callees`: Intersection of callees across 2+ target functions.
- `hub_functions`: Functions with both many callers and callees (score-ranked).
- `leaf_functions`: Functions with no outgoing calls.
- `recursive`: Direct and mutual recursion detection.
- `dominator`: Approximate entry-reachability dominator candidates.
- `influence`: Reachability fan-out from one function.
- `dependency_graph`: Node/edge graph from one or more seeds.
- `dead_functions`: Non-entry functions with no callers.

## Key Parameters
- `action`: One of the actions above.
- `addr`, `addr2`: Primary/secondary function addresses.
- `addrs`: Comma-separated function addresses for multi-target actions.
- `depth`: Traversal depth limit.
- `limit`: Max output rows/nodes/edges.

## Examples
```json
{"name":"xref_analysis","arguments":{"action":"call_chain","addr":"0x401000","addr2":"0x405000","depth":8}}
```

```json
{"name":"xref_analysis","arguments":{"action":"common_callees","addrs":"0x401000,0x401200,0x401500","limit":30}}
```

```json
{"name":"xref_analysis","arguments":{"action":"dependency_graph","addrs":"0x401000,0x402000","depth":3,"limit":200}}
```

## Failure Modes
- `call_chain` requires both `addr` and `addr2` as function addresses.
- `common_callers`/`common_callees` require at least two targets.
- `influence` requires `addr`.
- `dependency_graph` requires at least one target.
- Invalid/non-function addresses fail validation.
- `dominator` is heuristic (approximate), not strict graph-theory dominator output.
