# XREF_ANALYSIS Tool Manual

## What It Does
Performs callgraph-centric analysis with compact outputs by default. It finds shortest call paths, shared callers/callees, hub and leaf functions, recursion (SCC-based), entry-reachability dominators, influence reachability, dependency subgraphs, and dead-function candidates.

## Actions
- `call_chain`: shortest call path(s) from `addr` to `addr2`.
- `common_callers`: functions that call all target functions.
- `common_callees`: functions called by all target functions.
- `hub_functions`: high-centrality functions ranked by in/out degree.
- `leaf_functions`: functions with no outgoing calls.
- `recursive`: direct and mutual recursion using SCC analysis.
- `dominator`: bottleneck functions in the entry-reachable callgraph.
- `influence`: forward/backward/bidirectional reachability from `addr`.
- `dependency_graph`: compact callgraph around one or more seeds.
- `dead_functions`: unreachable functions with no internal callers or external refs.

## Key Parameters
- `action`: one of the actions above.
- `addr`, `addr2`: primary/secondary function addresses.
- `addrs`: comma-separated addresses for multi-target actions.
- `depth`: traversal depth limit (default `10`, max `64`).
- `limit`: page size (default `50`, max `500`).
- `offset`: pagination offset.
- `include_items`: include structured objects in `items` (off by default).
- `direction`: `forward|backward|both` (for `influence` and `dependency_graph`).

## Output Shape
- Compact by default:
  - `matches`: newline-delimited text rows.
  - `count`, `total`, `offset`, `truncated`: pagination metadata.
- Action-specific aliases are preserved (`chains`, `hubs`, `dead`, etc.).
- Set `include_items=true` for structured arrays.

## Examples
```json
{"name":"xref_analysis","arguments":{"action":"call_chain","addr":"0x401000","addr2":"0x405000","depth":8,"limit":20}}
```

```json
{"name":"xref_analysis","arguments":{"action":"influence","addr":"0x401000","direction":"both","depth":4,"limit":40}}
```

```json
{"name":"xref_analysis","arguments":{"action":"dependency_graph","addrs":"0x401000,0x402000","direction":"both","depth":3,"limit":200}}
```

## Failure Modes
- `call_chain` requires both `addr` and `addr2` and both must resolve to functions.
- `common_callers`/`common_callees` require at least two target functions.
- `influence` requires `addr`.
- `dependency_graph` requires at least one target function.
- Invalid addresses or non-function targets fail validation.
