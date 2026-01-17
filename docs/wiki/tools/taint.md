# TAINT Tool Manual

Static flow analysis and vulnerability triage.

## Actions
### Supported Actions
- find_arg_usage
- trace_return
- find_sinks
- data_flow
- backward_trace
- slice


### `trace_return`
Trace how a function return value is used.

### `data_flow`
Summarize input/output data flow for a function.
Returns prototype, args (if decompiler is available), callees, and local sink hits.

### `find_sinks`
Find dangerous sink calls reachable from an address.
Recursively searches callers to find paths to dangerous APIs.
*   **Args**: `addr`, `depth` (default 5), `max_hits`.
*   **Best for**: "How does user input reach `system()`?"

### `find_arg_usage`
Analyze how a function argument is used.
Identifies how a function argument is used in the decompiled code.
*   **Output**: Usage sites + pseudocode line hits.

### `backward_trace`
Trace instructions backward from an address.
A linear backward instruction trace.
*   **Best for**: Quick checks of which instructions set a specific register.

### `slice`
Heuristic argument-to-sink slice from decompiler output.
Heuristic argument-to-sink slice using decompiler output.

## Note on Accuracy
This tool performs **Static** analysis. For actual data flow during execution, use the `debug` tool.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
