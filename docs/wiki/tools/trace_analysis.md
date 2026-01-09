# TRACE_ANALYSIS Tool Manual

Post-mortem processing of execution traces.

## Actions
### Supported Actions
- import_trace
- analyze_coverage
- find_loops
- extract_api_calls
- basic_blocks_hit


### `import_trace`
Import execution trace data.
Loads a trace file from disk.

### `analyze_coverage`
Analyze trace coverage.
Calculates coverage percentage based on a trace.

### `find_loops`
Find loops in trace data.
Detects high-frequency instruction patterns (hot loops).

### `extract_api_calls`
Extract API calls from trace data.
Extracts the sequence of library/API calls made during the trace.

### `basic_blocks_hit`
Report basic blocks hit by trace.
Returns a per-function summary of basic block coverage.
*   **Args**: `addr` (optional). Defaults to the binary entry point.

## Strategy
Use `extract_api_calls` to understand the high-level behavior of a trace without reading every instruction.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
