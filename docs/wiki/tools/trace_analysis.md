# trace_analysis

Imports and analyzes execution traces for loop detection, API extraction, and anti-analysis identification.

## Actions
- `import_trace` — Import an execution trace file; params: `path`, `format`
- `analyze_coverage` — Compute coverage statistics from imported trace; params: `trace_id`
- `find_loops` — Detect hot loops and iteration counts in trace; params: `trace_id`, `min_iterations`
- `extract_api_calls` — Extract ordered API call sequence from trace; params: `trace_id`, `filter`
- `basic_blocks_hit` — List basic blocks executed in trace; params: `trace_id`, `address`
- `execution_timeline_graph` — Generate temporal execution flow graph; params: `trace_id`
- `cross_run_diff` — Diff two traces to find behavioral divergence; params: `trace_a`, `trace_b`
- `coverage_debug_plan` — Suggest debug breakpoints to increase coverage; params: `trace_id`
- `anti_analysis_detect` — Identify anti-debug/anti-VM checks in trace; params: `trace_id`

## Examples
```json
{"name": "trace_analysis", "arguments": {"action": "import_trace", "path": "/traces/run1.trace"}}
```
```json
{"name": "trace_analysis", "arguments": {"action": "find_loops", "trace_id": "run1", "min_iterations": 100}}
```

## Notes
- Import a trace before using analysis actions; most require a valid `trace_id`.
- `cross_run_diff` is effective for identifying input-dependent behavior (e.g., sandbox evasion paths).
- `anti_analysis_detect` flags common techniques: timing checks, CPUID, IsDebuggerPresent, VM artifacts.
