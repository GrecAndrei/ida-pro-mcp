# TRACE_ANALYSIS Tool Manual

## What It Does
Analyzes post-mortem execution traces from file input or inline `trace_data` addresses.

## Actions
- `import_trace`: Loads addresses from `trace_data` list or newline-separated file `path`.
- `analyze_coverage`: Computes hit vs total basic blocks over all functions.
- `find_loops`: Returns frequent addresses as hot spots (top 20, `hits > 5`).
- `extract_api_calls`: Collects called non-`sub_` target names from traced addresses.
- `basic_blocks_hit`: Per-function hit map of blocks (`addr` optional, defaults to entry-point function).

## Key Parameters
- `action`: `import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit`.
- `trace_data`: List of addresses (`"0x..."` or ints).
- `path`: Safe path to trace text file.
- `addr`: Target function for `basic_blocks_hit`.

## Examples
```json
{"name":"trace_analysis","arguments":{"action":"import_trace","path":"/tmp/trace.txt"}}
```

```json
{"name":"trace_analysis","arguments":{"action":"analyze_coverage","trace_data":["0x401000","0x401010","0x402000"]}}
```

```json
{"name":"trace_analysis","arguments":{"action":"basic_blocks_hit","addr":"0x401000","trace_data":["0x401000","0x40100A"]}}
```

## Failure Modes
- `import_trace` requires `path` or `trace_data`.
- Analysis actions require non-empty trace input (`No trace data`).
- Invalid/unsafe file paths are rejected.
- `basic_blocks_hit` fails if resolved `addr` is not a function.
- `find_loops` operates on unique-address sets from loader input; repeated-frequency detail can be reduced.
