# batch

Executes multiple tool calls in a single request with dependency resolution, piping, conditional execution, and dry-run support.

## Actions
- `run` — execute a list of tool calls. Params: `calls` (array of call objects or shorthand strings)

## Examples
```json
{"name": "batch", "arguments": {"calls": [
  "idb:meta",
  {"name": "data", "action": "imports"},
  {"name": "search", "action": "strings", "pattern": "http"}
]}}
```
```json
{"name": "batch", "arguments": {"calls": [
  {"name": "data", "arguments": {"action": "functions", "count": 10}},
  {"name": "code", "arguments": {"action": "disasm", "address": "0x401000"}}
]}}
```

## Notes
- Shorthand formats supported: `"tool:action"`, `{"name":"tool","action":"x"}`, `{"tool":"tool","action":"x"}`.
- Use batch when the next calls are deterministic to reduce round trips.
- Supports `dry_run: true` to preview execution plan without side effects.
