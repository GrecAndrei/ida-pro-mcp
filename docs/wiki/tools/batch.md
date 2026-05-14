# batch

Execute multiple tool calls in a single request to reduce round trips. Use for deterministic multi-step flows where all calls are known in advance.

## Actions
- Pass a `calls` array containing one or more tool invocations.

## Call Formats

Three formats are supported per entry in `calls`:

1. **Shorthand string** — `"tool:action"`
2. **Inline object** — `{"name": "tool", "action": "action", ...args}`
3. **Full MCP form** — `{"name": "tool", "arguments": {"action": "action", ...args}}`

## Examples
```json
{"name": "batch", "arguments": {"calls": ["idb:meta", "data:imports", "data:strings"]}}
```
```json
{"name": "batch", "arguments": {"calls": [
  "idb:meta",
  {"name": "data", "action": "functions", "count": 20},
  {"name": "search", "arguments": {"action": "strings", "pattern": "http"}}
]}}
```
```json
{"name": "batch", "arguments": {"calls": [
  {"name": "code", "arguments": {"action": "disasm", "address": "0x401000"}},
  {"name": "code", "arguments": {"action": "decompile", "address": "0x401000"}}
]}}
```

## Notes
- Returns compact per-call result rows plus a summary.
- All calls execute sequentially in order; a failure in one call does not abort subsequent calls.
- Use batch when the next steps are deterministic and do not depend on intermediate results.
- Shorthand `"tool:action"` is the most token-efficient format for simple parameterless calls.
- Batch responses respect the same `_response_mode` and compaction settings as individual calls.
