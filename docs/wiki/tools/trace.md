# trace

Manages IDA's execution trace buffer for recording and replaying instruction traces.

## Actions
- `get` — retrieve trace entries; params: `count` (optional), `offset` (optional)
- `clear` — clear the trace buffer
- `set_options` — configure trace options; params: `options` (dict)

## Examples
```json
{"name": "trace", "arguments": {"action": "get", "count": 50}}
```
```json
{"name": "trace", "arguments": {"action": "set_options", "options": {"trace_insn": true, "trace_func": true}}}
```

## Notes
- Trace must be enabled via `set_options` before debugging to capture data.
- `get` supports pagination with `offset`/`count`.
