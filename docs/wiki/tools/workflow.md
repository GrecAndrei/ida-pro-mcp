# Workflow

| Operation | Purpose |
| --- | --- |
| `ida_batch(calls=[...])` | Execute several deterministic analysis operations sequentially in one request. |

Each call is `{name: "<ida_* operation>", arguments: {...}}`; omit arguments
for parameterless calls. `continue_on_error: true` proceeds with later calls
after a failure. Use it for fixed pipelines (e.g. overview → find →
decompile) that don't need intermediate decisions.

## Example

```json
{"calls": [
  {"name": "ida_overview"},
  {"name": "ida_find", "arguments": {"query": "main"}},
  {"name": "ida_decompile", "arguments": {"address": "main"}}
]}
```
