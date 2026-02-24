# BATCH Tool Manual

## What It Does
Execute multiple tool calls in a single request.

## Actions
- Execute multiple tool calls in order and return per-call results.

## Key Parameters
- `calls` (required): Batch call list: each item includes `tool`, `action`, and params.
- `stop_on_error` (default `False`): Stop the batch after first failing call.

## Examples (JSON call snippets)
```json
{
  "tool": "batch",
  "args": {
    "calls": [
      {
        "tool": "code",
        "action": "decompile",
        "addr": "0x401000"
      },
      {
        "tool": "data",
        "action": "strings",
        "count": 20
      }
    ]
  }
}
```
```json
{
  "tool": "batch",
  "args": {
    "calls": [
      {
        "tool": "compare",
        "action": "functions",
        "addr": "0x401000",
        "addr2": "0x402000"
      }
    ],
    "stop_on_error": true
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `calls list is required and cannot be empty`
- `INVALID_ARGS`: `Maximum 20 calls per batch`
- `INVALID_ARGS`: `Call {i}: expected dict, got {type(call).__name__}`
- `INVALID_ARGS`: `Call {i}: 'tool' key is required`
- `TOOL_NOT_FOUND`: `Call {i}: tool '{tool_name}' not found`
