# CLASSIFY Tool Manual

## What It Does
Classify functions and binary by purpose using API call patterns and structural analysis.

## Actions
- `function`: Classify a single function by behavior patterns.
- `binary`: Classify the binary at a high level.
- `all_functions`: Classify many functions and return grouped results.
- `library_code`: Identify likely library/runtime functions.
- `wrappers`: Detect thin wrapper/thunk-style functions.
- `callbacks`: Identify callback-like functions.
- `initializers`: Find init/setup routines.
- `error_handlers`: Find error-handling oriented functions.
- `hot_functions`: Rank likely hot/important functions.
- `orphans`: Find isolated or weakly-connected functions.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.
- `category` (default `None`): Classification category filter.

## Examples (JSON call snippets)
```json
{
  "tool": "classify",
  "args": {
    "action": "function",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "classify",
  "args": {
    "action": "all_functions",
    "limit": 100,
    "category": "wrappers"
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required for 'function' action`
- `INVALID_ARGS`: `Unknown action: {action}`
