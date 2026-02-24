# CTREE Tool Manual

## What It Does
Hex-Rays AST (CTree) analysis utilities.

## Actions
- `get`: Return the decompiler CTree for a function.
- `traverse`: Traverse CTree nodes with bounded depth.
- `find_calls`: Find call expressions in CTree.
- `find_vars`: Find variable usage in CTree.
- `find_strings`: Find string usage in CTree.
- `find_conditions`: Find conditional expressions in CTree.
- `get_logic_flow`: Summarize high-level logic/control flow from CTree.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (required): Target address or function start (hex string).
- `query` (default `None`): Search query string or query payload.
- `depth` (default `10`): Traversal/path depth bound.

## Examples (JSON call snippets)
```json
{
  "tool": "ctree",
  "args": {
    "action": "get",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "ctree",
  "args": {
    "action": "find_calls",
    "addr": "0x401000",
    "query": "CreateFile",
    "depth": 12
  }
}
```

## Failure Modes
- `IDA_ERROR`: `Decompiler required for CTree`
- `IDA_ERROR`: `Decompilation failed`
- `INVALID_ARGS`: `Unknown action: {action}`
