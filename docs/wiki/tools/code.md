# CODE Tool Manual

## What It Does
Perform code analysis, decompilation, and graph traversal.

## Actions
- `decompile`: Return Hex-Rays pseudocode for a function.
- `disasm`: Return disassembly for a function/range.
- `xrefs_to`: List references to a target address.
- `xrefs_from`: List outgoing references from an address/function.
- `xrefs_to_field`: Find references to a named structure field.
- `callees`: List functions called by a function.
- `callers`: List functions that call a function.
- `blocks`: Return basic block information.
- `analyze`: Return compact multi-signal function analysis.
- `callgraph`: Build callgraph neighborhood with depth limits.
- `export`: Export code-centric analysis data.
- `find_paths`: Search paths between addresses/functions.
- `strings_in_func`: List strings referenced by a function.
- `diff_functions`: Diff two functions structurally/semantically.

## Key Parameters
- `action` (required): Operation selector.
- `addrs` (default `None`): Comma-separated addresses or address list, action-dependent.
- `addr` (default `None`): Target address or function start (hex string).
- `max_items` (default `1000`): Maximum returned items.
- `max_depth` (default `5`): Maximum graph/path depth.
- `format` (default `'json'`): Output/input format (`json`, `plain`, `md`, etc. as supported).
- `field_name` (default `None`): Structure field name for field-reference queries.
- `target` (default `None`): Target address/symbol for resolve/xref/path actions.

## Examples (JSON call snippets)
```json
{
  "tool": "code",
  "args": {
    "action": "decompile",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "code",
  "args": {
    "action": "callgraph",
    "addr": "0x401000",
    "max_depth": 3,
    "max_items": 200
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addrs or addr parameter required`
- `FUNCTION_NOT_FOUND`: `No function at {hex_ea(ea)}`
- `INVALID_ARGS`: `field_name required`
- `IDA_ERROR`: `Error searching for field: {str(e)}`
- `INVALID_ARGS`: `target required`
- `FUNCTION_NOT_FOUND`: `No function at {hex(ea)}`
- `INVALID_ARGS`: `diff_functions requires exactly 2 addresses`
- `IDA_ERROR`: `Decompilation failed: {e}`
