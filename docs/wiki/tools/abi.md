# ABI Tool Manual

## What It Does
Analyze ABI and calling conventions for functions.

## Actions
- `detect`: Detect calling convention of a function (cdecl, stdcall, fastcall, thiscall, etc.)
- `stack_args`: Analyze stack-passed arguments for a function.
- `reg_args`: Analyze register-passed arguments.
- `return_type`: Infer return type and register from function behavior.
- `varargs`: Detect variadic function patterns.
- `struct_return`: Detect functions returning structs (hidden pointer arg).
- `tail_calls`: Detect tail call optimization.
- `prologue`: Analyze function prologue pattern.
- `epilogue`: Analyze function epilogue pattern.
- `abi_violations`: Find calling convention violations/mismatches.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.

## Examples (JSON call snippets)
```json
{
  "tool": "abi",
  "args": {
    "action": "detect",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "abi",
  "args": {
    "action": "abi_violations",
    "limit": 100
  }
}
```

## Failure Modes
- `FUNCTION_NOT_FOUND`: `No function at or containing {hex(ea)}`
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `Unknown action: {action}`
