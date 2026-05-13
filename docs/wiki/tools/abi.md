# abi

Detects and reports ABI-level calling convention details for functions.

## Actions
- `detect` — auto-detect calling convention; params: `address`
- `stack_args` — list stack-passed arguments; params: `address`
- `reg_args` — list register-passed arguments; params: `address`
- `return_type` — infer return type; params: `address`
- `varargs` — detect variadic argument usage; params: `address`
- `struct_return` — detect struct return (hidden pointer); params: `address`
- `tail_calls` — find tail call sites; params: `address`
- `prologue` — analyze function prologue; params: `address`
- `epilogue` — analyze function epilogue; params: `address`
- `violations` — find calling convention violations; params: `address` (optional, scans all if omitted)

## Examples
```json
{"name": "abi", "arguments": {"action": "detect", "address": "0x401000"}}
```
```json
{"name": "abi", "arguments": {"action": "violations"}}
```

## Notes
- All address params accept hex strings or integers.
- `violations` without an address scans the entire binary for ABI mismatches.
- Useful for identifying miscompiled or hand-written assembly functions.
