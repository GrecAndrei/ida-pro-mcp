# EMULATE Tool Manual

## What It Does
Offers static tracing and light execution helpers: control-flow walk, debugger `Appcall`, decryption-call heuristics, and expression/value evaluation.

## Actions
- `static_trace`: BFS-style static walk from an address with optional call following.
- `appcall`: Invoke function via debugger Appcall API.
- `decrypt_strings`: Heuristically find string arguments near calls to a target routine.
- `eval_expr`: Evaluate IDC expression or read typed values at an address.

## Key Parameters
- `action`: One of `static_trace|appcall|decrypt_strings|eval_expr`.
- `addr`: Required for `static_trace` and `decrypt_strings`; optional fallback target for `appcall`; optional for `eval_expr`.
- `func_name`: Preferred named target for `appcall`.
- `args`: Positional argument list for `appcall`.
- `max_steps`, `follow_calls`, `max_depth`, `include_blocks`: `static_trace` behavior controls.
- `expr`: Required for expression mode in `eval_expr` when `addr` is not provided.

## Examples
```python
emulate(action="static_trace", addr="0x401000", max_steps=300, follow_calls=True, max_depth=2)
emulate(action="appcall", func_name="decrypt_buffer", args=[0x500000, 64])
emulate(action="decrypt_strings", addr="0x402000")
emulate(action="eval_expr", expr="get_wide_dword(0x401000)")
emulate(action="eval_expr", addr="0x401000")
```

## Failure Modes
- Missing `addr`/`func_name`/`expr` where required.
- `appcall` unavailable in current IDA build.
- Debugger not running for `appcall`.
- Function lookup failure for `appcall` target.
- Evaluation/decode errors surfaced as IDA error payloads.
