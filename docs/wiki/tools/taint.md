# TAINT Tool Manual

## What It Does
Performs static, heuristic data-flow triage for arguments, return usage, dangerous sinks, and nearby instruction history.

## Actions
- `find_arg_usage`: Uses decompiler locals/ctree to find uses of argument `arg_num` in a function.
- `trace_return`: Finds call sites and immediate post-call instructions that consume a function return value.
- `find_sinks`: Walks calls from a start address (BFS by `depth`) and flags dangerous API patterns.
- `data_flow`: Summarizes prototype, args, callees, and sink hits for one function.
- `backward_trace`: Linear instruction walk backward from an address.
- `slice`: Heuristic decompiler-text slice from one argument to sink-like lines.

## Key Parameters
- `action`: One of `find_arg_usage|trace_return|find_sinks|data_flow|backward_trace|slice`.
- `addr`: Required for every action.
- `arg_num`: 0-based argument index for `find_arg_usage` and `slice`.
- `depth`: Search depth for `find_sinks` and instruction budget multiplier for `backward_trace`.
- `max_hits`: Caps returned lines/matches.

## Examples
```json
{"name":"taint","arguments":{"action":"find_arg_usage","addr":"0x401000","arg_num":1,"max_hits":25}}
```

```json
{"name":"taint","arguments":{"action":"find_sinks","addr":"0x401000","depth":4,"max_hits":50}}
```

```json
{"name":"taint","arguments":{"action":"slice","addr":"0x401000","arg_num":0}}
```

## Failure Modes
- Missing or invalid `addr`; non-function `addr` where function context is required.
- `arg_num` out of range for function arguments.
- Hex-Rays unavailable or decompilation fails (`find_arg_usage`, `slice`, parts of `data_flow`).
- Unknown action returns invalid-args error.
- Output is heuristic; sink matches are name-based and should be manually confirmed.
