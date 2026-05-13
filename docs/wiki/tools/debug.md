# debug

Controls the IDA debugger: breakpoints, stepping, registers, threads, and memory maps.

## Actions
- `start` — start debugging; params: `args` (optional command-line args)
- `stop` — terminate debuggee
- `continue` — resume execution
- `step_into` — single step into calls
- `step_over` — step over calls
- `run_to` — run to address; params: `address`
- `run_until` — run until condition; params: `condition`
- `breakpoints` — list all breakpoints
- `add_bp` — add breakpoint; params: `address`, `condition` (optional)
- `del_bp` — delete breakpoint; params: `address`
- `regs` — dump registers
- `set_reg` — set register value; params: `reg`, `value`
- `snapshot_regs` — save register snapshot
- `reg_diff` — diff current regs against last snapshot
- `threads` — list threads
- `modules` — list loaded modules
- `mem_map` — show memory map
- `callstack` — get current call stack
- `bp_context` — queries blackboard for current PC + containing function context

## Examples
```json
{"name": "debug", "arguments": {"action": "start"}}
```
```json
{"name": "debug", "arguments": {"action": "add_bp", "address": "0x401000", "condition": "eax==0"}}
```

## Notes
- `bp_context` is injected automatically on suspend/step events.
- `reg_diff` compares against the last `snapshot_regs` call.
- Debugger must be active (`start`) before stepping or reading state.
