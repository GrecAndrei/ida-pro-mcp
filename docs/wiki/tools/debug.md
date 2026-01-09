# DEBUG Tool Manual

Control the IDA debugger and process state.

## Actions
### Supported Actions
- start
- stop
- continue
- step_into
- step_over
- run_to
- run_until
- breakpoints
- add_bp
- del_bp
- enable_bp
- regs
- set_reg
- threads
- modules
- callstack
- read_mem
- write_mem


### `stop`
Stop the active debugger session.

### `continue`
Continue debugger execution.

### `step_over`
Step over the next instruction.

### `run_to`
Run until the specified address.

### `add_bp`
Add a breakpoint.

### `del_bp`
Delete a breakpoint.

### `enable_bp`
Enable or disable a breakpoint.

### `threads`
List debugger threads.

### `modules`
List loaded debugger modules.

### `callstack`
Get the current call stack.

### `read_mem`
Read process memory via the debugger.

### `write_mem`
Write process memory via the debugger.

### `start`
Start the debugger for the current target.
Launches the process. Ensure your debugger backend (WinDbg, Local Windows, GDB) is configured in the IDB first.

### `regs`
Read register values.
Returns all general-purpose registers for the current thread.
*   **Optional Args**: `tid` (Thread ID)

### `set_reg`
Set a register value.
Modifies a register value.
*   **Args**: `reg` (str), `value` (int/str)

### `step_into` / `step_over`
Step into the next instruction.
Executes one instruction. The tool returns immediately; use `regs` to see the new state.

### `breakpoints`
List breakpoints.
Lists all active software and hardware breakpoints.

### `run_until`
Run until a condition or address is hit.
Autopilot debugging. Steps automatically until a condition is met.
*   **Args**: `addr` (Target IP) or `condition` (Python expression like `cpu.rax == 5`).
*   **Advantage**: Bypass network latency by running the stepping loop locally in IDA.

## Best Practices
1.  Always call `regs` after a step or `continue` to sync your internal state.
2.  Use `modules` to find the base address of DLLs if you are debugging malware.
3.  Check `threads` if the process seems hung; you might be in a background thread.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
