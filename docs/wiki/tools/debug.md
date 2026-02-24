# DEBUG Tool Manual

## What It Does
Debugger control: process state, breakpoints, registers, memory.

## Actions
- `start`: Start debugger/process.
- `stop`: Stop debugger/process.
- `continue`: Resume execution.
- `step_into`: Single-step into.
- `step_over`: Single-step over.
- `run_to`: Run until an address breakpoint.
- `run_until`: Run until condition/address trigger.
- `breakpoints`: List breakpoints.
- `add_bp`: Add breakpoint (optional condition).
- `del_bp`: Delete breakpoint.
- `enable_bp`: Enable/disable breakpoint.
- `regs`: Read register state.
- `set_reg`: Write a register value.
- `threads`: List debugger threads.
- `modules`: List loaded modules.
- `callstack`: Get current call stack.
- `read_mem`: Read process memory.
- `write_mem`: Write process memory.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `condition` (default `None`): Breakpoint/run condition expression.
- `reg` (default `None`): Register name for register operations.
- `value` (default `None`): Generic value parameter (setting, conversion, register write).
- `size` (default `16`): Byte size / read length / data width, action-dependent.
- `data` (default `None`): Data payload for memory write operations.
- `enabled` (default `True`): Enable (`true`) or disable (`false`) a breakpoint.
- `tid` (default `None`): Debugger thread ID.

## Examples (JSON call snippets)
```json
{
  "tool": "debug",
  "args": {
    "action": "add_bp",
    "addr": "0x401000",
    "condition": "eax==0",
    "enabled": true
  }
}
```
```json
{
  "tool": "debug",
  "args": {
    "action": "read_mem",
    "addr": "0x404000",
    "size": 32
  }
}
```

## Failure Modes
- `IDA_ERROR`: `Failed to start debugger`
- `DEBUGGER_NOT_RUNNING`: `Debugger not running`
- `INVALID_ARGS`: `addr required`
- `IDA_ERROR`: `Condition error: {e}`
- `IDA_ERROR`: `Failed to add breakpoint`
- `IDA_ERROR`: `Failed to delete breakpoint`
- `IDA_ERROR`: `Failed to enable/disable breakpoint`
- `IDA_ERROR`: `No debugger info`
