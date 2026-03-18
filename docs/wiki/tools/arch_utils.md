# ARCH_UTILS Tool Manual

## What It Does
Shared architecture-detection and instruction-pattern helpers used by multiple tools; this module is not directly callable as an MCP tool.
It now normalizes a broader firmware-focused architecture set, including comprehensive RISC-V naming variants (e.g. `risc-v`, `rv32*`, `rv64*`) plus embedded targets like Xtensa, TriCore, AVR, MSP430, C-SKY, ARC, Nios II, MicroBlaze, V850, RL78, H8, 8051/MCS-51, Z80, PIC24, and PIC18.

## Actions
- No MCP `action` interface (utility module only).
- `get_arch`: helper function used internally by other tools.
- `is_x86_family`: helper function used internally by other tools.
- `is_arm_family`: helper function used internally by other tools.
- `is_mips_family`: helper function used internally by other tools.
- `is_ppc_family`: helper function used internally by other tools.
- `is_riscv_family`: helper function used internally by other tools.
- `is_sparc_family`: helper function used internally by other tools.
- `get_return_register`: helper function used internally by other tools.
- `get_stack_pointer_names`: helper function used internally by other tools.
- `get_callee_saved_registers`: helper function used internally by other tools.
- `is_return_mnemonic`: helper function used internally by other tools.
- `is_call_mnemonic`: helper function used internally by other tools.
- `is_syscall_mnemonic`: helper function used internally by other tools.
- `get_prologue_pattern`: helper function used internally by other tools.
- `get_epilogue_pattern`: helper function used internally by other tools.
- `get_tail_call_mnemonics`: helper function used internally by other tools.

## Key Parameters
- No MCP request parameters (import/use helper functions directly in code).

## Examples (JSON call snippets)
```json
{
  "tool": "arch_utils",
  "args": {
    "note": "internal helper module; no MCP tool entrypoint"
  }
}
```
```json
{
  "tool": "abi",
  "args": {
    "action": "return_type",
    "addr": "0x401000"
  }
}
```

## Failure Modes
- Not directly invokable via MCP; calling it as a tool name will fail tool lookup.
- Returns `unknown` architecture when IDA API context is unavailable.
