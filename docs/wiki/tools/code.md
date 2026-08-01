# Code

Decompilation, disassembly, and references.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_decompile(address)` | Decompile one function with bounded CFG and ctree-derived structural evidence. | `address` |
| `ida_disassemble(address)` | Disassemble a function or range (`end`), in `csmini`/`classic`/`annotated` styles. | `address` |
| `ida_xrefs_to(address)` | Cross-references to a function, data item, or address. | `address` |
| `ida_callers(address)` | Functions that call the target. | `address` |
| `ida_callees(address)` | Functions called by the target. | `address` |

`address` accepts a function name or a hexadecimal address (e.g.
`0x401000`). Single-function decompilation is small-area work and stays
available in safe mode; `ida_decompile` responses include call-target
evidence when available.

## Working pattern

1. `ida_decompile` or `ida_disassemble` the function.
2. Follow `ida_xrefs_to` / `ida_callers` to find where it is used.
3. `ida_callees` to map what it reaches.
4. Record what you learned with `ida_write_finding` (see
   [Investigation](../core/investigation.md)).
