# Code

Decompilation, disassembly, references, and raw memory inspection.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_decompile(address)` | Decompile one function with bounded CFG and ctree-derived structural evidence. | `address` |
| `ida_disassemble(address)` | Disassemble a function or range (`end`), in `csmini`/`classic`/`annotated` styles. | `address` |
| `ida_xrefs_to(address)` | Cross-references to a function, data item, or address. | `address` |
| `ida_callers(address)` | Functions that call the target. | `address` |
| `ida_callees(address)` | Functions called by the target. | `address` |
| `ida_read_bytes(address, size)` | Read raw bytes at any address as a hex dump with ASCII preview (max 4096 bytes). | `address`, `size` |
| `ida_callgraph(address)` | Export a call graph rooted at a function. `direction` is `down`/`up`/`both`, `depth` controls traversal depth, `format` is `mermaid`/`json`/`dot`. | `address` |

`address` accepts a function name or a hexadecimal address (e.g.
`0x401000`). Single-function decompilation is small-area work and stays
available in safe mode; `ida_decompile` responses include call-target
evidence when available.

`ida_read_bytes` is useful when you need to verify the raw bytes at an
address — e.g. to confirm a patch, inspect a header, or check bytes that
IDA has not yet made code. `ida_callgraph` builds the full reachability
tree; use `max_nodes` to cap output size for large binaries.

## Working pattern

1. `ida_decompile` or `ida_disassemble` the function.
2. Follow `ida_xrefs_to` / `ida_callers` to find where it is used.
3. `ida_callees` or `ida_callgraph` to map what it reaches.
4. `ida_read_bytes` to inspect raw memory when the disassembly is ambiguous.
5. Record what you learned with `ida_write_finding` (see
   [Investigation](../core/investigation.md)).
