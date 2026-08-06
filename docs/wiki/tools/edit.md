# Edit

Mutations to the IDB: names, comments, function boundaries, patches, and local variables.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_rename(address, name)` | Rename a function or symbol. Never overwrites an existing symbol via publish paths; this operation sets the name directly. | `address`, `name`, `risk_ack` |
| `ida_comment(address, comment)` | Add or replace a comment at an address. | `address`, `comment`, `risk_ack` |
| `ida_create_function(address)` | Define a function, optionally with `end`, `name`, `flags`, `force`. | `address`, `risk_ack` |
| `ida_change_function(address, end)` | Change a function's end boundary. | `address`, `end`, `risk_ack` |
| `ida_patch_bytes(address, hex_bytes)` | Write raw hex bytes at an address, or pass `nop=true` to NOP-out the instruction(s). NOP encoding is architecture-aware (RISC-V, ARM, x86). | `address`, `risk_ack` |
| `ida_rename_local(address, var_name, new_name)` | Rename a local variable inside a decompiled function. `address` is the function start; `var_name` is the current decompiler name (e.g. `v3`). | `address`, `var_name`, `new_name`, `risk_ack` |

Every mutation requires `risk_ack: true` — set it only after verifying the
change is intended. These are IDB writes; they persist in the IDB, so be
conservative. `ida_patch_bytes` is permanent in the IDB and cannot be
undone via the MCP surface — double-check the address and bytes before
setting `risk_ack`. For batch propagation of confirmed findings, prefer
`ida_publish_findings` (see [Investigation](../core/investigation.md)).
