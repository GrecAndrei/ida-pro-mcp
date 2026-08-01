# Edit

Mutations to the IDB: names, comments, and function boundaries.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_rename(address, name)` | Rename a function or symbol. Never overwrites an existing symbol via publish paths; this operation sets the name directly. | `address`, `name`, `risk_ack` |
| `ida_comment(address, comment)` | Add or replace a comment at an address. | `address`, `comment`, `risk_ack` |
| `ida_create_function(address)` | Define a function, optionally with `end`, `name`, `flags`, `force`. | `address`, `risk_ack` |
| `ida_change_function(address, end)` | Change a function's end boundary. | `address`, `end`, `risk_ack` |

Every mutation requires `risk_ack: true` — set it only after verifying the
change is intended. These are IDB writes; they are allowed in safe mode
(they are manual, small-area work) but persist in the IDB, so be
conservative. For batch propagation of confirmed findings, prefer
`ida_publish_findings` (see [Investigation](../core/investigation.md)).
