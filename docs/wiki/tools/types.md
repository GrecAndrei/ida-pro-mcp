# Types

Struct, enum, and typedef management in the IDA local Type Library (TIL).

Every mutating type operation requires `risk_ack: true` and alters the IDB.

---

## Operations Overview

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_list_types(query, kind, limit)` | List types in the TIL, optionally filtered by name or kind (`struct`/`enum`/`typedef`/`all`). | — |
| `ida_get_type(name)` | Inspect the layout of a struct or enum: members, offsets, sizes, and nested types. | `name` |
| `ida_declare_type(declaration)` | Define a new struct, enum, or typedef from a C declaration string. | `declaration`, `risk_ack` |
| `ida_apply_type(address, type_str)` | Apply a type to a function (`kind='function'`), global variable (`kind='global'`), or local (`kind='local'`). | `address`, `type_str`, `risk_ack` |
| `ida_struct_member_add(struct_name, member_name)` | Add a member to a struct type (appends when `offset=-1`). Provide `type_str` or `size`. | `struct_name`, `member_name`, `risk_ack` |
| `ida_struct_member_del(struct_name, member_name)` | Delete a member from a struct type by name. | `struct_name`, `member_name`, `risk_ack` |
| `ida_struct_member_rename(struct_name, old_name, new_name)` | Rename a member of a struct type. | `struct_name`, `old_name`, `new_name`, `risk_ack` |
| `ida_struct_member_set_type(struct_name, member_name, type_str)` | Retype a member of a struct type using a C type string. | `struct_name`, `member_name`, `type_str`, `risk_ack` |
| `ida_enum_member_add(enum_name, member_name, value)` | Add an enumerator to an enum type with a numeric value. | `enum_name`, `member_name`, `value`, `risk_ack` |
| `ida_enum_member_rename(enum_name, old_name, new_name)` | Rename an enumerator in an enum type. | `enum_name`, `old_name`, `new_name`, `risk_ack` |
| `ida_enum_member_revalue(enum_name, member_name, value)` | Revalue an existing enumerator in an enum type. | `enum_name`, `member_name`, `value`, `risk_ack` |
| `ida_til_import(path)` | Import a C header file into the local Type Library. | `path`, `risk_ack` |
| `ida_til_export(path, name)` | Export matching named types as a C header file for cross-session use. | `path`, `risk_ack` |
| `ida_til_delete(name)` | Delete a named type from the local Type Library. | `name`, `risk_ack` |

---

## Working Pattern

1. `ida_list_types(query="pkt_")` to see existing defined types.
2. `ida_get_type(name="pkt_header")` to inspect struct layout, member offsets, and padding.
3. `ida_declare_type(declaration="struct pkt_header { uint32_t magic; uint16_t len; };", risk_ack=true)` to declare new structures.
4. `ida_apply_type(address="0x401000", type_str="int parse_pkt(struct pkt_header *hdr)", kind="function", risk_ack=true)` to attach the prototype to decompiled code.

---

## Member Retyping & Reshaping

- `ida_struct_member_add` adds fields at specific offsets. If `offset=-1`, the member is appended at the end.
- `ida_struct_member_set_type` changes a member's type (e.g. `uint32_t` to `void*`). The server shifts overlapping subsequent members automatically if needed.
- `ida_struct_member_del` removes a field by name.
- `ida_struct_member_rename` renames fields for clarity after reverse engineering their purpose.

---

## Local Variables in Decompiler

To retype local variables in Hex-Rays pseudocode:

```json
{
  "address": "0x401000",
  "kind": "local",
  "var_name": "v3",
  "type_str": "struct pkt_header *",
  "risk_ack": true
}
```

Use `ida_rename_local` to rename the variable (e.g. `v3` → `pkt`).
