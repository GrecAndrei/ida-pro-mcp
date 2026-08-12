# Types

Struct, enum, and typedef management in the IDA local type library (TIL).

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_list_types(query, kind, limit)` | List types in the TIL, optionally filtered by name or kind (`struct`/`enum`/`typedef`/`all`). | — |
| `ida_get_type(name)` | Show the full layout of a struct or enum: members, offsets, sizes, and nested types. | `name` |
| `ida_declare_type(declaration)` | Define a new struct, enum, or typedef from a C declaration string. | `declaration`, `risk_ack` |
| `ida_apply_type(address, type_str)` | Apply a type to a function (`kind=function`), global variable (`kind=global`), or local variable (`kind=local`, requires `var_name`). | `address`, `type_str`, `risk_ack` |
| `ida_struct_member_add(struct_name, member_name, ...)` | Add a member to a struct type. `offset=-1` appends at the end; provide `type_str` (a C type) or `size`. | `struct_name`, `member_name`, `risk_ack` |
| `ida_struct_member_rename / _del / _set_type` | Rename, delete, or retype a struct member by name. | `struct_name`, `member_name`, `risk_ack` |
| `ida_enum_member_add / _rename / _revalue` | Add, rename, or revalue an enumerator of an enum type. | `enum_name`, `member_name`, `risk_ack` |
| `ida_til_import(path)` | Import a C header into the TIL. Native-format headers are parsed per-declaration for robustness; foreign headers fall back to `parse_decls`. | `path`, `risk_ack` |
| `ida_til_export(path, name)` | Export matching named types as a C header (cross-session carry). Typedefs are skipped in C exports. | `path`, `risk_ack` |
| `ida_til_delete(name)` | Delete a named type from the TIL. | `name`, `risk_ack` |

## Working pattern

1. `ida_list_types` to see what types are already defined.
2. `ida_get_type(name)` to inspect a struct's layout before applying it.
3. `ida_declare_type` to add a new type from a C header or your own reconstruction.
4. `ida_apply_type` to attach the type to a function prototype, a global, or a
   local variable in the decompiler.

## Notes

- `ida_declare_type` accepts standard C declarations, including nested structs,
  bitfields, and typedefs. Use semicolons to separate multiple declarations in one
  call. Plain (bare) declarations and member type strings should end with `;` —
  the server retries parsing with a trailing `;` when the first attempt fails.
- Bare member types are resolved against the local type library by name
  (`char`/`int`/`short`/etc. map to their fixed-width IDA aliases; `char[N]`
  becomes a `char` array).
- `ida_apply_type` with `kind=function` sets the full prototype (e.g.
  `int parse_pkt(uint8_t *buf, size_t len)`). With `kind=local`, also pass
  `var_name` matching the current decompiler name (e.g. `v3`).
- Type mutations require `risk_ack: true` and persist in the IDB. `set_named_type`
  may return a falsy status even when the type saved — the server verifies with a
  follow-up lookup, so treat a successful response as authoritative.
- Member edits on large structs may need a delete-and-re-add when the retype
  overlaps trailing members; the server performs that shift automatically.
