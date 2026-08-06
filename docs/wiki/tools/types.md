# Types

Struct, enum, and typedef management in the IDA local type library (TIL).

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_list_types(query, kind, limit)` | List types in the TIL, optionally filtered by name or kind (`struct`/`enum`/`typedef`/`all`). | — |
| `ida_get_type(name)` | Show the full layout of a struct or enum: members, offsets, sizes, and nested types. | `name` |
| `ida_declare_type(declaration)` | Define a new struct, enum, or typedef from a C declaration string. | `declaration`, `risk_ack` |
| `ida_apply_type(address, type_str)` | Apply a type to a function (`kind=function`), global variable (`kind=global`), or local variable (`kind=local`, requires `var_name`). | `address`, `type_str`, `risk_ack` |

## Working pattern

1. `ida_list_types` to see what types are already defined.
2. `ida_get_type(name)` to inspect a struct's layout before applying it.
3. `ida_declare_type` to add a new type from a C header or your own reconstruction.
4. `ida_apply_type` to attach the type to a function prototype, a global, or a
   local variable in the decompiler.

## Notes

- `ida_declare_type` accepts standard C declarations, including nested structs,
  bitfields, and typedefs. Use semicolons to separate multiple declarations in one
  call.
- `ida_apply_type` with `kind=function` sets the full prototype (e.g.
  `int parse_pkt(uint8_t *buf, size_t len)`). With `kind=local`, also pass
  `var_name` matching the current decompiler name (e.g. `v3`).
- Type mutations require `risk_ack: true` and persist in the IDB.
