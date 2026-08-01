# Calculation

Address and value arithmetic without running scripts.

| Operation | Purpose |
| --- | --- |
| `ida_calc_eval(expr)` | Evaluate a safe arithmetic/bitwise expression, e.g. `0x401000 + 0x20`. |
| `ida_calc_offset(address, target)` | Signed and absolute distance between two addresses/symbols. |
| `ida_calc_convert(value)` | Hex, decimal, binary, octal, byte, ASCII forms of a value. |
| `ida_calc_resolve(value)` | Translate an IDA virtual address or file offset via segment mapping. |
| `ida_calc_deref(address)` | Read a typed value (`u8`–`u64`, `f32`, `ptr`, `string`, ...) at an address, with `deref_depth` hops. |
| `ida_calc_chain(address, offsets)` | Follow a pointer chain with explicit offsets. |
| `ida_calc_align(value, size)` | Align a value down/up/nearest to a boundary. |
| `ida_calc_bitops(value, op)` | and/or/xor/not/shl/shr on integer values. |

Values accept numeric literals, hex addresses, or symbols. Set `persist:
true` to save a result into the investigation notebook.
