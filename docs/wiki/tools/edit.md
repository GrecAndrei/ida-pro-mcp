# Edit

Mutations to the IDA Database (IDB): names, comments, function boundaries, patches,
code/data interpretations, types, segments, snapshots, and transactions.

Every mutating operation requires explicit acknowledgement (`risk_ack: true`) and is
governed by operator policy. These writes alter the underlying database; always verify the
target and intended outcome beforehand.

---

## 1. Names, Comments & Function Structure

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_rename(address, name)` | Rename a function or symbol in the IDB. | `address`, `name`, `risk_ack` |
| `ida_comment(address, comment)` | Add, replace, or clear a comment at an address. | `address`, `comment`, `risk_ack` |
| `ida_rename_local(address, var_name, new_name)` | Rename a local variable inside a decompiled function (e.g. `v3` → `pkt_len`). | `address`, `var_name`, `new_name`, `risk_ack` |
| `ida_create_function(address)` | Define a function at an address, optionally specifying `end`, `name`, or `flags`. | `address`, `risk_ack` |
| `ida_change_function(address, end)` | Change a function's end boundary (Set function end). | `address`, `end`, `risk_ack` |
| `ida_add_entry(address)` | Mark an address as an entry point (reclassifies as code and sets entry flag). | `address`, `risk_ack` |
| `ida_mark_dangerous(address)` | Flag dangerous API call sites with warning comments. | `address`, `risk_ack` |
| `ida_import_system_map(path)` | Import bounded Linux/System.map symbols, optionally adding a virtual-address delta and creating code functions. | `path`, `risk_ack` |

---

## 2. Code, Data & Patching

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_make_code(address)` | Force bytes to be disassembled as CPU instructions (requeues containing function). | `address`, `risk_ack` |
| `ida_undefine(address)` | Undefine code or data annotations across an address range, resetting to raw bytes. | `address`, `risk_ack` |
| `ida_create_data(address, item_type)` | Define scalar, array, or pointer data items (`byte|word|dword|qword|pointer|array`). | `address`, `item_type`, `risk_ack` |
| `ida_create_strlit(address, size)` | Define a string literal covering `[address, address+size)` (`strtype='c'|'c16'|'c32'`). | `address`, `size`, `risk_ack` |
| `ida_patch_bytes(address, hex_bytes)` | Write raw hex bytes to the IDB or NOP out instructions (`nop=true`). Permanent in IDB. | `address`, `risk_ack` |

---

## 3. Segment & Register Edits

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_sreg_set(start, reg, value)` | Set segment-register value mapping for segmented code ranges (e.g. `CS`, `DS`, `GP`). | `start`, `reg`, `value`, `risk_ack` |
| `ida_add_segment(start, end, name)` | Create a new segment (e.g. MMIO, RAM, or carved firmware regions). | `start`, `end`, `name`, `risk_ack` |
| `ida_set_segment_attrs(address, attr, value)` | Update segment attribute (`perm='rwx'`, `name`, `align`, `bitness`, `comb`, `type`, `color`). | `address`, `attr`, `value`, `risk_ack` |

See [Segments](segments.md) for detailed segment workflows.

---

## 4. Type & Signature Mutations

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_declare_type(declaration)` | Define a new struct, enum, or typedef from a C declaration string. | `declaration`, `risk_ack` |
| `ida_apply_type(address, type_str)` | Apply a type to a function prototype (`kind='function'`), global, or local variable. | `address`, `type_str`, `risk_ack` |
| `ida_apply_sig(name)` | Apply an offline FLIRT signature file to name recognized library functions. | `name`, `risk_ack` |
| `ida_struct_member_add(struct_name, member_name)` | Add a member to a struct type (appends when `offset=-1`). | `struct_name`, `member_name`, `risk_ack` |
| `ida_struct_member_del(struct_name, member_name)` | Delete a member from a struct type by name. | `struct_name`, `member_name`, `risk_ack` |
| `ida_struct_member_rename(struct_name, old_name, new_name)` | Rename a member of a struct type. | `struct_name`, `old_name`, `new_name`, `risk_ack` |
| `ida_struct_member_set_type(struct_name, member_name, type_str)` | Retype a member of a struct type using a C type string. | `struct_name`, `member_name`, `type_str`, `risk_ack` |
| `ida_enum_member_add(enum_name, member_name, value)` | Add an enumerator to an enum type with a numeric value. | `enum_name`, `member_name`, `value`, `risk_ack` |
| `ida_enum_member_rename(enum_name, old_name, new_name)` | Rename an enumerator in an enum type. | `enum_name`, `old_name`, `new_name`, `risk_ack` |
| `ida_enum_member_revalue(enum_name, member_name, value)` | Revalue an enumerator in an enum type. | `enum_name`, `member_name`, `value`, `risk_ack` |
| `ida_til_import(path)` | Import a C header file into the local Type Library. | `path`, `risk_ack` |
| `ida_til_export(path, name)` | Export matching named types as a C header file. | `path`, `risk_ack` |
| `ida_til_delete(name)` | Delete a named type from the local Type Library. | `name`, `risk_ack` |

See [Types](types.md) and [Signatures](signatures.md).

---

## 5. Persistence, Snapshots & Rollback

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_save_idb(path=...)` | Save the current IDB to disk (in-place or to `path`). | `risk_ack` |
| `ida_idb_snapshot(name=...)` | Save a named snapshot of the current IDB state for rollback. | `risk_ack` |
| `ida_idb_restore_snapshot(snapshot_id, ordinal)` | Restore the IDB to a previously saved snapshot (LIFO order). | `risk_ack` |
| `ida_undo_begin` | Open an undo transaction/undo-point so a failing batch can be rolled back. | `risk_ack` |
| `ida_undo_end` | Commit changes wrapped by `ida_undo_begin`. | `risk_ack` |

---

## Safety & Rollback Guidelines

1. **Before experiments**: Always capture an `ida_idb_snapshot(name="pre_experiment", risk_ack=true)`.
2. **Bracket batches**: Wrap speculative edit batches between `ida_undo_begin` and `ida_undo_end`.
3. **Destructive operations**: `ida_patch_bytes` permanently alters bytes in the IDB; double check addresses and byte values with `ida_read_bytes` first.
4. **Publishing findings**: For batch propagation of findings into the IDB, prefer `ida_publish_findings` (see [Investigation](../core/investigation.md)).
5. **Persisting work**: Call `ida_save_idb(risk_ack=true)` after completing reviewed edits so work survives session restarts.
