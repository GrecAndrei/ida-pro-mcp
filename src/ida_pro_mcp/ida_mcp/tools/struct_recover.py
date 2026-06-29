
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# STRUCT_RECOVER - Automatic struct/type recovery from field access patterns
# ============================================================================

# Size mapping from operand dtype
_DTYPE_TO_SIZE = {
    0: 1,   # dt_byte
    1: 2,   # dt_word
    2: 4,   # dt_dword
    3: 8,   # dt_qword
    4: 4,   # dt_float
    5: 8,   # dt_double
    6: 10,  # dt_tbyte
    7: 16,  # dt_packreal / dt_byte16
}

# Mnemonics that write to operand 0
_WRITE_MNEMONICS = frozenset({
    "mov", "movzx", "movsx", "movsxd", "lea", "xor", "or", "and", "add",
    "sub", "inc", "dec", "shl", "shr", "sar", "sal", "imul", "mul",
    "not", "neg", "adc", "sbb", "bts", "btr", "btc", "pop",
    # ARM
    "str", "strb", "strh", "strd", "stp",
    "sw", "sh", "sb", "sd",  # MIPS stores
})


def _get_reg_name(reg_num, bits=8):
    """Get register name safely."""
    try:
        name = idaapi.get_reg_name(reg_num, bits)
        if name:
            return name.lower()
    except Exception:
        pass
    try:
        name = idaapi.get_reg_name(reg_num, 4)
        if name:
            return name.lower()
    except Exception:
        pass
    return f"reg{reg_num}"


def _access_size_from_dtype(dtype):
    """Convert operand dtype to access size in bytes."""
    return _DTYPE_TO_SIZE.get(dtype, 4)


def _collect_field_accesses(func_ea):
    """Collect all (base_reg_name, offset, access_size, 'r'|'w') tuples from a function."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    accesses = []
    ptr_size = _inf_ptr_size()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        if not idc.is_code(idc.get_full_flags(head)):
            continue
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, head) <= 0:
            continue
        mnem = idc.print_insn_mnem(head)
        if not mnem:
            continue
        mnem_lower = mnem.lower()
        for i in range(idaapi.UA_MAXOP):
            op = insn.ops[i]
            if op.type == idaapi.o_void:
                break
            if op.type in (idaapi.o_displ, idaapi.o_phrase):
                base_reg = _get_reg_name(op.reg, ptr_size)
                offset = op.addr if op.type == idaapi.o_displ else 0
                # Skip negative offsets (stack-relative) and very large offsets
                if offset > 0x7FFFFFFF:
                    # Likely negative in two's complement
                    continue
                if offset > 0x10000:
                    # Implausibly large struct offset
                    continue
                size = _access_size_from_dtype(op.dtype)
                # Determine read vs write
                is_write = (i == 0 and mnem_lower in _WRITE_MNEMONICS)
                accesses.append((base_reg, offset, size, 'w' if is_write else 'r'))
    return accesses


def _cluster_by_register(accesses):
    """Group accesses by base register, returning {reg: [(offset, size, rw), ...]}."""
    clusters = {}
    for reg, offset, size, rw in accesses:
        clusters.setdefault(reg, []).append((offset, size, rw))
    return clusters


def _infer_field_type(size):
    """Infer field type from access size. Returns a C type string."""
    if size == 1:
        return "uint8_t"
    elif size == 2:
        return "uint16_t"
    elif size == 4:
        return "uint32_t"
    elif size == 8:
        return "uint64_t"
    return f"uint8_t[{size}]"


def _build_field_layout(cluster, func_ea):
    """Build ordered field layout from a cluster of accesses.

    Returns list of dicts: [{name, offset, size, type, access}].
    """
    # Deduplicate: for each offset, pick largest size seen
    offset_map = {}  # offset -> (max_size, set_of_rw)
    for offset, size, rw in cluster:
        if offset not in offset_map:
            offset_map[offset] = (size, {rw})
        else:
            prev_size, prev_rw = offset_map[offset]
            offset_map[offset] = (max(prev_size, size), prev_rw | {rw})

    # Sort by offset
    sorted_offsets = sorted(offset_map.keys())
    fields = []
    for _idx, offset in enumerate(sorted_offsets):
        size, rw_set = offset_map[offset]
        access = "rw" if len(rw_set) > 1 else list(rw_set)[0]
        type_str = _infer_field_type(size)
        fields.append({
            "name": f"field_{offset:X}",
            "offset": offset,
            "size": size,
            "type": type_str,
            "access": access,
        })
    return fields


def _fields_to_c_struct(struct_name, fields):
    """Generate a C struct definition from field layout."""
    lines = [f"struct {struct_name} {{"]
    prev_end = 0
    for field in fields:
        offset = field["offset"]
        size = field["size"]
        # Insert padding if there's a gap
        if offset > prev_end:
            gap = offset - prev_end
            lines.append(f"    uint8_t _pad_{prev_end:X}[{gap}];")
        type_str = field["type"]
        name = field["name"]
        if "[" in type_str:
            # Array type: split base and array part
            base = type_str.split("[")[0]
            arr = "[" + "[".join(type_str.split("[")[1:])
            lines.append(f"    {base} {name}{arr};")
        else:
            lines.append(f"    {type_str} {name};")
        prev_end = offset + size
    lines.append("};")
    return "\n".join(lines)


def _propagate_struct_info(func_ea, fields, limit=50):
    """Walk call graph from func_ea to find functions receiving the same struct pointer.

    Returns list of {callee, callee_addr, arg_index, shared_fields}.
    """
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    results = []
    seen = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            callee_fn = ida_funcs.get_func(xref)
            if not callee_fn or callee_fn.start_ea in seen:
                continue
            seen.add(callee_fn.start_ea)
            callee_name = idc.get_func_name(callee_fn.start_ea)
            # Collect accesses in callee
            callee_accesses = _collect_field_accesses(callee_fn.start_ea)
            if not callee_accesses:
                continue
            callee_clusters = _cluster_by_register(callee_accesses)
            # Find clusters with overlapping offsets
            source_offsets = {f["offset"] for f in fields}
            for reg, cluster in callee_clusters.items():
                callee_offsets = {off for off, _, _ in cluster}
                shared = source_offsets & callee_offsets
                if len(shared) >= 2:
                    results.append({
                        "callee": callee_name,
                        "callee_addr": hex_ea(callee_fn.start_ea),
                        "base_reg": reg,
                        "shared_offsets": sorted(shared),
                        "shared_count": len(shared),
                    })
            if len(results) >= limit:
                break
    return results


def _apply_struct_to_til(struct_name, fields):
    """Create/update struct in IDA's local type library. Returns (ok, error_msg)."""
    try:
        til = ida_typeinf.get_idati()
        if not til:
            return False, "Failed to get local type library"

        udt = ida_typeinf.udt_type_data_t()
        prev_end = 0

        for field in fields:
            offset = field["offset"]
            size = field["size"]

            # Insert padding member if gap
            if offset > prev_end:
                gap = offset - prev_end
                pad_member = ida_typeinf.udt_member_t()
                pad_member.name = f"_pad_{prev_end:X}"
                pad_tif = ida_typeinf.tinfo_t()
                # Create byte array for padding
                if gap == 1:
                    pad_tif.create_simple_type(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
                else:
                    elem_tif = ida_typeinf.tinfo_t()
                    elem_tif.create_simple_type(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
                    pad_tif.create_array(elem_tif, gap)
                pad_member.type = pad_tif
                pad_member.offset = prev_end * 8  # offset in bits
                udt.push_back(pad_member)

            member = ida_typeinf.udt_member_t()
            member.name = field["name"]
            member.offset = offset * 8  # offset in bits

            # Create type based on size
            tif = ida_typeinf.tinfo_t()
            type_str = field.get("type", "")
            if "[" in type_str:
                # Array type
                type_str.split("[")[0]
                arr_part = type_str.split("[")[1].rstrip("]")
                arr_count = int(arr_part) if arr_part.isdigit() else size
                elem_tif = ida_typeinf.tinfo_t()
                _set_simple_type(elem_tif, 1)
                tif.create_array(elem_tif, arr_count)
            else:
                _set_simple_type(tif, size)

            member.type = tif
            member.size = size * 8  # size in bits
            udt.push_back(member)
            prev_end = offset + size

        # Create the tinfo for the struct
        struct_tif = ida_typeinf.tinfo_t()
        struct_tif.create_udt(udt, idaapi.BTF_STRUCT)

        # Register in local type library
        rc = struct_tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
        if rc not in (0, ida_typeinf.TERR_OK):
            # Try without NTF_REPLACE (new type)
            rc = struct_tif.set_named_type(til, struct_name, 0)
            if rc not in (0, ida_typeinf.TERR_OK):
                return False, f"set_named_type failed with code {rc}"

        return True, None
    except Exception as e:
        return False, str(e)


def _set_simple_type(tif, size):
    """Set a tinfo_t to a simple integer type matching the given size."""
    if size == 1:
        tif.create_simple_type(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
    elif size == 2:
        tif.create_simple_type(idaapi.BT_INT16 | idaapi.BTMT_UNSIGNED)
    elif size == 4:
        tif.create_simple_type(idaapi.BT_INT32 | idaapi.BTMT_UNSIGNED)
    elif size == 8:
        tif.create_simple_type(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED)
    else:
        # Fallback: byte array
        elem = ida_typeinf.tinfo_t()
        elem.create_simple_type(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
        tif.create_array(elem, size)


def _get_func_or_error(addr):
    """Resolve addr to a function, returning (func_ea, error_dict_or_None)."""
    if addr is not None:
        ea, err = validate_addr(addr)
        if err:
            return None, err
    else:
        ea = idc.get_screen_ea()
        if ea == idaapi.BADADDR:
            return None, make_error(MCPError.INVALID_ARGS, "addr required (no cursor in headless mode)")
    func = ida_funcs.get_func(ea)
    if not func:
        return None, make_error(MCPError.INVALID_ARGS, f"No function at {hex(ea)}")
    return func.start_ea, None


@tool
@idaread
def struct_recover(
    action: Annotated[Literal["recover", "recover_all", "propagate", "preview", "apply"],
                      "Struct recovery action"],
    addr: Annotated[Optional[str], "Function/address to analyze"] = None,
    min_fields: Annotated[int, "Minimum fields to consider a struct candidate (for recover_all)"] = 3,
    struct_name: Annotated[Optional[str], "Struct name for preview/apply (auto-generated if omitted)"] = None,
    limit: Annotated[int, "Max results"] = 50,
) -> dict:
    """
    Automatic struct/type recovery from field access patterns in disassembly.

    ACTIONS:

    recover - Recover struct layout from field access patterns at a function.
        Params: addr (required)
        Returns: {function, candidates[{base_reg, field_count, fields[], total_size}]}
        Example: struct_recover(action="recover", addr="0x401000")

    recover_all - Scan all functions for pointer-based struct access patterns.
        Params: min_fields (default 3), limit
        Returns: {candidates[{function, addr, base_reg, field_count, total_size}]}
        Example: struct_recover(action="recover_all", min_fields=4)

    propagate - Transitive type propagation via call graph.
        Params: addr (required)
        Returns: {source_function, propagated_to[{callee, shared_offsets}]}
        Example: struct_recover(action="propagate", addr="0x401000")

    preview - Show inferred struct as a C definition (TIL-compatible).
        Params: addr (required), struct_name (optional)
        Returns: {c_definition, fields}
        Example: struct_recover(action="preview", addr="0x401000")

    apply - Apply inferred struct to IDA's local type system.
        Params: addr (required), struct_name (optional)
        Returns: {applied, struct_name, field_count}
        Example: struct_recover(action="apply", addr="0x401000", struct_name="my_ctx")
    """
    try:
        # ----------------------------------------------------------------
        # ACTION: recover
        # ----------------------------------------------------------------
        if action == "recover":
            func_ea, err = _get_func_or_error(addr)
            if err:
                return err
            func_name = idc.get_func_name(func_ea)
            accesses = _collect_field_accesses(func_ea)
            if not accesses:
                return {"ok": True, "function": func_name, "addr": hex_ea(func_ea),
                        "candidates": [], "note": "No struct-like field accesses found"}
            clusters = _cluster_by_register(accesses)
            # Filter: skip stack pointer registers (they are frame accesses, not structs)
            sp_names = {n.lower() for n in get_stack_pointer_names()}
            candidates = []
            for reg, cluster in sorted(clusters.items(), key=lambda x: -len(x[1])):
                if reg in sp_names:
                    continue
                # Deduplicate offsets
                unique_offsets = set()
                for off, _, _ in cluster:
                    unique_offsets.add(off)
                if len(unique_offsets) < 2:
                    continue
                fields = _build_field_layout(cluster, func_ea)
                if not fields:
                    continue
                total_size = max(f["offset"] + f["size"] for f in fields)
                candidates.append({
                    "base_reg": reg,
                    "field_count": len(fields),
                    "total_size": total_size,
                    "fields": fields,
                })
                if len(candidates) >= limit:
                    break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func_ea),
                "access_count": len(accesses),
                "candidates": candidates,
            }

        # ----------------------------------------------------------------
        # ACTION: recover_all
        # ----------------------------------------------------------------
        elif action == "recover_all":
            sp_names = {n.lower() for n in get_stack_pointer_names()}
            candidates = []
            func_count = 0
            for ea in idautils.Functions():
                func_count += 1
                if func_count > 10000:
                    break
                accesses = _collect_field_accesses(ea)
                if not accesses:
                    continue
                clusters = _cluster_by_register(accesses)
                for reg, cluster in clusters.items():
                    if reg in sp_names:
                        continue
                    unique_offsets = set()
                    for off, _, _ in cluster:
                        unique_offsets.add(off)
                    if len(unique_offsets) < min_fields:
                        continue
                    fields = _build_field_layout(cluster, ea)
                    total_size = max(f["offset"] + f["size"] for f in fields) if fields else 0
                    func_name = idc.get_func_name(ea)
                    candidates.append({
                        "function": func_name,
                        "addr": hex_ea(ea),
                        "base_reg": reg,
                        "field_count": len(fields),
                        "total_size": total_size,
                    })
                    if len(candidates) >= limit:
                        break
                if len(candidates) >= limit:
                    break
            return {
                "ok": True,
                "functions_scanned": func_count,
                "candidates": candidates,
                "count": len(candidates),
            }

        # ----------------------------------------------------------------
        # ACTION: propagate
        # ----------------------------------------------------------------
        elif action == "propagate":
            func_ea, err = _get_func_or_error(addr)
            if err:
                return err
            func_name = idc.get_func_name(func_ea)
            # First recover struct at this function
            accesses = _collect_field_accesses(func_ea)
            if not accesses:
                return {"ok": True, "function": func_name, "addr": hex_ea(func_ea),
                        "propagated_to": [],
                        "note": "No struct accesses found to propagate"}
            clusters = _cluster_by_register(accesses)
            sp_names = {n.lower() for n in get_stack_pointer_names()}
            # Pick the best candidate (most fields, non-stack)
            best_fields = []
            for reg, cluster in sorted(clusters.items(), key=lambda x: -len(x[1])):
                if reg in sp_names:
                    continue
                fields = _build_field_layout(cluster, func_ea)
                if len(fields) > len(best_fields):
                    best_fields = fields
            if not best_fields:
                return {"ok": True, "function": func_name, "addr": hex_ea(func_ea),
                        "propagated_to": [],
                        "note": "No struct candidate found"}
            propagated = _propagate_struct_info(func_ea, best_fields, limit=limit)
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func_ea),
                "source_field_count": len(best_fields),
                "propagated_to": propagated,
                "propagation_count": len(propagated),
            }

        # ----------------------------------------------------------------
        # ACTION: preview
        # ----------------------------------------------------------------
        elif action == "preview":
            func_ea, err = _get_func_or_error(addr)
            if err:
                return err
            func_name = idc.get_func_name(func_ea)
            accesses = _collect_field_accesses(func_ea)
            if not accesses:
                return {"ok": True, "function": func_name, "addr": hex_ea(func_ea),
                        "c_definition": "", "note": "No struct accesses found"}
            clusters = _cluster_by_register(accesses)
            sp_names = {n.lower() for n in get_stack_pointer_names()}
            # Pick best candidate
            best_fields = []
            best_reg = None
            for reg, cluster in sorted(clusters.items(), key=lambda x: -len(x[1])):
                if reg in sp_names:
                    continue
                fields = _build_field_layout(cluster, func_ea)
                if len(fields) > len(best_fields):
                    best_fields = fields
                    best_reg = reg
            if not best_fields:
                return {"ok": True, "function": func_name, "addr": hex_ea(func_ea),
                        "c_definition": "", "note": "No struct candidate found"}
            # Generate name
            name = struct_name or f"struct_{func_name}_{best_reg}"
            # Sanitize name
            name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
            c_def = _fields_to_c_struct(name, best_fields)
            total_size = max(f["offset"] + f["size"] for f in best_fields)
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func_ea),
                "struct_name": name,
                "base_reg": best_reg,
                "field_count": len(best_fields),
                "total_size": total_size,
                "c_definition": c_def,
                "fields": best_fields,
            }

        # ----------------------------------------------------------------
        # ACTION: apply
        # ----------------------------------------------------------------
        elif action == "apply":
            func_ea, err = _get_func_or_error(addr)
            if err:
                return err
            func_name = idc.get_func_name(func_ea)
            accesses = _collect_field_accesses(func_ea)
            if not accesses:
                return make_error(MCPError.INVALID_ARGS,
                                  f"No struct-like field accesses found in {func_name}")
            clusters = _cluster_by_register(accesses)
            sp_names = {n.lower() for n in get_stack_pointer_names()}
            best_fields = []
            best_reg = None
            for reg, cluster in sorted(clusters.items(), key=lambda x: -len(x[1])):
                if reg in sp_names:
                    continue
                fields = _build_field_layout(cluster, func_ea)
                if len(fields) > len(best_fields):
                    best_fields = fields
                    best_reg = reg
            if not best_fields:
                return make_error(MCPError.INVALID_ARGS,
                                  f"No struct candidate found in {func_name}")
            name = struct_name or f"struct_{func_name}_{best_reg}"
            name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
            ok, err_msg = _apply_struct_to_til(name, best_fields)
            if not ok:
                return make_error(MCPError.INTERNAL, f"Failed to apply struct: {err_msg}")
            total_size = max(f["offset"] + f["size"] for f in best_fields)
            return {
                "ok": True,
                "applied": True,
                "struct_name": name,
                "field_count": len(best_fields),
                "total_size": total_size,
                "function": func_name,
                "addr": hex_ea(func_ea),
                "note": f"Struct '{name}' created in local types with {len(best_fields)} fields",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
