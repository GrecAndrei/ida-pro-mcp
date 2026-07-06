
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# Ensure utility functions for local var type modification are available
try:
    from ida_mcp.utils import my_modifier_t, refresh_decompiler_ctext
except ImportError:
    try:
        from utils import my_modifier_t, refresh_decompiler_ctext  # type: ignore[import-not-found]
    except ImportError:
        pass


def _is_fully_mapped(ea: int, size: int) -> bool:
    """True iff [ea, ea+size) lies within a mapped segment."""
    if size < 0:
        return False
    if size == 0:
        return True
    try:
        start = int(ea)
        end = int(ea) + int(size) - 1
        if end < start:
            return False
        if not ida_bytes.is_loaded(start) or not ida_bytes.is_loaded(end):
            return False
        seg = idaapi.getseg(start)
        return bool(seg) and int(end) < int(seg.end_ea)
    except Exception:
        return False


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================

@tool
@idawrite
def types(
    action: Annotated[Literal["list", "get", "set_prototype", "parse_decl", "declare", "apply",
                              "search_structs", "infer", "read_struct", "import_header",
                              "diff", "visualize", "propagate", "enum_values", "type_graph", "vtable"],
                      "Action: list|get|set_prototype|parse_decl|declare|apply|search_structs|"
                      "infer|read_struct|import_header|diff|visualize|propagate|enum_values|type_graph|vtable"],
    name: Annotated[Optional[str], "Type name (or variable name for apply)"] = None,
    addr: Annotated[Optional[str], "Address (for set_prototype/apply/infer/read_struct)"] = None,
    decl: Annotated[Optional[str], "Type declaration string (or header content)"] = None,
    query: Annotated[Optional[str], "Search query (regex/glob/substring/semantic; for list/search_structs)"] = None,
    kind: Annotated[Optional[str], "Apply kind: function, global, local, stack"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Maximum items to return"] = 100,
    # Extended action parameters
    other_name: Annotated[Optional[str], "Second type name (for diff)"] = None,
    value: Annotated[Optional[int], "Enum value to look up (for enum_values with lookup mode)"] = None,
    max_depth: Annotated[int, "Maximum recursion depth for type_graph"] = 5,
    **kwargs
) -> dict:
    """
    Manage and inspect types, structures, and function prototypes.

    Actions:
    - list:           List all types (structs, enums, typedefs) in the Type Library (TIL).
    - get:            Get detailed structure layout or enum members for a named type.
    - set_prototype:  Set the C-style function prototype at an address.
    - parse_decl:     Parse a C declaration string to verify validity and size.
    - declare:        Define a new local type/struct from a C declaration.
    - apply:          Apply a type to an address (global/function/local).
    - search_structs: Find structs containing a field matching `query`.
    - infer:          Attempt to guess the type at an address.
    - read_struct:    Read structured data from memory using a type.
    - import_header:  Parse a full C header content (structs/enums) into the local type library.
    - diff:           Compare two types by name and show field-level differences.
    - visualize:      Create a visual/textual representation of a struct layout with offsets/sizes.
    - propagate:      Propagate a type from one address to all locations that reference it via xrefs.
    - enum_values:    List all enum values for a given enum name, with optional value lookup.
    - type_graph:     Build a dependency graph of structs (which structs contain which other structs).

    Arguments:
    - name:       Type name, or variable name when applying types.
    - addr:       Target address.
    - decl:       C declaration string or header content.
    - query:      Name filter for 'list' or field filter for 'search_structs'.
    - offset/count: Pagination controls for 'list'.
    - other_name: Second type name for 'diff' action.
    - value:      Enum numeric value to look up (for 'enum_values').
    - max_depth:  Max recursion depth for 'type_graph' (default 5).
    """
    try:
        # ====================================================================
        # import_header - Parse C header into the type library
        # ====================================================================
        if action == "import_header":
            if not decl:
                return make_error(MCPError.INVALID_ARGS, "decl (header content) required. "
                                  "Provide a C header string with struct, enum, and typedef declarations.")

            # idc.parse_decls wraps ida_typeinf.idc_parse_types
            # Returns the number of parsing errors (0 = success)
            errors = idc.parse_decls(decl, 0)

            if errors == 0:
                return {"ok": True, "status": "Header imported successfully", "errors": 0}
            else:
                return make_error(MCPError.TYPE_ERROR, f"Header parsing failed with {errors} errors. "
                                  "Check C syntax, ensure all referenced types exist in the type library, "
                                  "and avoid trailing semicolons in unexpected places.")

        # ====================================================================
        # list - Enumerate all types in the type library
        # ====================================================================
        elif action == "list":
            types_list = []
            til = ida_typeinf.get_idati()
            if not til:
                return make_error(MCPError.IDA_ERROR, "Type library not available. "
                                  "Ensure IDA has finished initial analysis and a type library is loaded.")

            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return make_error(MCPError.IDA_ERROR, "Type ordinal API not available. "
                                  "This IDA version may use a different type enumeration API.")

            total_qty = qty_func(til)
            found = 0
            matcher = compile_smart_pattern(query, case_sensitive=False) if query else None

            for ordinal in range(1, total_qty + 1):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(til, ordinal):
                    tname = tif.get_type_name()
                    if tname and (matcher is None or matcher(tname)):
                        found += 1
                        if found > offset and (count == 0 or len(types_list) < count):
                            types_list.append({
                                "ordinal": ordinal,
                                "name": tname,
                                "type": str(tif),
                                "is_struct": tif.is_struct(),
                                "is_enum": tif.is_enum(),
                                "size": tif.get_size(),
                            })
                            if count > 0 and len(types_list) >= count:
                                break

            return {
                "ok": True,
                "types": types_list,
                "total": found,
                "offset": offset,
                "count": len(types_list),
            }

        # ====================================================================
        # get - Inspect a single type (struct/enum/typedef) in detail
        # ====================================================================
        elif action == "get":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required. "
                                  "Provide the name of a struct, enum, or typedef to inspect.")

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(name, tif):
                return make_error(MCPError.TYPE_ERROR, f"Type '{name}' not found in the type library. "
                                  "Use 'list' to see all available types or 'import_header' to load from a C header.")

            result = {"ok": True, "name": name, "type": str(tif), "size": tif.get_size()}

            if tif.is_struct() or tif.is_union():
                result["kind"] = "union" if tif.is_union() else "struct"
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for m in udt:
                        if not m.is_gap():
                            members.append({
                                "name": m.name,
                                "offset": m.offset // 8,
                                "type": str(m.type),
                                "size": m.type.get_size(),
                            })
                    result["members"] = members
                    result["total_members"] = len(members)
                    result["total_size"] = tif.get_size()

            elif tif.is_enum():
                result["kind"] = "enum"
                ei = ida_typeinf.enum_type_data_t()
                if tif.get_enum_details(ei):
                    members = [{"name": e.name, "value": e.value} for e in ei]
                    result["members"] = members
                    result["total_members"] = len(members)

            elif tif.is_func():
                result["kind"] = "function"

            elif tif.is_typedef():
                result["kind"] = "typedef"
                # Best-effort typedef chain unwrapping to a concrete type.
                try:
                    chain = [str(tif)]
                    cur = ida_typeinf.tinfo_t(tif)
                    for _ in range(8):
                        if not cur.is_typedef():
                            break
                        nxt = ida_typeinf.tinfo_t()
                        ok = False
                        if hasattr(cur, "get_next_type_name"):
                            try:
                                next_name = cur.get_next_type_name()
                                if next_name and _resolve_type_by_name(next_name, nxt):
                                    ok = True
                            except Exception:
                                ok = False
                        if not ok and hasattr(cur, "get_next_type"):
                            try:
                                ok = bool(cur.get_next_type(nxt))
                            except Exception:
                                ok = False
                        if not ok:
                            break
                        chain.append(str(nxt))
                        cur = nxt
                    if len(chain) > 1:
                        result["typedef_chain"] = chain
                        result["resolved_type"] = chain[-1]
                except Exception:
                    pass

            return result

        # ====================================================================
        # set_prototype - Set function prototype at an address
        # ====================================================================
        elif action == "set_prototype":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. "
                                  "Provide the address of a function (e.g., '0x401000').")
            if not decl:
                return make_error(MCPError.INVALID_ARGS, "decl required (function prototype). "
                                  "Example: 'int __cdecl my_func(int a, char *b)'")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse prototype: '{decl}'. "
                                  "Check C syntax and ensure all referenced types exist in the type library.")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": hex(ea), "prototype": str(tif)}
            return make_error(MCPError.IDA_ERROR, f"Failed to apply prototype at {hex(ea)}. "
                              "The address may not be a valid function entry point or the type may be incompatible.")

        # ====================================================================
        # parse_decl - Parse a C declaration string for validation
        # ====================================================================
        elif action == "parse_decl":
            if not decl:
                return make_error(MCPError.INVALID_ARGS, "decl required. "
                                  "Provide a C type declaration to parse (e.g., 'int *[10]').")
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse declaration: '{decl}'. "
                                  "Check C syntax and ensure referenced types exist in the type library.")
            return {
                "ok": True,
                "type": str(tif),
                "size": tif.get_size(),
                "is_func": tif.is_func(),
                "is_struct": tif.is_struct(),
                "is_enum": tif.is_enum(),
                "is_ptr": tif.is_ptr(),
                "is_typedef": tif.is_typedef(),
            }

        # ====================================================================
        # declare - Define a new type from a C declaration
        # ====================================================================
        elif action == "declare":
            if not decl:
                return make_error(MCPError.INVALID_ARGS, "decl required. "
                                  "Example: 'struct MyStruct { int x; char buf[256]; };'")
            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()
            result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_TYP)
            if result is None:
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse declaration: '{decl}'. "
                                  "Check C syntax; all referenced types must already exist in the type library.")
            type_name = tif.get_type_name() or name
            if not type_name:
                import re
                match = re.search(r'(?:struct|enum|union)\s+(\w+)', decl)
                if match:
                    type_name = match.group(1)
                else:
                    return make_error(MCPError.INVALID_ARGS, "Could not determine type name from declaration. "
                                      "Provide a 'name' parameter or use a named struct/enum/union declaration.")
            ordinal = ida_typeinf.alloc_type_ordinal(til)
            if ida_typeinf.set_numbered_type(til, ordinal, ida_typeinf.NTF_TYPE, type_name, tif):
                return {"ok": True, "name": type_name, "ordinal": ordinal, "size": tif.get_size()}
            return make_error(MCPError.IDA_ERROR, f"Failed to save type '{type_name}' to the type library. "
                              "A type with the same name may already exist; use a different name.")

        # ====================================================================
        # apply - Apply a type to an address (global/function/local)
        # ====================================================================
        elif action == "apply":
            if not addr or not decl:
                return make_error(MCPError.INVALID_ARGS, "addr and decl required. "
                                  "Provide an address and a C type declaration (e.g., 'int' or 'MyStruct *').")

            ea, err = validate_addr(addr)
            if err:
                return err

            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse type: '{decl}'. "
                                  "Check C syntax and ensure all referenced types exist.")

            apply_kind = kind
            func = idaapi.get_func(ea)

            if not apply_kind:
                apply_kind = "function" if func and func.start_ea == ea else "global"

            if apply_kind == "function":
                if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return make_error(MCPError.IDA_ERROR, f"Failed to apply function type at {hex(ea)}. "
                                      "Ensure the address is a valid function start.")

            elif apply_kind == "local":
                if not name:
                    return make_error(MCPError.INVALID_ARGS, "name required for local variable. "
                                      "Provide the local variable name as it appears in the decompiler.")
                if not func:
                    return make_error(MCPError.FUNCTION_NOT_FOUND, f"Address {hex(ea)} is not inside a function. "
                                      "For local variables, addr must be within a recognized function.")

                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if not cfunc:
                        return make_error(MCPError.IDA_ERROR, f"Decompilation failed at {hex(func.start_ea)}. "
                                          "Hex-Rays may not be available or the function is too complex.")

                    lvar_found = None
                    for lvar in cfunc.lvars:
                        if lvar.name == name:
                            lvar_found = lvar
                            break

                    if not lvar_found:
                        var_list = [lv.name for lv in cfunc.lvars if lv.name]
                        hint = f"Available locals: {', '.join(var_list[:10])}"
                        if len(var_list) > 10:
                            hint += "..."
                        return make_error(MCPError.INVALID_ARGS, f"Local variable '{name}' not found in function. {hint}")

                    modifier = my_modifier_t(name, tif)
                    if ida_hexrays.modify_user_lvars(func.start_ea, modifier):
                        refresh_decompiler_ctext(func.start_ea)
                        return {"ok": True, "addr": hex(ea), "var": name, "type": str(tif), "kind": "local"}
                    return make_error(MCPError.IDA_ERROR, f"Failed to modify local variable '{name}' type. "
                                      "The variable may be optimized out or the type is incompatible.")
                except Exception as e:
                    return handle_error(e)

            elif not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return make_error(MCPError.IDA_ERROR, f"Failed to apply type at {hex(ea)}. "
                                  "The address or type may be incompatible.")

            return {"ok": True, "addr": hex(ea), "type": str(tif), "kind": apply_kind}

        # ====================================================================
        # search_structs - Find structs containing a field matching query
        # ====================================================================
        elif action == "search_structs":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required. "
                                  "Provide a field name or pattern to search for (e.g., 'callback', 'flags', '*size*').")

            matches = []
            matcher = compile_smart_pattern(query, case_sensitive=False)
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return make_error(MCPError.IDA_ERROR, "Type ordinal API not available. "
                                  "This IDA version may use a different type enumeration API.")

            max_types = max(1, qty_func(None))
            limit = max_types
            if count > 0:
                limit = min(max_types, offset + count + 100)  # scan ahead beyond page
            for ordinal in range(1, limit):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and (tif.is_struct() or tif.is_union()):
                    type_name = tif.get_type_name()
                    if matcher(type_name):
                        matches.append({"name": type_name, "ordinal": ordinal, "match": "name"})
                        if count > 0 and len(matches) >= count:
                            break
                        continue

                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for i in range(udt.size()):
                            m = udt[i]
                            if matcher(m.name):
                                matches.append({
                                    "name": type_name,
                                    "ordinal": ordinal,
                                    "match": "field",
                                    "field": m.name,
                                })
                                if count > 0 and len(matches) >= count:
                                    break
                                break
            return {"ok": True, "matches": matches, "total": len(matches)}

        # ====================================================================
        # infer - Guess the type at an address
        # ====================================================================
        elif action == "infer":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. "
                                  "Provide an address to try to infer the type at.")
            ea = parse_address(addr)
            if ea == idaapi.BADADDR:
                return make_error(MCPError.INVALID_ARGS, f"Invalid address: {addr}")

            inferred_types = []
            applied = False
            conf = 0.0
            # Prologue/frame-driven locals inference.
            try:
                frame_id = idc.get_frame_id(ea)
                if frame_id != idaapi.BADADDR:
                    locals_found = []
                    off = idc.get_first_member(frame_id)
                    while off not in (-1, idaapi.BADADDR):
                        nm = idc.get_member_name(frame_id, off) or ""
                        if nm:
                            sz = idc.get_member_size(frame_id, off)
                            locals_found.append({"name": nm, "offset": int(off), "size": int(sz)})
                        off = idc.get_next_member(frame_id, off)
                    if len(locals_found) >= 3:
                        inferred_types.append({"kind": "stack_frame", "locals": locals_found[:32], "count": len(locals_found)})
                        conf = max(conf, 0.65)
            except Exception:
                pass
            # Object-init pattern heuristic: detect allocator usage without
            # guessing sizes from call operands (often callee addresses).
            try:
                fn = idaapi.get_func(ea)
                if fn:
                    alloc_hits = 0
                    for head in idautils.Heads(fn.start_ea, fn.end_ea):
                        dis = (ida_lines.tag_remove(idc.generate_disasm_line(head, 0) or "")).lower()
                        if "malloc" in dis or "calloc" in dis:
                            alloc_hits += 1
                    if alloc_hits:
                        inferred_types.append({"kind": "heap_object", "allocator_calls": int(alloc_hits)})
                        conf = max(conf, 0.55)
            except Exception:
                pass
            # Existing/hexrays fallback
            if not inferred_types:
                tif = ida_typeinf.tinfo_t()
                try:
                    if ida_nalt.get_tinfo(tif, ea):
                        inferred_types.append({"kind": "existing", "type": str(tif)})
                        conf = max(conf, 0.8)
                except Exception:
                    pass
            return {"ok": True, "addr": addr, "inferred_types": inferred_types, "confidence": round(float(conf), 3), "applied": bool(applied)}

        # ====================================================================
        # read_struct - Read structured data from memory using a type
        # FIXED: uses correct ida_bytes.get_byte/get_word/get_dword/get_qword,
        #        handles pointer size properly, removes spurious get_wide_byte
        # ====================================================================
        elif action == "read_struct":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. "
                                  "Provide the memory address where the struct is located.")
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name (struct name) required. "
                                  "Provide the name of a known struct type (e.g., '_IMAGE_DOS_HEADER').")

            ea = parse_address(addr)
            if ea == idaapi.BADADDR:
                return make_error(MCPError.INVALID_ARGS, f"Invalid address: {addr}")
            if not ida_bytes.is_loaded(ea):
                return make_error(MCPError.INVALID_ARGS, f"Address {hex(ea)} is not loaded in memory. "
                                  "The address may be in an unmapped region or the binary is not fully loaded.")

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(name, tif):
                return make_error(MCPError.TYPE_ERROR, f"Struct '{name}' not found in type library. "
                                  "Use 'list' to find available structs or 'import_header' to load from a C header.")

            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return make_error(MCPError.TYPE_ERROR, f"'{name}' is not a struct/union type. "
                                  "Use 'get' action to inspect the type or choose a different name.")
            struct_size = int(tif.get_size())
            if struct_size < 0:
                return make_error(MCPError.TYPE_ERROR, f"Failed to determine size for '{name}'.")
            if not _is_fully_mapped(ea, struct_size):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Struct range exceeds mapped segment bounds",
                    hint=f"Requested {name} ({struct_size} bytes) at {hex(ea)} is partially unmapped.",
                )

            # Determine pointer size from the database
            is_64 = hasattr(idaapi, 'inf_is_64bit') and _inf_is_64bit()
            ptr_size = 8 if is_64 else 4

            members = []
            for i in range(udt.size()):
                m = udt[i]
                field_offset = m.offset // 8
                mem_addr = ea + field_offset
                str(m.type)
                mem_size = m.type.get_size()

                val_str = "?"
                try:
                    if m.type.is_ptr():
                        val = ida_bytes.get_qword(mem_addr) if ptr_size == 8 else ida_bytes.get_dword(mem_addr)
                        val_str = hex(val)
                    elif mem_size == 1:
                        val = ida_bytes.get_byte(mem_addr)
                        val_str = hex(val)
                    elif mem_size == 2:
                        val = ida_bytes.get_word(mem_addr)
                        val_str = hex(val)
                    elif mem_size == 4:
                        val = ida_bytes.get_dword(mem_addr)
                        val_str = hex(val)
                    elif mem_size == 8:
                        val = ida_bytes.get_qword(mem_addr)
                        val_str = hex(val)
                    elif 0 < mem_size <= 256:
                        raw = ida_bytes.get_bytes(mem_addr, mem_size)
                        if raw:
                            if isinstance(raw, bytes) and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                                val_str = repr(raw.decode('utf-8', errors='replace'))
                            elif isinstance(raw, bytes):
                                val_str = raw.hex()[:64] + ("..." if len(raw) > 32 else "")
                            else:
                                val_str = repr(str(raw))
                        else:
                            val_str = f"[{mem_size} bytes]"
                    else:
                        val_str = f"[{mem_size} bytes]"
                except Exception:
                    val_str = "?(read error)"

                members.append({
                    "name": m.name,
                    "offset": int(field_offset),
                    "size": mem_size,
                    "value": val_str,
                })

            return {
                "ok": True,
                "addr": hex(ea),
                "type_name": name,
                "fields": members,
                "struct_size": struct_size,
            }

        # ====================================================================
        # NEW: diff - Compare two types and show field-level differences
        # ====================================================================
        elif action == "diff":
            if not name or not other_name:
                return make_error(MCPError.INVALID_ARGS, "name and other_name required. "
                                  "Provide two type names to compare (e.g., name='OldStruct', other_name='NewStruct').")

            tif_a = ida_typeinf.tinfo_t()
            tif_b = ida_typeinf.tinfo_t()

            if not _resolve_type_by_name(name, tif_a):
                return make_error(MCPError.TYPE_ERROR, f"Type '{name}' not found. Use 'list' to see available types.")
            if not _resolve_type_by_name(other_name, tif_b):
                return make_error(MCPError.TYPE_ERROR, f"Type '{other_name}' not found. Use 'list' to see available types.")

            result = {
                "ok": True,
                "type_a": {"name": name, "size": tif_a.get_size(), "kind": _type_kind(tif_a)},
                "type_b": {"name": other_name, "size": tif_b.get_size(), "kind": _type_kind(tif_b)},
            }

            # Struct/union comparison
            if (tif_a.is_struct() or tif_a.is_union()) and (tif_b.is_struct() or tif_b.is_union()):
                udt_a = ida_typeinf.udt_type_data_t()
                udt_b = ida_typeinf.udt_type_data_t()

                if tif_a.get_udt_details(udt_a) and tif_b.get_udt_details(udt_b):
                    fields_a = {}
                    for m in udt_a:
                        if not m.is_gap() and m.name:
                            fields_a[m.name] = {
                                "offset": m.offset // 8,
                                "type": str(m.type),
                                "size": m.type.get_size(),
                            }
                    fields_b = {}
                    for m in udt_b:
                        if not m.is_gap() and m.name:
                            fields_b[m.name] = {
                                "offset": m.offset // 8,
                                "type": str(m.type),
                                "size": m.type.get_size(),
                            }

                    names_a = set(fields_a.keys())
                    names_b = set(fields_b.keys())
                    common = names_a & names_b
                    only_a = names_a - names_b
                    only_b = names_b - names_a

                    changed = []
                    for field_name in sorted(common):
                        fa = fields_a[field_name]
                        fb = fields_b[field_name]
                        diffs = {}
                        if fa["offset"] != fb["offset"]:
                            diffs["offset"] = {"a": fa["offset"], "b": fb["offset"]}
                        if fa["type"] != fb["type"]:
                            diffs["type"] = {"a": fa["type"], "b": fb["type"]}
                        if fa["size"] != fb["size"]:
                            diffs["size"] = {"a": fa["size"], "b": fb["size"]}
                        if diffs:
                            changed.append({"field": field_name, "differences": diffs})

                    result["field_changes"] = changed
                    result["fields_added"] = sorted(
                        [{"name": f, **fields_b[f]} for f in only_b], key=lambda x: x["offset"]
                    )
                    result["fields_removed"] = sorted(
                        [{"name": f, **fields_a[f]} for f in only_a], key=lambda x: x["offset"]
                    )
                    result["summary"] = {
                        "common_fields": len(common),
                        "changed_fields": len(changed),
                        "fields_added": len(only_b),
                        "fields_removed": len(only_a),
                        "size_change": tif_b.get_size() - tif_a.get_size(),
                    }
                else:
                    result["error"] = "Failed to retrieve struct member details for comparison."

            # Enum comparison
            elif tif_a.is_enum() and tif_b.is_enum():
                ei_a = ida_typeinf.enum_type_data_t()
                ei_b = ida_typeinf.enum_type_data_t()

                if tif_a.get_enum_details(ei_a) and tif_b.get_enum_details(ei_b):
                    members_a = {e.name: e.value for e in ei_a}
                    members_b = {e.name: e.value for e in ei_b}

                    names_a = set(members_a.keys())
                    names_b = set(members_b.keys())
                    common = names_a & names_b
                    only_a = names_a - names_b
                    only_b = names_b - names_a

                    changed = []
                    for enum_name in sorted(common):
                        if members_a[enum_name] != members_b[enum_name]:
                            changed.append({
                                "name": enum_name,
                                "value_a": members_a[enum_name],
                                "value_b": members_b[enum_name],
                            })

                    result["value_changes"] = changed
                    result["values_added"] = sorted(
                        [{"name": n, "value": members_b[n]} for n in only_b], key=lambda x: x["name"]
                    )
                    result["values_removed"] = sorted(
                        [{"name": n, "value": members_a[n]} for n in only_a], key=lambda x: x["name"]
                    )
                    result["summary"] = {
                        "common_values": len(common),
                        "changed_values": len(changed),
                        "values_added": len(only_b),
                        "values_removed": len(only_a),
                    }
                else:
                    result["error"] = "Failed to retrieve enum member details for comparison."
            else:
                # Cross-kind comparison
                result["type_mismatch"] = True
                result["note"] = f"Types have different kinds: '{_type_kind(tif_a)}' vs '{_type_kind(tif_b)}'"

            return result

        # ====================================================================
        # NEW: visualize - Visual/textual struct layout with offsets and sizes
        # ====================================================================
        elif action == "visualize":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required. "
                                  "Provide the struct/union name to visualize.")

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(name, tif):
                return make_error(MCPError.TYPE_ERROR, f"Type '{name}' not found. Use 'list' to see available types.")

            if not (tif.is_struct() or tif.is_union()):
                return make_error(MCPError.INVALID_ARGS, f"'{name}' is not a struct or union type. "
                                  "Visualization only supports struct/union types.")

            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return make_error(MCPError.TYPE_ERROR, f"Failed to retrieve struct details for '{name}'.")

            is_union = tif.is_union()
            total_size = tif.get_size()

            # Build human-readable visual representation
            lines = []
            kind_label = "UNION" if is_union else "STRUCT"
            header = f"{kind_label} {name} ({total_size} bytes)"
            lines.append(header)
            lines.append("=" * len(header))

            for m in udt:
                field_offset = m.offset // 8
                field_size = m.type.get_size()
                field_end = field_offset + max(field_size, 0)
                field_type = str(m.type)
                field_name = m.name if m.name else "(gap)" if m.is_gap() else "(unnamed)"

                if is_union:
                    lines.append(f"  [{field_type:<30}]  {field_name:<20}  ({field_size} bytes)")
                else:
                    offset_str = f"{field_offset:3d}-{field_end - 1:3d}"
                    bar_marker = "#" if m.is_gap() else " "
                    "|" + bar_marker * max(field_size, 1)
                    lines.append(f"  {offset_str}  [{field_type:<30}]  {field_name:<20}  ({field_size} bytes)")

            if not is_union:
                lines.append("=" * len(header))
                lines.append(f"  Total: {total_size} bytes")

            # Build structured field list
            fields_repr = []
            for m in udt:
                field_offset = m.offset // 8
                field_size = m.type.get_size()
                field_end = field_offset + max(field_size, 0)
                fields_repr.append({
                    "name": m.name if m.name else ("(gap)" if m.is_gap() else "(unnamed)"),
                    "offset": field_offset,
                    "offset_hex": hex(field_offset),
                    "end_offset": field_end,
                    "end_offset_hex": hex(field_end),
                    "size": field_size,
                    "type": str(m.type),
                    "is_gap": m.is_gap(),
                })

            return {
                "ok": True,
                "name": name,
                "kind": "union" if is_union else "struct",
                "size": total_size,
                "visual": "\n".join(lines),
                "fields": fields_repr,
                "total_fields": len(fields_repr),
            }

        # ====================================================================
        # NEW: propagate - Propagate a type from addr to all xref locations
        # ====================================================================
        elif action == "propagate":
            seed_addr = kwargs.get("seed_addr") or addr
            type_name = kwargs.get("type_name") or name
            if not seed_addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. "
                                  "Provide the address whose type should be propagated to all xref locations.")
            if not type_name:
                return make_error(MCPError.INVALID_ARGS, "name (type name) required. "
                                  "Provide the type name to apply at all referencing locations.")

            ea, err = validate_addr(str(seed_addr))
            if err:
                return err

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(str(type_name), tif):
                return make_error(MCPError.TYPE_ERROR, f"Type '{type_name}' not found. Use 'list' to see available types.")

            # Collect code + data xrefs TO the given address.
            locations = []
            seen = set()
            MAX_XREFS = 5000

            for xref in idautils.XrefsTo(ea, 0):
                if len(locations) >= MAX_XREFS:
                    break
                frm = int(getattr(xref, "frm", xref))
                xref_type = int(getattr(xref, "type", 0) or 0)
                key = (frm, xref_type)
                if key in seen:
                    continue
                seen.add(key)
                is_code_xref = bool(getattr(xref, "iscode", False))

                loc_info = {
                    "from": frm,
                    "from_hex": hex(frm),
                    "xref_kind": "code" if is_code_xref else "data",
                    "xref_type": xref_type,
                }

                # Best-effort type propagation at the xref origin.
                try:
                    if ida_typeinf.apply_tinfo(frm, tif, ida_typeinf.TINFO_DEFINITE):
                        loc_info["applied"] = True
                        loc_info["status"] = "applied"
                    else:
                        loc_info["applied"] = False
                        loc_info["status"] = "skipped"
                        loc_info["reason"] = "apply_tinfo failed (incompatible type or address not writable)"
                except Exception as e:
                    loc_info["applied"] = False
                    loc_info["status"] = "error"
                    loc_info["reason"] = str(e)

                locations.append(loc_info)

            applied_count = sum(1 for loc in locations if loc.get("applied"))
            failed_count = len(locations) - applied_count

            return {
                "ok": True,
                "source_addr": hex(ea),
                "type": str(type_name),
                "type_str": str(tif),
                "type_size": tif.get_size(),
                "propagated_to": [loc["from_hex"] for loc in locations if loc.get("applied")],
                "skipped": int(failed_count),
                "total_xrefs": len(locations),
                "locations": locations[:200],
            }

        # ====================================================================
        # NEW: enum_values - List enum values with optional value lookup
        # ====================================================================
        elif action == "enum_values":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required. "
                                  "Provide the enum type name to inspect.")

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(name, tif):
                return make_error(MCPError.TYPE_ERROR, f"Enum '{name}' not found. Use 'list' to see available types.")

            if not tif.is_enum():
                return make_error(MCPError.INVALID_ARGS, f"'{name}' is not an enum type. "
                                  "Use 'get' to inspect any type, or 'list' to browse available types.")

            ei = ida_typeinf.enum_type_data_t()
            if not tif.get_enum_details(ei):
                return make_error(MCPError.TYPE_ERROR, f"Failed to retrieve enum details for '{name}'.")

            value_map = {}
            all_members = []

            for e in ei:
                entry = {
                    "name": e.name,
                    "value": e.value,
                    "value_hex": hex(e.value) if e.value >= 0 else hex(e.value & ((1 << 64) - 1)),
                }
                all_members.append(entry)
                if e.value not in value_map:
                    value_map[e.value] = []
                value_map[e.value].append(e.name)

            result = {
                "ok": True,
                "name": name,
                "size": tif.get_size(),
                "total_members": len(all_members),
                "members": all_members,
                "value_map": value_map,
            }

            # Optional: look up a specific value
            if value is not None:
                if value in value_map:
                    result["value_lookup"] = {
                        "value": value,
                        "value_hex": hex(value) if value >= 0 else hex(value & ((1 << 64) - 1)),
                        "names": value_map[value],
                        "match_type": "exact",
                    }
                else:
                    # Attempt bitmask decomposition
                    matched_names = []
                    remaining = value
                    sorted_vals = sorted(
                        (v for v in value_map if v != 0), key=lambda x: -x
                    )
                    for v in sorted_vals:
                        if (remaining & v) == v:
                            matched_names.extend(value_map[v])
                            remaining &= ~v

                    if matched_names:
                        match_type = "bitmask" if remaining == 0 else "partial_bitmask"
                        result["value_lookup"] = {
                            "value": value,
                            "value_hex": hex(value) if value >= 0 else hex(value & ((1 << 64) - 1)),
                            "names": matched_names,
                            "remaining_bits": remaining,
                            "match_type": match_type,
                        }
                    else:
                        result["value_lookup"] = {
                            "value": value,
                            "value_hex": hex(value) if value >= 0 else hex(value & ((1 << 64) - 1)),
                            "names": [],
                            "match_type": "no_match",
                        }

            return result

        # ====================================================================
        # NEW: type_graph - Build struct dependency graph
        # ====================================================================
        elif action == "type_graph":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required. "
                                  "Provide the root struct name to build a dependency graph from.")

            tif = ida_typeinf.tinfo_t()
            if not _resolve_type_by_name(name, tif):
                return make_error(MCPError.TYPE_ERROR, f"Type '{name}' not found. Use 'list' to see available types.")

            if not (tif.is_struct() or tif.is_union()):
                return make_error(MCPError.INVALID_ARGS, f"'{name}' is not a struct/union type. "
                                  "type_graph only supports struct and union types.")

            visited = set()
            graph_nodes = []
            graph_edges = []

            def _resolve_deps(type_name: str, current_depth: int) -> None:
                """Recursively resolve struct references within a type."""
                if type_name in visited or current_depth > max_depth:
                    return
                visited.add(type_name)

                node_tif = ida_typeinf.tinfo_t()
                if not _resolve_type_by_name(type_name, node_tif):
                    return

                if not (node_tif.is_struct() or node_tif.is_union()):
                    return

                graph_nodes.append({
                    "name": type_name,
                    "kind": "union" if node_tif.is_union() else "struct",
                    "size": node_tif.get_size(),
                    "depth": current_depth,
                })

                udt = ida_typeinf.udt_type_data_t()
                if not node_tif.get_udt_details(udt):
                    return

                for m in udt:
                    if m.is_gap() or not m.name:
                        continue

                    dep_name = _extract_struct_name(m.type)
                    if dep_name and dep_name != type_name:
                        edge = {"from": type_name, "to": dep_name, "field": m.name}
                        if edge not in graph_edges:
                            graph_edges.append(edge)
                        _resolve_deps(dep_name, current_depth + 1)

            _resolve_deps(name, 0)

            # Build text representation
            text_lines = [f"Type Dependency Graph for '{name}'", "=" * 50]
            if not graph_nodes:
                text_lines.append("(no dependent structs found)")
            else:
                adj = {}
                for e in graph_edges:
                    adj.setdefault(e["from"], []).append(e)

                def _print_deps(node_name: str, indent: int) -> None:
                    text_lines.append(f"{'  ' * indent}- {node_name}")
                    for e in adj.get(node_name, []):
                        text_lines.append(f"{'  ' * (indent + 1)}via field '{e['field']}' -> ")
                        _print_deps(e["to"], indent + 2)

                _print_deps(name, 1)

            return {
                "ok": True,
                "root": name,
                "nodes": graph_nodes,
                "edges": graph_edges,
                "total_structs": len(graph_nodes),
                "total_edges": len(graph_edges),
                "max_depth": max_depth,
                "visual": "\n".join(text_lines),
            }

        # ====================================================================
        # vtable - Find and dump a C++ vtable by class name or address
        # ====================================================================
        elif action == "vtable":
            if not name and not addr:
                return make_error(MCPError.INVALID_ARGS,
                                  "name or addr required. Provide class name (e.g. 'SystemKloProxy') "
                                  "or vtable address (e.g. '_ZTVN7android14SystemKloProxyE').")
            # Resolve vtable address from name or addr
            vtable_ea = None
            vtable_name = None
            if addr:
                vtable_ea, error = validate_addr(addr)
                if error:
                    return error
                vtable_name = idc.get_name(vtable_ea) or addr
            else:
                # Search for vtable symbol by class name
                clean_name = name.strip()
                mangled_vtable = f"_ZTVN{len(clean_name)}{clean_name}E"
                # Try demangled form: "vtable for ClassName"
                fangled_forms = [
                    mangled_vtable,
                    f"vtable for {clean_name}",
                    clean_name,
                ]
                for form in fangled_forms:
                    ea = idc.get_name_ea_simple(form)
                    if ea != idaapi.BADADDR:
                        vtable_ea = ea
                        vtable_name = form
                        break
                if vtable_ea is None:
                    # Scan all names for partial match
                    for ea, n in idautils.Names():
                        if clean_name.lower() in n.lower() and ("_ZTV" in n or "vtable" in n.lower()):
                            vtable_ea = ea
                            vtable_name = n
                            break
            if vtable_ea is None:
                return make_error(MCPError.NOT_FOUND,
                                  f"No vtable found for '{name or addr}'. "
                                  "Try the mangled name (e.g. '_ZTVN7android14SystemKloProxyE').")

            # Determine pointer size
            ptr_size = 8 if _inf_is_64bit() else 4
            # Read vtable entries: each entry is a pointer to a virtual function
            entries = []
            cur = vtable_ea
            idx = 0
            max_entries = 64  # safety cap
            seen_targets = set()
            while idx < max_entries:
                raw = ida_bytes.get_bytes(cur, ptr_size)
                if not raw or len(raw) < ptr_size:
                    break
                import struct
                fmt = "<Q" if ptr_size == 8 else "<I"
                target = struct.unpack(fmt, raw)[0]
                if target == 0:
                    break
                if not ida_bytes.is_loaded(target):
                    break
                if target in seen_targets:
                    break
                seen_targets.add(target)
                func = idaapi.get_func(target)
                func_name = idc.get_name(target) or ""
                demangled = func_name
                try:
                    import ida_nalt
                    demangled = ida_nalt.demangle_name(func_name, ida_nalt.get_short_name_synonym()) or func_name
                    # Strip parameters for readability: "Class::method(int)" -> "Class::method"
                    if "(" in demangled:
                        demangled = demangled[:demangled.index("(")].strip()
                except Exception:
                    pass
                func_size = 0
                if func:
                    func_size = int(func.end_ea - func.start_ea)
                entries.append({
                    "index": idx,
                    "addr": hex(target),
                    "name": demangled,
                    "mangled": func_name,
                    "size": func_size,
                })
                cur += ptr_size
                idx += 1

            if not entries:
                return {"ok": True, "vtable_addr": hex(vtable_ea), "name": vtable_name,
                        "entries": [], "count": 0,
                        "note": "Vtable found but no valid function pointers detected."}

            return {
                "ok": True,
                "vtable_addr": hex(vtable_ea),
                "name": vtable_name,
                "class": clean_name if name else idc.get_name(vtable_ea) or "",
                "entries": entries,
                "count": len(entries),
                "vtable": "\n".join(
                    f"  [{e['index']}] {e['addr']}  {e['name']}" for e in entries
                ),
            }

        # ====================================================================
        # Unknown action
        # ====================================================================
        else:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown action: '{action}'. "
                f"Supported actions: list|get|set_prototype|parse_decl|declare|apply|"
                f"search_structs|infer|read_struct|import_header|diff|visualize|"
                f"propagate|enum_values|type_graph|vtable",
            )

    except Exception as e:
        return handle_error(e)


# ============================================================================
# Helper functions for types.py
# ============================================================================


def _resolve_type_by_name(type_name: str, tif: ida_typeinf.tinfo_t) -> bool:
    """Resolve a type by name into a tinfo_t object.

    Tries direct named lookup first (IDA 7+), then falls back to TID-based
    lookup (IDA 9+). Returns True if the type was successfully resolved.
    """
    if tif.get_named_type(None, type_name):
        return True
    tid = ida_typeinf.get_named_type_tid(type_name)
    return bool(tid != idaapi.BADADDR and tif.get_type_by_tid(tid))


def _type_kind(tif: ida_typeinf.tinfo_t) -> str:
    """Return a human-readable kind string for a tinfo_t."""
    if tif.is_union():
        return "union"
    if tif.is_struct():
        return "struct"
    if tif.is_enum():
        return "enum"
    if tif.is_func():
        return "function"
    if tif.is_typedef():
        return "typedef"
    if tif.is_ptr():
        return "pointer"
    if tif.is_array():
        return "array"
    return "other"


def _extract_struct_name(tif: ida_typeinf.tinfo_t) -> Optional[str]:
    """Extract the name of a struct/union type referenced by a tinfo_t.

    Unwraps pointers and arrays to find the underlying named struct/union.
    Returns None if the type does not ultimately reference a struct/union.
    """
    # Unwrap pointers and arrays to find the base struct
    while tif.is_ptr() or tif.is_array():
        if tif.is_ptr():
            tif = tif.get_pointed_object()
        elif tif.is_array():
            tif = tif.get_array_element()
        if tif is None:
            return None

    if tif.is_struct() or tif.is_union():
        return tif.get_type_name()
    return None
