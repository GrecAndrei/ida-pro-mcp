
from __future__ import annotations

import os

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

# ida_struct is the classic IDA 7/8 struct-editing module (add_struc_member,
# del_struc_member, set_member_name, set_member_tinfo). IDA 9 merged it into
# ida_typeinf and no longer ships an `ida_struct` module, so its absence is
# expected there — the per-member helpers fall back to tinfo_t methods.
try:
    import ida_struct
except ImportError:
    ida_struct = None  # type: ignore[assignment]

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
        seg = _compat.get_segment(start)
        return bool(seg) and int(end) < int(seg.end_ea)
    except Exception:
        return False


def _is_data_location(ea: int) -> bool:
    """True when ``ea`` resolves to a standalone data item (never code).

    Used by type propagation to decide whether an xref origin is a safe place
    to apply a type: an address inside a function (code) is never a data item,
    and an undefined location has no data flags to type. Only genuine data
    items qualify.
    """
    try:
        if _compat.get_func_start(ea) is not None:
            return False
        flags = ida_bytes.get_flags(ea)
        if not flags:
            return False
        return bool(ida_bytes.is_data(flags))
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
                              "diff", "visualize", "propagate", "enum_values", "type_graph", "vtable",
                              "struct_member_add", "struct_member_del", "struct_member_rename",
                              "struct_member_set_type", "enum_member_add", "enum_member_rename",
                              "enum_member_revalue", "til_delete", "til_export", "til_import"],
                      "Action: list|get|set_prototype|parse_decl|declare|apply|search_structs|"
                      "infer|read_struct|import_header|diff|visualize|propagate|enum_values|type_graph|vtable|"
                      "struct_member_add|struct_member_del|struct_member_rename|struct_member_set_type|"
                      "enum_member_add|enum_member_rename|enum_member_revalue|til_delete|til_export|til_import"],
    name: Annotated[Optional[str], "Type name (or variable name for apply)"] = None,
    addr: Annotated[Optional[str], "Address (for set_prototype/apply/infer/read_struct)"] = None,
    decl: Annotated[Optional[str], "Type declaration string (or header content)"] = None,
    query: Annotated[Optional[str], "Search query (regex/glob/substring/semantic; for list/search_structs)"] = None,
    kind: Annotated[Optional[str], "Apply kind: function, global, local"] = None,
    offset: Annotated[int, "Pagination offset (or member byte offset for struct_member_add; -1 appends)"] = 0,
    count: Annotated[int, "Maximum items to return"] = 100,
    # Extended action parameters
    other_name: Annotated[Optional[str], "Second type name (for diff)"] = None,
    value: Annotated[Optional[int], "Enum value to look up (for enum_values) or enum member value (for enum_member_*)"] = None,
    max_depth: Annotated[int, "Maximum recursion depth for type_graph"] = 5,
    # Per-member struct/enum editing + TIL carry parameters
    struct_name: Annotated[Optional[str], "Struct type name (struct_member_* actions)"] = None,
    member_name: Annotated[Optional[str], "Member/enumerator name (struct_member_*/enum_member_* actions)"] = None,
    new_name: Annotated[Optional[str], "Replacement name (struct_member_rename / enum_member_rename)"] = None,
    type_str: Annotated[Optional[str], "C type string (struct_member_add / struct_member_set_type)"] = None,
    size: Annotated[Optional[int], "Member size in bytes (struct_member_add when type_str is omitted)"] = None,
    enum_name: Annotated[Optional[str], "Enum type name (enum_member_* actions)"] = None,
    enum_value: Annotated[Optional[int], "Enum member value (enum_member_add / enum_member_revalue)"] = None,
    path: Annotated[Optional[str], "TIL file path (til_export / til_import)"] = None,
    til_filter: Annotated[Optional[str], "Type-name filter for til_export (default '*')"] = None,
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
    - struct_member_add:       Add a member to a struct (struct_name + member_name + offset, type_str or size).
    - struct_member_del:       Delete a member from a struct by name.
    - struct_member_rename:    Rename a struct member.
    - struct_member_set_type:  Retype a struct member from a C type string.
    - enum_member_add:         Add an enumerator (enum_name + member_name + value).
    - enum_member_rename:      Rename an enumerator.
    - enum_member_revalue:     Revalue an enumerator (new numeric value).
    - til_delete:              Delete a named type from the local Type Library (TIL).
    - til_export:              Export matching named types as a C header file (cross-session carry).
    - til_import:              Import a C header file into the local Type Library.

    Arguments:
    - name:       Type name, or variable name when applying types.
    - addr:       Target address.
    - decl:       C declaration string or header content.
    - query:      Name filter for 'list' or field filter for 'search_structs'.
    - offset/count: Pagination controls for 'list'; offset is the member byte offset for
                   'struct_member_add' (-1 appends at the end).
    - other_name: Second type name for 'diff' action.
    - value:      Enum numeric value to look up (for 'enum_values').
    - max_depth:  Max recursion depth for 'type_graph' (default 5).
    - struct_name: Struct type name (struct_member_* actions).
    - member_name: Member/enumerator name (struct_member_*/enum_member_* actions).
    - new_name:    Replacement name for the *_rename actions.
    - type_str:    C type string for struct_member_add / struct_member_set_type.
    - size:        Member size in bytes for struct_member_add when type_str is omitted.
    - enum_name:   Enum type name (enum_member_* actions).
    - enum_value:  Enum member value for enum_member_add / enum_member_revalue.
    - path:        TIL file path for til_export / til_import.
    - til_filter:  Type-name filter for til_export (default '*').
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
            if result is None and not decl.rstrip().endswith(";"):
                # C declarations end with ';'; LLM callers routinely drop it.
                tif = ida_typeinf.tinfo_t()
                result = ida_typeinf.parse_decl(tif, til, decl + ";", ida_typeinf.PT_TYP)
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
            saved = False
            try:
                saved = bool(ida_typeinf.set_numbered_type(til, ordinal, ida_typeinf.NTF_TYPE, type_name, tif))
            except Exception:
                # IDA 9.4 binding changed the type argument to serialized
                # bytes (verified live); use the tinfo method form instead.
                try:
                    tif.set_named_type(til, type_name, ida_typeinf.NTF_TYPE)
                except Exception as e:
                    return make_error(MCPError.IDA_ERROR, f"Failed to save type '{type_name}': {e}")
            # set_named_type may return falsy while still creating the type
            # (observed on 9.4); verify by lookup rather than trusting the
            # return value.
            if not saved:
                try:
                    check = ida_typeinf.get_named_type(til, type_name, ida_typeinf.NTF_TYPE)
                    saved = bool(check)
                    if saved:
                        try:
                            ordinal = check.get_ordinal() or ordinal
                        except Exception:
                            pass
                except Exception:
                    saved = False
            if saved:
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
                # Prototype parsing needs the trailing ';' (PT_SIL rejects
                # 'int foo(int a)' without it on IDA 9.x — verified live);
                # LLM callers routinely drop it, so retry once with it.
                tif = ida_typeinf.tinfo_t()
                if decl.rstrip().endswith(";") or not ida_typeinf.parse_decl(
                    tif, None, decl + ";", ida_typeinf.PT_SIL
                ):
                    return make_error(MCPError.INVALID_ARGS, f"Failed to parse type: '{decl}'. "
                                      "Check C syntax and ensure all referenced types exist.")

            apply_kind = kind
            func = _compat.get_func_start(ea)

            if not apply_kind:
                apply_kind = "function" if func is not None and func == ea else "global"

            if apply_kind not in ("function", "global", "local"):
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Invalid apply kind '{apply_kind}'. Supported kinds: function, global, local.",
                )

            if apply_kind == "function":
                if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return make_error(MCPError.IDA_ERROR, f"Failed to apply function type at {hex(ea)}. "
                                      "Ensure the address is a valid function start.")

            elif apply_kind == "local":
                if not name:
                    return make_error(MCPError.INVALID_ARGS, "name required for local variable. "
                                      "Provide the local variable name as it appears in the decompiler.")
                if func is None:
                    return make_error(MCPError.FUNCTION_NOT_FOUND, f"Address {hex(ea)} is not inside a function. "
                                      "For local variables, addr must be within a recognized function.")

                try:
                    cfunc = ida_hexrays.decompile(func)
                    if not cfunc:
                        return make_error(MCPError.IDA_ERROR, f"Decompilation failed at {hex(func)}. "
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
                    if ida_hexrays.modify_user_lvars(func, modifier):
                        refresh_decompiler_ctext(func)
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

            # Scan the whole TIL once so `total` is accurate, then paginate the
            # collected matches with offset/count (offset is not a scan window).
            max_types = max(1, qty_func(None))
            for ordinal in range(1, max_types + 1):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and (tif.is_struct() or tif.is_union()):
                    type_name = tif.get_type_name()
                    # Anonymous structs/unions have no name (get_type_name returns
                    # None); the smart-pattern matcher cannot handle None, so only
                    # match named types here. Same guard applies to unnamed members.
                    if type_name and matcher(type_name):
                        matches.append({"name": type_name, "ordinal": ordinal, "match": "name"})
                        continue

                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for i in range(udt.size()):
                            m = udt[i]
                            if m.name and matcher(m.name):
                                matches.append({
                                    "name": type_name,
                                    "ordinal": ordinal,
                                    "match": "field",
                                    "field": m.name,
                                })
                                break
            total = len(matches)
            page = matches[offset:] if count == 0 else matches[offset:offset + count]
            return {"ok": True, "matches": page, "total": total, "offset": offset, "count": len(page)}

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
                fn = _compat.get_func_info(ea)
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
            return {"ok": True, "addr": addr, "inferred_types": inferred_types, "confidence": round(float(conf), 3)}

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

            # Collect code + data xrefs TO the given address. Code references
            # (call/load/store sites) are recorded without mutating them —
            # applying a data type to an instruction address corrupts the IDB.
            # apply_tinfo runs only at origins that are genuine data items.
            locations = []
            call_sites = []
            seen = set()
            MAX_XREFS = 5000

            for xref in idautils.XrefsTo(ea, 0):
                if len(locations) + len(call_sites) >= MAX_XREFS:
                    break
                frm = int(getattr(xref, "frm", xref))
                xref_type = int(getattr(xref, "type", 0) or 0)
                key = (frm, xref_type)
                if key in seen:
                    continue
                seen.add(key)
                is_code_xref = bool(getattr(xref, "iscode", False))

                base_info = {
                    "from": frm,
                    "from_hex": hex(frm),
                    "xref_kind": "code" if is_code_xref else "data",
                    "xref_type": xref_type,
                }

                if is_code_xref:
                    # Code origin: never mutate — record it as a call site.
                    func = _compat.get_func_start(frm)
                    base_info["func"] = hex(func) if func is not None else ""
                    base_info["func_name"] = ida_funcs.get_func_name(func) if func is not None else ""
                    base_info["status"] = "referenced"
                    call_sites.append(base_info)
                    continue

                # Data origin: apply only when it is a genuine data item.
                if not _is_data_location(frm):
                    base_info["applied"] = False
                    base_info["status"] = "skipped"
                    base_info["reason"] = "xref origin is not a data item (code or undefined)"
                    locations.append(base_info)
                    continue

                try:
                    if ida_typeinf.apply_tinfo(frm, tif, ida_typeinf.TINFO_DEFINITE):
                        base_info["applied"] = True
                        base_info["status"] = "applied"
                    else:
                        base_info["applied"] = False
                        base_info["status"] = "skipped"
                        base_info["reason"] = "apply_tinfo failed (incompatible type or address not writable)"
                except Exception as e:
                    base_info["applied"] = False
                    base_info["status"] = "error"
                    base_info["reason"] = str(e)
                locations.append(base_info)

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
                "total_xrefs": len(locations) + len(call_sites),
                "locations": locations[:200],
                "call_sites": call_sites[:200],
                "note": ("Type applied only at data-xref origins that resolve to a data item; "
                         "code references are recorded in call_sites without mutation."),
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
                # Respect database endianness — hardcoding little-endian swaps
                # every pointer on big-endian targets (PPC, big-endian MIPS/ARM).
                endian = ">" if _inf_is_be() else "<"
                fmt = f"{endian}Q" if ptr_size == 8 else f"{endian}I"
                target = struct.unpack(fmt, raw)[0]
                if target == 0:
                    break
                if not ida_bytes.is_loaded(target):
                    break
                # A vtable can legitimately point several slots at the same
                # implementation (multiple interfaces collapsing to one method),
                # so a repeated target does NOT end the vtable — skip it and keep
                # scanning. Only a self-referential entry (pointer back to the
                # vtable base) marks the end of the meaningful run.
                if target == vtable_ea:
                    break
                if target in seen_targets:
                    cur += ptr_size
                    idx += 1
                    continue
                seen_targets.add(target)
                func = _compat.get_func_info(target)
                func_name = idc.get_name(target) or ""
                demangled = func_name
                # ida_nalt.demangle_name / get_short_name_synonym are absent or
                # wrong-arity on IDA 9; idc.demangle_name(name, disable_mask)
                # is the portable API (same idiom as search/unified.py).
                try:
                    typeinf = idc.get_inf_attr(idc.INF_SHORT_DN)
                except Exception:
                    typeinf = 0
                try:
                    demangled = idc.demangle_name(func_name, typeinf) or func_name
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
        # struct_member_add - Add a member to a struct
        # ====================================================================
        elif action == "struct_member_add":
            sname, mname = _resolve_struct_names(struct_name, name, member_name)
            if not sname:
                return make_error(MCPError.INVALID_ARGS, "struct_name required. "
                                  "Provide the struct type name to extend.")
            if not mname:
                return make_error(MCPError.INVALID_ARGS, "member_name required. "
                                  "Provide the name of the new member.")
            if not type_str and not size:
                return make_error(MCPError.INVALID_ARGS, "type_str or size required. "
                                  "Provide a C type (e.g. 'uint32_t') or the member size in bytes.")
            tif, err = _struct_tif(sname)
            if err:
                return err
            nbytes, err = _add_struct_member(tif, sname, mname, int(offset), type_str, size)
            if err:
                return err
            return {
                "ok": True,
                "action": "struct_member_add",
                "struct": sname,
                "member": mname,
                "offset": int(offset),
                "type": type_str or f"bytes[{int(size)}]",
                "size": nbytes,
            }

        # ====================================================================
        # struct_member_del - Delete a struct member by name
        # ====================================================================
        elif action == "struct_member_del":
            sname, mname = _resolve_struct_names(struct_name, name, member_name)
            if not sname or not mname:
                return make_error(MCPError.INVALID_ARGS, "struct_name and member_name required. "
                                  "Provide the struct type name and the member to delete.")
            tif, err = _struct_tif(sname)
            if err:
                return err
            moff, err = _del_struct_member(tif, sname, mname)
            if err:
                return err
            return {"ok": True, "action": "struct_member_del", "struct": sname,
                    "member": mname, "offset": moff}

        # ====================================================================
        # struct_member_rename - Rename a struct member
        # ====================================================================
        elif action == "struct_member_rename":
            sname, mname = _resolve_struct_names(struct_name, name, member_name)
            if not sname or not mname or not new_name:
                return make_error(MCPError.INVALID_ARGS, "struct_name, member_name, and new_name required. "
                                  "Provide the struct type, the current member name, and the replacement name.")
            tif, err = _struct_tif(sname)
            if err:
                return err
            moff, err = _rename_struct_member(tif, sname, mname, new_name)
            if err:
                return err
            return {"ok": True, "action": "struct_member_rename", "struct": sname,
                    "old_name": mname, "new_name": new_name, "offset": moff}

        # ====================================================================
        # struct_member_set_type - Retype a struct member from a C type string
        # ====================================================================
        elif action == "struct_member_set_type":
            sname, mname = _resolve_struct_names(struct_name, name, member_name)
            if not sname or not mname or not type_str:
                return make_error(MCPError.INVALID_ARGS, "struct_name, member_name, and type_str required. "
                                  "Provide the struct type, the member name, and the new C type string.")
            tif, err = _struct_tif(sname)
            if err:
                return err
            moff, nbytes, err = _set_struct_member_type(tif, sname, mname, type_str)
            if err:
                return err
            return {"ok": True, "action": "struct_member_set_type", "struct": sname,
                    "member": mname, "type": type_str, "size": nbytes, "offset": moff}

        # ====================================================================
        # enum_member_add - Add an enumerator
        # ====================================================================
        elif action == "enum_member_add":
            ename, mname = _resolve_enum_names(enum_name, name, member_name)
            ev = enum_value if enum_value is not None else value
            if not ename or not mname:
                return make_error(MCPError.INVALID_ARGS, "enum_name and member_name required. "
                                  "Provide the enum type name and the name of the new enumerator.")
            if ev is None:
                return make_error(MCPError.INVALID_ARGS, "enum_value required. "
                                  "Provide the numeric value for the new enumerator.")
            tif, err = _enum_tif(ename)
            if err:
                return err
            err = _add_enum_member(tif, mname, int(ev))
            if err:
                return err
            return {"ok": True, "action": "enum_member_add", "enum": ename,
                    "member": mname, "value": int(ev)}

        # ====================================================================
        # enum_member_rename - Rename an enumerator
        # ====================================================================
        elif action == "enum_member_rename":
            ename, mname = _resolve_enum_names(enum_name, name, member_name)
            if not ename or not mname or not new_name:
                return make_error(MCPError.INVALID_ARGS, "enum_name, member_name, and new_name required. "
                                  "Provide the enum type, the current enumerator name, and the replacement name.")
            tif, err = _enum_tif(ename)
            if err:
                return err
            err = _rename_enum_member(tif, mname, new_name)
            if err:
                return err
            return {"ok": True, "action": "enum_member_rename", "enum": ename,
                    "old_name": mname, "new_name": new_name}

        # ====================================================================
        # enum_member_revalue - Revalue an enumerator
        # ====================================================================
        elif action == "enum_member_revalue":
            ename, mname = _resolve_enum_names(enum_name, name, member_name)
            ev = enum_value if enum_value is not None else value
            if not ename or not mname:
                return make_error(MCPError.INVALID_ARGS, "enum_name and member_name required. "
                                  "Provide the enum type name and the enumerator to revalue.")
            if ev is None:
                return make_error(MCPError.INVALID_ARGS, "enum_value required. "
                                  "Provide the new numeric value for the enumerator.")
            tif, err = _enum_tif(ename)
            if err:
                return err
            err = _revalue_enum_member(tif, mname, int(ev))
            if err:
                return err
            return {"ok": True, "action": "enum_member_revalue", "enum": ename,
                    "member": mname, "value": int(ev)}

        # ====================================================================
        # til_delete - Delete a named type from the local Type Library
        # ====================================================================
        elif action == "til_delete":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required. "
                                  "Provide the name of the type (struct/enum/typedef) to delete from the library.")
            til = ida_typeinf.get_idati()
            if not til:
                return make_error(MCPError.IDA_ERROR, "Type library not available. "
                                  "Ensure IDA has finished initial analysis and a type library is loaded.")
            ntf = getattr(ida_typeinf, "NTF_TYPE", 1)
            if not ida_typeinf.del_named_type(til, name, ntf):
                return make_error(MCPError.TYPE_ERROR, f"Failed to delete type '{name}'. "
                                  "The type may not exist in the local type library.")
            return {"ok": True, "action": "til_delete", "name": name, "deleted": True}

        # ====================================================================
        # til_export - Export matching named types as a C header file
        # ====================================================================
        elif action == "til_export":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required. "
                                  "Provide the file path to write the exported type declarations to.")
            _vp = validate_path_safe(path)
            if _vp is not None:
                path, _verr = _vp
                if _verr:
                    return _verr
            til = ida_typeinf.get_idati()
            if not til:
                return make_error(MCPError.IDA_ERROR, "Type library not available. "
                                  "Ensure IDA has finished initial analysis and a type library is loaded.")
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return make_error(MCPError.IDA_ERROR, "Type ordinal API not available. "
                                  "This IDA version may use a different type enumeration API.")
            # '*' (the default) means "all types"; any other filter is matched
            # with the shared smart matcher (substring/glob per _SMART_MATCH_MODE).
            matcher = compile_smart_pattern(til_filter, case_sensitive=False) \
                if til_filter and til_filter != "*" else None
            lines = ["/* Exported from IDA type library. Import with types(action='til_import'). */", ""]
            exported = []
            total_qty = qty_func(til)
            # PRTYPE_DEF|PRTYPE_MULTI prints the full C declaration; the
            # undocumented SEMI flag (8) adds the terminating ';' so the
            # output parses with idc.parse_decls on import.
            print_flags = 0x20 | 0x1 | 0x8
            for ordinal in range(1, total_qty + 1):
                tif = ida_typeinf.tinfo_t()
                if not tif.get_numbered_type(til, ordinal):
                    continue
                tname = tif.get_type_name()
                if not tname or (matcher is not None and not matcher(tname)):
                    continue
                # typedef aliases (uint32_t, int8_t, ...) exist in every local
                # til; exporting them pollutes the header with non-parsing
                # declaration fragments. Carry real struct/union/enum types.
                try:
                    if tif.is_typedef():
                        continue
                except Exception:
                    pass
                decl_text = ""
                try:
                    decl_text = ida_typeinf.print_tinfo(
                        "", 0, 0, print_flags, tif, tname, ""
                    ).strip()
                except Exception:
                    decl_text = str(tif).strip()
                if not decl_text:
                    continue
                lines.append(decl_text)
                lines.append("")
                exported.append({"name": tname, "ordinal": ordinal})
            content = "\n".join(lines)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                return handle_error(e, context="til_export")
            return {"ok": True, "action": "til_export", "path": path,
                    "exported_count": len(exported), "types": exported}

        # ====================================================================
        # til_import - Import a C header file into the local Type Library
        # ====================================================================
        elif action == "til_import":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required. "
                                  "Provide the path to a C header exported by til_export (or any header).")
            _vp = validate_path_safe(path)
            if _vp is not None:
                path, _verr = _vp
                if _verr:
                    return _verr
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"Type library file not found: {path}")
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                return handle_error(e, context="til_import")
            if not content.strip():
                return make_error(MCPError.INVALID_ARGS, f"Type library file is empty: {path}")
            if content.lstrip().startswith("/* Exported from IDA type library"):
                # Own export format: one declaration per blank-line-separated
                # block. idc.parse_decls silently creates nothing on IDA 9.x
                # (verified live: it reports 0 errors and the til stays
                # unchanged), so each block is parsed with parse_decl and
                # saved with the same named-type path as `declare`.
                import re as _re2
                imported = []
                failed = []
                til = ida_typeinf.get_idati()
                blocks = [
                    b.strip()
                    for b in _re2.split(r"\n\s*\n", content)
                    if b.strip() and not b.lstrip().startswith("/*")
                ]
                for blk in blocks:
                    # "struct\n{\n...\n} Name;" parses back with a generated
                    # hash name; rewrite to "struct Name { ... };" so the
                    # declared name is preserved.
                    m = _re2.fullmatch(r"(struct|union|enum)\s*\n(.*?)\}\s*(\w+)\s*;", blk, _re2.S)
                    if m:
                        blk = f"{m.group(1)} {m.group(3)}\n{m.group(2)}}};\n"
                    tif = ida_typeinf.tinfo_t()
                    parsed = None
                    try:
                        parsed = ida_typeinf.parse_decl(tif, til, blk, ida_typeinf.PT_TYP)
                    except Exception:
                        parsed = None
                    if not parsed:
                        failed.append(blk.splitlines()[0][:60] if blk else blk)
                        continue
                    tname = tif.get_type_name() or parsed
                    try:
                        tif.set_named_type(til, tname, ida_typeinf.NTF_TYPE)
                    except Exception:
                        failed.append(tname)
                        continue
                    imported.append(tname)
                if failed:
                    return make_error(
                        MCPError.TYPE_ERROR,
                        f"Type library import: {len(imported)} type(s) imported, "
                        f"{len(failed)} failed to parse: {', '.join(failed[:5])}",
                        details={"imported": imported, "failed": failed},
                    )
                return {"ok": True, "action": "til_import", "path": path,
                        "status": "Header imported into the local type library",
                        "imported": imported, "errors": 0}
            errors = idc.parse_decls(content, 0)
            if errors == 0:
                return {"ok": True, "action": "til_import", "path": path,
                        "status": "Header imported into the local type library", "errors": 0}
            return make_error(MCPError.TYPE_ERROR, f"Header parsing failed with {errors} errors. "
                              "Check C syntax, ensure all referenced types exist in the type library, "
                              "and avoid trailing semicolons in unexpected places.")

        # ====================================================================
        # Unknown action
        # ====================================================================
        else:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown action: '{action}'. "
                f"Supported actions: list|get|set_prototype|parse_decl|declare|apply|"
                f"search_structs|infer|read_struct|import_header|diff|visualize|"
                f"propagate|enum_values|type_graph|vtable|struct_member_add|struct_member_del|"
                f"struct_member_rename|struct_member_set_type|enum_member_add|enum_member_rename|"
                f"enum_member_revalue|til_delete|til_export|til_import",
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


# ============================================================================
# Per-member struct/enum editing + TIL carry helpers
#
# The member-editing actions are thin wrappers over the classic IDA 7/8
# ida_struct / ida_typeinf module functions (add_struc_member, del_struc_member,
# set_member_name, set_member_tinfo, add_enum_member, set_enum_member_name,
# set_enum_member_value). IDA 9 removed `ida_struct` and the classic enum
# member functions, so each helper also falls back to the tinfo_t methods
# (add_udm/del_udm/rename_udm/set_udm_type, add_edm/rename_edm/del_edm).
# ============================================================================

# Human-readable add_struc_member / del_struc_member / set_member_* error codes.
_STRUC_ERROR_TEXT = {
    -1: "member name already exists or is invalid",
    -2: "invalid member offset (overlaps or out of range)",
    -3: "invalid member size (zero or too small)",
    -4: "invalid member type info",
    -5: "member not found",
    -6: "member already exists",
    -7: "variable-size member not supported",
    -8: "bitfield member not supported",
    -9: "nested structure error",
}


def _struc_error_text(code: int) -> str:
    """Best-effort description of a classic struct-editing error code."""
    return _STRUC_ERROR_TEXT.get(int(code), "unknown error")


def _resolve_struct_names(struct_name: Optional[str], name: Optional[str],
                          member_name: Optional[str]):
    """Resolve the effective (struct_name, member_name) for a struct edit.

    ``struct_name`` is the canonical struct parameter and ``name`` is accepted
    as an alias for it. When ``struct_name`` is given explicitly, the shared
    ``name`` parameter carries the member name (matching the
    struct_member_add(struct_name, name, offset, ...) signature).
    """
    sname = struct_name or name
    if member_name is not None:
        mname = member_name
    elif struct_name is not None:
        mname = name
    else:
        mname = None
    return sname, mname


def _resolve_enum_names(enum_name: Optional[str], name: Optional[str],
                        member_name: Optional[str]):
    """Resolve the effective (enum_name, member_name) for an enum edit.

    Mirrors ``_resolve_struct_names``: ``name`` aliases the enum name, and when
    ``enum_name`` is explicit ``name`` carries the member name (matching the
    enum_member_add(enum_name, name, value) signature).
    """
    ename = enum_name or name
    if member_name is not None:
        mname = member_name
    elif enum_name is not None:
        mname = name
    else:
        mname = None
    return ename, mname


def _struct_tif(struct_name: str):
    """Resolve a struct/union by name to its tinfo_t, or (None, error_dict)."""
    tif = ida_typeinf.tinfo_t()
    if not _resolve_type_by_name(struct_name, tif):
        return None, make_error(MCPError.TYPE_ERROR, f"Struct '{struct_name}' not found in the type library. "
                                 "Use 'list' to browse available types.")
    if not (tif.is_struct() or tif.is_union()):
        return None, make_error(MCPError.INVALID_ARGS, f"'{struct_name}' is not a struct/union type. "
                                 "Use 'get' to inspect any type, or 'list' to browse available types.")
    return tif, None


def _enum_tif(enum_name: str):
    """Resolve an enum by name to its tinfo_t, or (None, error_dict)."""
    tif = ida_typeinf.tinfo_t()
    if not _resolve_type_by_name(enum_name, tif):
        return None, make_error(MCPError.TYPE_ERROR, f"Enum '{enum_name}' not found in the type library. "
                                 "Use 'list' to browse available types.")
    if not tif.is_enum():
        return None, make_error(MCPError.INVALID_ARGS, f"'{enum_name}' is not an enum type. "
                                 "Use 'get' to inspect any type, or 'list' to browse available types.")
    return tif, None


def _struct_sptr(struct_name: str):
    """Best-effort ``struc_t*`` handle for a struct (classic ida_struct path)."""
    sid = None
    try:
        sid = idc.get_struc_id(struct_name)
    except Exception:
        sid = None
    if sid in (None, 0, -1, idaapi.BADADDR):
        try:
            sid = ida_struct.get_struc_id(struct_name)
        except Exception:
            return None
    if sid in (None, 0, -1, idaapi.BADADDR):
        return None
    try:
        return ida_struct.get_struc(sid)
    except Exception:
        return None


def _udt_member(tif: ida_typeinf.tinfo_t, member_name: str):
    """Return ``(index, byte_offset)`` of a named struct/union member, or None."""
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return None
    for i in range(udt.size()):
        m = udt[i]
        if m.name == member_name:
            return i, m.offset // 8
    return None


def _enum_member_index(tif: ida_typeinf.tinfo_t, member_name: str):
    """Return the index of a named enum member, or None."""
    ei = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(ei):
        return None
    for i in range(ei.size()):
        if ei[i].name == member_name:
            return i
    return None


def _parse_member_type(type_str: Optional[str], size: Optional[int]):
    """Build a tinfo_t for a member from type_str (or a raw byte array of `size`).

    Returns ``(tif, None)`` on success or ``(None, error_dict)``.
    """
    decl = type_str or (f"char[{int(size)}]" if size else "")
    if not decl:
        return None, make_error(MCPError.INVALID_ARGS, "type_str or size required. "
                                 "Provide a C type (e.g. 'uint32_t') or the member size in bytes.")
    til = ida_typeinf.get_idati()

    # Primitives (char/int/float/...) are not named types in the til on
    # IDA 9.x and cannot be resolved by get_named_type (verified live); map
    # them to the fixed-width typedefs the local til does carry.
    _PRIMITIVE_ALIASES = {
        "char": "int8_t", "signed char": "int8_t", "unsigned char": "uint8_t",
        "short": "int16_t", "unsigned short": "uint16_t",
        "int": "int32_t", "unsigned int": "uint32_t",
        "long": "int64_t", "unsigned long": "uint64_t",
        "long long": "int64_t", "unsigned long long": "uint64_t",
        "int8": "int8_t", "uint8": "uint8_t", "int16": "int16_t",
        "uint16": "uint16_t", "int32": "int32_t", "uint32": "uint32_t",
        "int64": "int64_t", "uint64": "uint64_t", "size_t": "size_t",
    }

    def _resolve_named(name: str):
        """Resolve a bare type name (uint32_t, struct tag, builtin) to a
        tinfo. On IDA 9.x parse_decl cannot resolve bare type names or
        plain declarations ('int x;' returns empty) — verified live; the
        named-type lookup is the reliable path."""
        for candidate in (name, _PRIMITIVE_ALIASES.get(name)):
            if not candidate:
                continue
            tif = ida_typeinf.tinfo_t()
            try:
                if tif.get_named_type(til, candidate):
                    return tif
            except Exception:
                pass
        return None

    text = decl.strip()
    # Array form: 'uint8_t[16]' / 'char[4]'.
    import re as _re
    arr = _re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]", text)
    if arr:
        base = _resolve_named(arr.group(1))
        if base is not None:
            try:
                arr_tif = ida_typeinf.tinfo_t()
                if arr_tif.create_array(base, int(arr.group(2))):
                    size = arr_tif.get_size()
                    if size > 0 and size == int(arr.group(2)) * base.get_size():
                        return arr_tif, None
            except Exception:
                pass
    # Bare identifier: named-type lookup first, then the signed/unsigned
    # builtin spellings, then the declaration parser.
    ident = text.rstrip(";").strip()
    if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ ]*", ident):
        for cand in (ident, "unsigned " + ident if not ident.startswith(("unsigned", "signed")) else ident):
            tif = _resolve_named(cand)
            if tif is not None and tif.get_size() > 0:
                return tif, None
    # Full declaration form (with a trailing-';' retry).
    tif = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(tif, til, text, ida_typeinf.PT_TYP):
        tif = ida_typeinf.tinfo_t()
        if text.rstrip().endswith(";") or not ida_typeinf.parse_decl(
            tif, til, text + ";", ida_typeinf.PT_TYP
        ):
            return None, make_error(MCPError.INVALID_ARGS, f"Failed to parse member type: '{decl}'. "
                                     "Check C syntax and ensure all referenced types exist in the type library.")
    if tif.get_size() <= 0:
        return None, make_error(MCPError.INVALID_ARGS, f"Could not determine a positive size for member type '{decl}'.")
    return tif, None


def _has_classic_struct_api() -> bool:
    """True when the classic ida_struct module (IDA 7/8) is importable and usable."""
    return ida_struct is not None and hasattr(ida_struct, "add_struc_member")


def _add_struct_member(tif: ida_typeinf.tinfo_t, struct_name: str, member_name: str,
                       offset: int, type_str: Optional[str], size: Optional[int]):
    """Add a member to a struct. Returns ``(nbytes, None)`` or ``(None, error_dict)``."""
    mt, err = _parse_member_type(type_str, size)
    if err:
        return None, err
    nbytes = mt.get_size()
    if _has_classic_struct_api():
        sptr = _struct_sptr(struct_name)
        if sptr is None:
            return None, make_error(MCPError.IDA_ERROR, f"Could not resolve struct handle for '{struct_name}'.")
        res = ida_struct.add_struc_member(sptr, member_name, offset, 0, mt, nbytes)
        if res != 0:
            return None, make_error(MCPError.IDA_ERROR,
                                    f"add_struc_member failed with code {res} ({_struc_error_text(res)}).")
        return nbytes, None
    # IDA 9 tinfo_t path.
    if not hasattr(tif, "add_udm"):
        return None, make_error(MCPError.IDA_ERROR, "No struct member API available on this IDA version.")
    bit_offset = tif.get_size() * 8 if offset < 0 else offset * 8
    try:
        tif.add_udm(member_name, mt, bit_offset)
    except Exception as e:
        return None, make_error(MCPError.IDA_ERROR, f"add_udm failed: {e}")
    return nbytes, None


def _del_struct_member(tif: ida_typeinf.tinfo_t, struct_name: str, member_name: str):
    """Delete a named member from a struct. Returns ``(byte_offset, None)`` or ``(None, error_dict)``."""
    info = _udt_member(tif, member_name)
    if info is None:
        return None, make_error(MCPError.TYPE_ERROR, f"Member '{member_name}' not found in struct '{struct_name}'. "
                                 "Use types(action='get', name='<struct>') to list members.")
    idx, moff = info
    if _has_classic_struct_api():
        sptr = _struct_sptr(struct_name)
        if sptr is None:
            return None, make_error(MCPError.IDA_ERROR, f"Could not resolve struct handle for '{struct_name}'.")
        res = ida_struct.del_struc_member(sptr, moff)
        if res != 0:
            return None, make_error(MCPError.IDA_ERROR,
                                    f"del_struc_member failed with code {res} ({_struc_error_text(res)}).")
        return moff, None
    if not hasattr(tif, "del_udm"):
        return None, make_error(MCPError.IDA_ERROR, "No struct member API available on this IDA version.")
    res = tif.del_udm(idx)
    if res != 0:
        return None, make_error(MCPError.IDA_ERROR, f"del_udm failed with code {res}.")
    return moff, None


def _rename_struct_member(tif: ida_typeinf.tinfo_t, struct_name: str, member_name: str, new_name: str):
    """Rename a struct member. Returns ``(byte_offset, None)`` or ``(None, error_dict)``."""
    info = _udt_member(tif, member_name)
    if info is None:
        return None, make_error(MCPError.TYPE_ERROR, f"Member '{member_name}' not found in struct '{struct_name}'. "
                                 "Use types(action='get', name='<struct>') to list members.")
    idx, moff = info
    if _has_classic_struct_api():
        sptr = _struct_sptr(struct_name)
        if sptr is None:
            return None, make_error(MCPError.IDA_ERROR, f"Could not resolve struct handle for '{struct_name}'.")
        res = ida_struct.set_member_name(sptr, moff, new_name)
        if res != 0:
            return None, make_error(MCPError.IDA_ERROR,
                                    f"set_member_name failed with code {res} ({_struc_error_text(res)}).")
        return moff, None
    if not hasattr(tif, "rename_udm"):
        return None, make_error(MCPError.IDA_ERROR, "No struct member API available on this IDA version.")
    res = tif.rename_udm(idx, new_name)
    if res != 0:
        return None, make_error(MCPError.IDA_ERROR, f"rename_udm failed with code {res}.")
    return moff, None


def _set_struct_member_type(tif: ida_typeinf.tinfo_t, struct_name: str, member_name: str, type_str: str):
    """Retype a struct member. Returns ``(byte_offset, nbytes, None)`` or ``(None, None, error_dict)``."""
    info = _udt_member(tif, member_name)
    if info is None:
        return None, None, make_error(MCPError.TYPE_ERROR, f"Member '{member_name}' not found in struct '{struct_name}'. "
                                      "Use types(action='get', name='<struct>') to list members.")
    idx, moff = info
    mt, err = _parse_member_type(type_str, None)
    if err:
        return None, None, err
    if _has_classic_struct_api():
        sptr = _struct_sptr(struct_name)
        if sptr is None:
            return None, None, make_error(MCPError.IDA_ERROR, f"Could not resolve struct handle for '{struct_name}'.")
        member = ida_struct.get_member(sptr, moff)
        res = ida_struct.set_member_tinfo(sptr, member, moff, mt, 0)
        if res != 0:
            return None, None, make_error(MCPError.IDA_ERROR,
                                          f"set_member_tinfo failed with code {res} ({_struc_error_text(res)}).")
        return moff, mt.get_size(), None
    if not hasattr(tif, "set_udm_type"):
        return None, None, make_error(MCPError.IDA_ERROR, "No struct member API available on this IDA version.")
    res = tif.set_udm_type(idx, mt)
    if res != 0:
        # IDA 9.4 refuses an in-place retype when the new type is larger and
        # would overlap the next member (UDM_TYPE_INVALID, verified live).
        # Emulate the C re-declaration semantics: delete the member and every
        # member after it, then re-add them shifted by the size delta.
        try:
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
            old_bits = udt[idx].size
            new_bits = mt.get_size() * 8
            if new_bits <= old_bits:
                return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
            tail = [
                (udt[i].name, udt[i].type, udt[i].offset)
                for i in range(idx + 1, udt.size())
            ]
            # Remove members from the tail end down through idx (refetch the
            # details each pass — the udt object does not track deletions).
            while True:
                cur = ida_typeinf.udt_type_data_t()
                if not tif.get_udt_details(cur):
                    break
                if cur.size() <= idx:
                    break
                if tif.del_udm(cur.size() - 1) != 0:
                    return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
            delta = new_bits - old_bits
            if tif.add_udm(member_name, mt, moff * 8) != 0:
                return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
            for tname, ttype, toff in tail:
                try:
                    if tif.add_udm(tname, ttype, toff + delta) != 0:
                        return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
                except Exception:
                    return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
            return moff, mt.get_size(), None
        except Exception:
            return None, None, make_error(MCPError.IDA_ERROR, f"set_udm_type failed with code {res}.")
    return moff, mt.get_size(), None


def _add_enum_member(tif: ida_typeinf.tinfo_t, member_name: str, value: int):
    """Add an enumerator. Returns None or an error_dict."""
    if hasattr(ida_typeinf, "add_enum_member"):
        res = ida_typeinf.add_enum_member(tif.get_tid(), member_name, value, -1)
        if res != 0:
            return make_error(MCPError.IDA_ERROR, f"add_enum_member failed with code {res}. "
                              "The enumerator name must be unique and the value must be valid for the enum.")
        return None
    if hasattr(tif, "add_edm"):
        try:
            tif.add_edm(member_name, value, -1)
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"add_edm failed: {e}")
        return None
    return make_error(MCPError.IDA_ERROR, "No enum member API available on this IDA version.")


def _rename_enum_member(tif: ida_typeinf.tinfo_t, member_name: str, new_name: str):
    """Rename an enumerator. Returns None or an error_dict."""
    if hasattr(ida_typeinf, "set_enum_member_name"):
        res = ida_typeinf.set_enum_member_name(tif.get_tid(), member_name, new_name)
        if res != 0:
            return make_error(MCPError.IDA_ERROR, f"set_enum_member_name failed with code {res}. "
                              "The new enumerator name must be unique.")
        return None
    if hasattr(tif, "rename_edm"):
        idx = _enum_member_index(tif, member_name)
        if idx is None:
            return make_error(MCPError.TYPE_ERROR, f"Enumerator '{member_name}' not found in the enum.")
        res = tif.rename_edm(idx, new_name)
        if res != 0:
            return make_error(MCPError.IDA_ERROR, f"rename_edm failed with code {res}.")
        return None
    return make_error(MCPError.IDA_ERROR, "No enum member API available on this IDA version.")


def _revalue_enum_member(tif: ida_typeinf.tinfo_t, member_name: str, value: int):
    """Revalue an enumerator. Returns None or an error_dict."""
    if hasattr(ida_typeinf, "set_enum_member_value"):
        res = ida_typeinf.set_enum_member_value(tif.get_tid(), member_name, value, -1)
        if res != 0:
            return make_error(MCPError.IDA_ERROR, f"set_enum_member_value failed with code {res}. "
                              "The value may collide with another enumerator's bitmask.")
        return None
    if hasattr(tif, "del_edm") and hasattr(tif, "add_edm"):
        idx = _enum_member_index(tif, member_name)
        if idx is None:
            return make_error(MCPError.TYPE_ERROR, f"Enumerator '{member_name}' not found in the enum.")
        res = tif.del_edm(idx)
        if res != 0:
            return make_error(MCPError.IDA_ERROR, f"del_edm failed with code {res}.")
        try:
            tif.add_edm(member_name, value, -1, 0, idx)
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"add_edm failed: {e}")
        return None
    return make_error(MCPError.IDA_ERROR, "No enum member API available on this IDA version.")
