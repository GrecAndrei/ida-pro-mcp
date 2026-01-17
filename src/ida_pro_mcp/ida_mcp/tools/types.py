
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_segment
import ida_funcs
import ida_kernwin
import ida_frame
import ida_lines

# Infrastructure discovery
try:
    # Package mode
    from ..rpc import tool, unsafe
    from ..sync import idaread, idawrite, IDAError
    from ..utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ..error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
        
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================

@tool
@idawrite
def types(
    action: Annotated[Literal["list", "get", "set_prototype", "parse_decl", "declare", "apply", "search_structs", "infer", "read_struct", "import_header"],
                      "Action: list|get|set_prototype|parse_decl|declare|apply|search_structs|infer|read_struct|import_header"],
    name: Annotated[Optional[str], "Type name (or variable name for apply)"] = None,
    addr: Annotated[Optional[str], "Address (for set_prototype/apply/infer/read_struct)"] = None,
    decl: Annotated[Optional[str], "Type declaration string (or header content)"] = None,
    query: Annotated[Optional[str], "Search query (for list/search_structs)"] = None,
    kind: Annotated[Optional[str], "Apply kind: function, global, local, stack"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Maximum items to return"] = 100,
    **kwargs
) -> dict:
    """
    Manage and inspect types, structures, and function prototypes.
    
    Actions:
    - list: List all types (structs, enums, typedefs) in the Type Library (TIL).
    - get: Get detailed structure layout or enum members for a named type.
    - set_prototype: Set the C-style function prototype at an address.
    - parse_decl: Parse a C declaration string to verify validity and size.
    - declare: Define a new local type/struct from a C declaration.
    - apply: Apply a type to an address (global/function).
    - search_structs: Find structs containing a field matching `query`.
    - infer: Attempt to guess the type at an address.
    - read_struct: Read structured data from memory using a type.
    - import_header: Parse a full C header content (structs/enums) into the local type library.
    
    Arguments:
    - name: Type name, or variable name when applying types.
    - addr: Target address.
    - decl: C declaration string or header content.
    - query: Name filter for 'list' or field filter for 'search_structs'.
    - offset/count: Pagination controls for 'list'.
    """
    try:
        if action == "import_header":
            if not decl: return make_error(MCPError.INVALID_ARGS, "decl (header content) required")
            
            # Using idc.parse_decls which is a wrapper around ida_typeinf.idc_parse_types
            # It returns the number of parsing errors (0 = success)
            errors = idc.parse_decls(decl, 0)
            
            if errors == 0:
                # Count how many types were actually added? Hard to track exact delta efficiently without snapshot.
                # But we can assume success.
                return {"ok": True, "status": "Header imported successfully", "errors": 0}
            else:
                return make_error(MCPError.TYPE_ERROR, f"Header parsing failed with {errors} errors. Check syntax.")

        elif action == "list":
            types_list = []
            til = ida_typeinf.get_idati()
            if not til:
                return make_error(MCPError.IDA_ERROR, "Type library not available")
            
            # Use get_ordinal_qty/get_ordinal_count for efficiency
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return make_error(MCPError.IDA_ERROR, "Type ordinal API not available")
            
            total_qty = qty_func(til)
            found = 0
            
            for ordinal in range(1, total_qty + 1):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(til, ordinal):
                    name = tif.get_type_name()
                    if name:
                        if not query or query.lower() in name.lower():
                            found += 1
                            if found > offset and (count == 0 or len(types_list) < count):
                                types_list.append({
                                    "ordinal": ordinal,
                                    "name": name,
                                    "type": str(tif),
                                    "is_struct": tif.is_struct(),
                                    "is_enum": tif.is_enum()
                                })
            
            return {
                "ok": True, 
                "types": types_list, 
                "total": found, 
                "offset": offset, 
                "count": len(types_list)
            }
        
        elif action == "get":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            
            tif = ida_typeinf.tinfo_t()
            # Try to get by name directly
            if not tif.get_named_type(None, name):
                # Try by TID (IDA 9+)
                tid = ida_typeinf.get_named_type_tid(name)
                if tid == idaapi.BADADDR or not tif.get_type_by_tid(tid):
                    return make_error(MCPError.TYPE_ERROR, f"Type not found: {name}")
            
            result = {"ok": True, "name": name, "type": str(tif), "size": tif.get_size()}
            
            if tif.is_struct() or tif.is_union():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for m in udt:
                        if not m.is_gap():
                            members.append({"name": m.name, "offset": m.offset // 8, "type": str(m.type)})
                    result["members"] = members
            
            elif tif.is_enum():
                ei = ida_typeinf.enum_type_data_t()
                if tif.get_enum_details(ei):
                    members = [{"name": e.name, "value": e.value} for e in ei]
                    result["members"] = members
            
            return result
        
        elif action == "apply":
            # Apply type to address (enhanced for locals)
            if not addr or not decl:
                return make_error(MCPError.INVALID_ARGS, "addr and decl required")
            
            ea, err = validate_addr(addr)
            if err: return err
            
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse type: {decl}")

            apply_kind = kind
            func = idaapi.get_func(ea)
            
            if not apply_kind:
                if func and func.start_ea == ea: apply_kind = "function"
                else: apply_kind = "global"

            if apply_kind == "function":
                 if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                     return make_error(MCPError.IDA_ERROR, "Failed to apply function type")
            
            elif apply_kind == "local":
                if not name: return make_error(MCPError.INVALID_ARGS, "name required for local var")
                if not func: return make_error(MCPError.FUNCTION_NOT_FOUND, "Address not in function")
                
                # Use Hex-Rays to modify local variable
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if not cfunc: return make_error(MCPError.IDA_ERROR, "Decompilation failed")
                    
                    # Search for the local variable by name
                    lvar_found = None
                    for lvar in cfunc.lvars:
                        if lvar.name == name:
                            lvar_found = lvar
                            break
                    
                    if not lvar_found:
                        return make_error(MCPError.INVALID_ARGS, f"Local variable '{name}' not found in function")
                    
                    # Use the modern user_lvar_modifier approach
                    modifier = my_modifier_t(name, tif)
                    if ida_hexrays.modify_user_lvars(func.start_ea, modifier):
                        # Force refresh
                        refresh_decompiler_ctext(func.start_ea)
                        return {"ok": True, "addr": hex(ea), "var": name, "type": str(tif), "kind": "local"}
                    return make_error(MCPError.IDA_ERROR, "Failed to modify local variable type")
                except Exception as e:
                    return handle_error(e)

            else: # global/default
                if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return make_error(MCPError.IDA_ERROR, "Failed to apply type")

            return {"ok": True, "addr": hex(ea), "type": str(tif), "kind": apply_kind}
        
        elif action == "search_structs":
            # Search structs by field name or type
            if not query:
                return {"error": "query required"}
            
            matches = []
            # Check if ordinal qty API exists
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            if not qty_func:
                return {"error": "Type ordinal API not available"}
            for ordinal in range(1, qty_func(None)):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and (tif.is_struct() or tif.is_union()):
                    type_name = tif.get_type_name()
                    # Check type name
                    if query.lower() in type_name.lower():
                        matches.append({"name": type_name, "ordinal": ordinal, "match": "name"})
                        continue
                    
                    # Check fields
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for i in range(udt.size()):
                            m = udt[i]
                            if query.lower() in m.name.lower():
                                matches.append({
                                    "name": type_name,
                                    "ordinal": ordinal,
                                    "match": "field",
                                    "field": m.name
                                })
                                break
            return {"ok": True, "matches": matches}
        
        elif action == "infer":
             # Infer type at address
             if not addr:
                 return {"error": "addr required"}
             ea = parse_address(addr)
             tif = ida_typeinf.tinfo_t()
             
             method = "none"
             confidence = "none"
             
             # Try Hex-Rays
             try:
                 import ida_hexrays
                 if ida_hexrays.init_hexrays_plugin():
                     # guess_tinfo removed in IDA 9, use decompile approach
                     if hasattr(ida_hexrays, 'guess_tinfo') and ida_hexrays.guess_tinfo(tif, ea):
                          method = "hexrays"
                          confidence = "high"
                     elif hasattr(ida_hexrays, 'decompile'):
                          # Try to infer from decompilation
                          try:
                              cfunc = ida_hexrays.decompile(ea)
                              if cfunc and cfunc.type:
                                  tif = cfunc.type
                                  method = "hexrays"
                                  confidence = "high"
                          except:
                              pass
             except:
                 pass
             
             if method == "none":
                 # Try existing
                 if ida_nalt.get_tinfo(tif, ea):
                     method = "existing"
                     confidence = "high"
            
             if method == "none":
                 # Size based
                 size = ida_bytes.get_item_size(ea)
                 if size > 0:
                     type_guess = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, f"uint8_t[{size}]")
                     return {"addr": addr, "inferred_type": type_guess, "method": "size", "confidence": "low"}
                     
             return {"addr": addr, "inferred_type": str(tif) if method != "none" else None, "method": method, "confidence": confidence}

        elif action == "read_struct":
            # Read struct at address
            if not addr: # 'name' param is struct name here!
                 return {"error": "addr required"}
            if not name:
                return {"error": "name (struct name) required"}
            
            ea = parse_address(addr)
            
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                return {"error": f"Struct '{name}' not found"}
            
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return {"error": "Not a struct/union or failed to get details"}
            
            members = []
            for i in range(udt.size()):
                m = udt[i]
                offset = m.offset // 8
                mem_addr = ea + offset
                mem_type = str(m.type)
                mem_size = m.type.get_size()
                
                # Simple value reading
                val_str = "?"
                try:
                    if m.type.is_ptr():
                         val = ida_bytes.get_qword(mem_addr) # assume 64-bit for now or check
                         val_str = hex(val)
                    elif mem_size in [1, 2, 4, 8]:
                        val = ida_bytes.get_wide_byte(mem_addr) # simplistic
                        if mem_size == 1: val = ida_bytes.get_byte(mem_addr)
                        elif mem_size == 2: val = ida_bytes.get_word(mem_addr)
                        elif mem_size == 4: val = ida_bytes.get_dword(mem_addr)
                        elif mem_size == 8: val = ida_bytes.get_qword(mem_addr)
                        val_str = hex(val)
                    else:
                        val_str = "..."
                except:
                    pass
                
                members.append({
                    "name": m.name,
                    "offset": hex(offset),
                    "type": mem_type,
                    "value": val_str
                })
            
            return {"addr": addr, "struct": name, "members": members}
        
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 6. MEMORY - Read/Write operations
# ============================================================================
