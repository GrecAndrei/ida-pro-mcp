
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
# 26. STRUCTS - Automatic Structure Recovery and Analysis
# ============================================================================

@tool
@idaread
def structs(
    action: Annotated[Literal["recover", "analyze_usage", "list", "create", "add_member", "apply", "reconstruct_vtable"],
                      "Action: recover|analyze_usage|list|create|add_member|apply|reconstruct_vtable"],
    addr: Annotated[Optional[str], "Address for struct operations"] = None,
    name: Annotated[Optional[str], "Structure name"] = None,
    decl: Annotated[Optional[str], "C declaration for struct creation"] = None,
    member_name: Annotated[Optional[str], "Member name for add_member"] = None,
    member_type: Annotated[Optional[str], "Member type for add_member"] = "int",
    member_offset: Annotated[int, "Member offset for add_member"] = 0,
    query: Annotated[Optional[str], "Filter by name"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max items to return"] = 100,
    **kwargs
) -> dict:
    """
    Automatic structure recovery and struct management.
    
    ACTIONS:
    
    recover - Attempt automatic struct recovery from function usage
        Params: addr (function that uses a struct pointer)
        Returns: {recovered_struct: {name, members: [{offset, name, type}]}}
    
    reconstruct_vtable - Create a VTable struct from a list of function pointers
        Params: addr (start of vtable), name (optional class name)
        Returns: {vtable_struct: name, count: method_count}
        
    analyze_usage - Analyze how an address/register is used as struct
        Params: addr
        Returns: {accesses: [{offset, size, operation}]}
        
    list - List all structures in the database
        Params: query (filter name), offset, count (default 100)
        Returns: {structs: [{name, size, ordinal, is_union}]}
        
    create - Create a new structure from C declaration
        Params: decl (e.g., "struct Foo { int x; char y[16]; };")
        Returns: {created, name, size}
        
    add_member - Add a member to an existing structure
        Params: name (struct name), member_name, member_type, member_offset
        Returns: {added, struct, member}
        
    apply - Apply a structure type to an address
        Params: addr, name (struct name)
        Returns: {applied, addr, struct}
    """
    try:
        if action == "reconstruct_vtable":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, 'inf_is_64bit') else (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100)
            ptr_size = 8 if is_64 else 4
            methods = []
            curr = ea
            
            # Scan for pointers
            while True:
                ptr = ida_bytes.get_qword(curr) if ptr_size == 8 else ida_bytes.get_dword(curr)
                # Check if ptr points to valid code/data
                if not ida_bytes.is_loaded(ptr): break
                
                # Check if it looks like a function
                # 1. Is it the start of a known function?
                func = ida_funcs.get_func(ptr)
                if func and func.start_ea == ptr:
                    method_name = idc.get_func_name(ptr)
                else:
                    # 2. Is it in a code segment?
                    seg = ida_segment.getseg(ptr)
                    if seg and seg.perm & ida_segment.SEGPERM_EXEC:
                        method_name = f"sub_{ptr:x}"
                    else:
                        break # Stop at non-code pointer
                
                methods.append({"offset": curr - ea, "ptr": hex(ptr), "name": method_name})
                curr += ptr_size
                if len(methods) > 200: break # Safety limit
            
            if not methods:
                return make_error(MCPError.IDA_ERROR, "No valid function pointers found at address")
            
            # Create the VTable struct
            vtable_name = name if name else f"VTable_{ea:X}"
            
            # 1. Create struct
            udt = ida_typeinf.udt_type_data_t()
            til = ida_typeinf.get_idati()
            
            for m in methods:
                mem = ida_typeinf.udt_member_t()
                mem.name = f"method_{m['offset'] // ptr_size}"
                mem.offset = m['offset'] * 8
                
                # Create function pointer type: void (*)(void)
                # Ideally we'd use the actual prototype of the target function
                # but "void*" or generic func ptr is safer default
                mtif = ida_typeinf.tinfo_t()
                if not ida_typeinf.parse_decl(mtif, til, "void *;", 0):
                    pass 
                mem.type = mtif
                mem.size = ptr_size * 8
                udt.push_back(mem)
            
            tf = ida_typeinf.tinfo_t()
            if tf.create_udt(udt):
                ordinal = ida_typeinf.alloc_type_ordinal(til)
                if ida_typeinf.set_numbered_type(til, ordinal, ida_typeinf.NTF_TYPE, vtable_name, tf):
                    # Apply it to the address
                    ida_typeinf.apply_tinfo(ea, tf, ida_typeinf.TINFO_DEFINITE)
                    return {"ok": True, "vtable": vtable_name, "methods": len(methods), "size": len(methods) * ptr_size}
            
            return make_error(MCPError.IDA_ERROR, "Failed to create VTable struct")

        elif action == "recover":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (function address)")

            ea, error = validate_addr(addr)
            if error: return error
            
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            
            # Try to recover struct from decompilation
            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    return make_error(MCPError.IDA_ERROR, "Could not decompile function")
                
                # Analyze local variables that might be struct pointers
                struct_candidates = []
                
                for lvar in cfunc.lvars:
                    if lvar.type().is_ptr():
                        # This is a pointer - might be a struct pointer
                        pointed_type = lvar.type().get_pointed_object()
                        if pointed_type and not pointed_type.is_scalar():
                            struct_candidates.append({
                                "var_name": lvar.name,
                                "type": str(lvar.type()),
                                "pointed_type": str(pointed_type)
                            })
                
                # Look for field accesses
                accesses = []
                
                class AccessFinder(ida_hexrays.ctree_visitor_t):
                    def __init__(self):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    
                    def visit_expr(self, e):
                        if e.op == ida_hexrays.cot_memptr or e.op == ida_hexrays.cot_memref:
                            accesses.append({
                                "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None,
                                "op": ida_hexrays.get_ctype_name(e.op),
                                "offset": e.m if hasattr(e, 'm') else None
                            })
                        return 0
                
                finder = AccessFinder()
                finder.apply_to(cfunc.body, None)
                
                return {
                    "ok": True,
                    "function": idc.get_func_name(ea) or hex(ea),
                    "struct_candidates": struct_candidates,
                    "field_accesses": accesses[:50]
                }
                
            except ida_hexrays.DecompilationFailure:
                return make_error(MCPError.IDA_ERROR, "Decompilation failed")
        
        elif action == "analyze_usage":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            
            ea, error = validate_addr(addr)
            if error: return error
            
            # Analyze memory accesses from this point
            accesses = []
            
            # Get xrefs from this address
            for xref in idautils.XrefsFrom(ea):
                size = idc.get_item_size(xref.to)
                accesses.append({
                    "target": hex(xref.to),
                    "type": "code" if xref.type in [1, 17, 18, 19, 20, 21] else "data",
                    "size": size
                })
            
            return {"ok": True, "addr": hex(ea), "accesses": accesses[:100]}
        
        elif action == "list":
            structs_list = []
            
            # Iterate through all local types
            til = ida_typeinf.get_idati()
            if til:
                qty_func = getattr(ida_typeinf, "get_ordinal_qty", None) or getattr(ida_typeinf, "get_ordinal_count", None)
                total_count = qty_func(til) if qty_func else 0
                found = 0
                for ordinal in range(1, total_count + 1):
                    tinfo = ida_typeinf.tinfo_t()
                    if tinfo.get_numbered_type(til, ordinal):
                        if tinfo.is_struct() or tinfo.is_union():
                            type_name = tinfo.get_type_name() or f"struct_{ordinal}"
                            if not query or query.lower() in type_name.lower():
                                found += 1
                                if found > offset and (count == 0 or len(structs_list) < count):
                                    structs_list.append({
                                        "name": type_name,
                                        "ordinal": ordinal,
                                        "size": tinfo.get_size(),
                                        "is_union": tinfo.is_union()
                                    })
            
            return {"ok": True, "structs": structs_list, "total": found, "offset": offset, "count": len(structs_list)}
        
        elif action == "create":
            if not decl:
                return make_error(MCPError.INVALID_ARGS, "decl required (C structure declaration)")
            
            # Parse the declaration
            til = ida_typeinf.get_idati()
            tinfo = ida_typeinf.tinfo_t()
            
            result = ida_typeinf.parse_decl(tinfo, til, decl, ida_typeinf.PT_TYP)
            if result is None:
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse declaration: {decl}")
            
            # Get the name
            struct_name = tinfo.get_type_name()
            if not struct_name:
                # Try to extract from declaration
                import re
                match = re.search(r'struct\s+(\w+)', decl)
                if match:
                    struct_name = match.group(1)
            
            # Save to til
            ordinal = ida_typeinf.alloc_type_ordinal(til)
            if ida_typeinf.set_numbered_type(til, ordinal, ida_typeinf.NTF_TYPE, struct_name, tinfo):
                return {
                    "ok": True,
                    "name": struct_name,
                    "ordinal": ordinal,
                    "size": tinfo.get_size()
                }
            
            return make_error(MCPError.IDA_ERROR, "Failed to save structure to type library")
        
        elif action == "add_member":
            if not name: return make_error(MCPError.INVALID_ARGS, "name (struct name) required")
            if not member_name: return make_error(MCPError.INVALID_ARGS, "member_name required")
            
            # Use modern UDT API for IDA 9.2+
            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(til, name):
                return make_error(MCPError.TYPE_ERROR, f"Structure '{name}' not found")
            
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return make_error(MCPError.IDA_ERROR, "Failed to get structure details")
            
            # Create new member info
            new_member = ida_typeinf.udt_member_t()
            new_member.name = member_name
            new_member.offset = member_offset * 8 # Convert to bits
            
            # Parse member type
            mtif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(mtif, til, member_type + ";", ida_typeinf.PT_SIL):
                return make_error(MCPError.INVALID_ARGS, f"Failed to parse member type: {member_type}")
            new_member.type = mtif
            new_member.size = mtif.get_size() * 8
            
            # Insert/Append
            udt.push_back(new_member)
            
            # Finalize and save
            if tif.create_udt(udt):
                if ida_typeinf.set_numbered_type(til, ida_typeinf.get_named_type_tid(name), ida_typeinf.NTF_TYPE, name, tif):
                    return {"ok": True, "struct": name, "member": member_name, "offset": hex(member_offset)}
            
            return make_error(MCPError.IDA_ERROR, "Failed to save updated structure")
        
        elif action == "apply":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            if not name: return make_error(MCPError.INVALID_ARGS, "name (struct name) required")
            
            ea, err = validate_addr(addr)
            if err: return err
            
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
                return make_error(MCPError.TYPE_ERROR, f"Structure '{name}' not found")
            
            if ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
                return {"ok": True, "addr": hex(ea), "struct": name, "size": tinfo.get_size()}
            
            return make_error(MCPError.IDA_ERROR, f"Failed to apply struct '{name}'")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    
    except Exception as e:
        return handle_error(e)




# ============================================================================
# 27. EMULATE - Code Emulation and Snippet Execution
# ============================================================================
