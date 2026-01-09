
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
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ida_mcp.error_handling import (
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
# 10. FUNCS - Function management
# ============================================================================

@tool
@idawrite
def funcs(
    action: Annotated[Literal["create", "delete", "set_flags", "set_name", "add_comment", "list", "info"],
                      "Action: create|delete|set_flags|set_name|add_comment|list|info"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    comment: Annotated[Optional[str], "Function comment"] = None,
    repeatable: Annotated[bool, "Is comment repeatable?"] = False,
    query: Annotated[Optional[str], "Filter for function names (list action)"] = None,
    offset: Annotated[int, "Pagination offset (list action)"] = 0,
    count: Annotated[int, "Max results (0=all) (list action)"] = 100,
    named_only: Annotated[bool, "Only return named functions (list action)"] = False,
    include_prototype: Annotated[bool, "Include function prototype (info/list)"] = False,
    include_stack: Annotated[bool, "Include stack frame variables (info)"] = False,
    **kwargs
) -> dict:
    """
    Create and modify function definitions.
    
    Actions:
    - create: Define a new function at `addr`.
    - delete: Remove function definition at `addr`.
    - set_flags: Update function attribute flags.
    - set_name: Rename function at `addr`.
    - add_comment: Set function-level comment.
    - list: Paginated listing with optional name filtering.
    - info: Detailed info about a single function.
    """
    try:
        if action == "create":
            ea, err = validate_addr(addr)
            if err: return err
            existing = ida_funcs.get_func(ea)
            if existing and existing.start_ea == ea:
                if name:
                    idc.set_name(ea, name, ida_name.SN_FORCE)
                return {"ok": True, "addr": hex(ea), "name": name, "note": "Function already exists"}
            # Ensure code exists at the start address
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                created = idc.create_insn(ea)
                if created == 0 or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    return make_error(
                        MCPError.ADDRESS_INVALID,
                        f"Address {hex(ea)} is not code",
                        "Convert to code with data_ops.make_code or provide a valid function start",
                    )
            end_ea = None
            if end:
                end_ea, err = validate_addr(end)
                if err: return err
            if ida_funcs.add_func(ea, end_ea or idaapi.BADADDR):
                if name:
                    idc.set_name(ea, name, ida_name.SN_FORCE)
                return {"ok": True, "addr": hex(ea), "end": hex(end_ea) if end_ea else None, "name": name}
            return make_error(MCPError.IDA_ERROR, "Failed to create function", "Try defining code at the start or specify a valid end address")

        elif action == "delete":
            ea, err = validate_addr(addr)
            if err: return err
            if ida_funcs.del_func(ea): return {"ok": True, "addr": hex(ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to delete function")

        elif action == "set_flags":
            ea, err = validate_addr(addr)
            if err: return err
            func = ida_funcs.get_func(ea)
            if not func: return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            func.flags = flags
            if ida_funcs.update_func(func): return {"ok": True, "flags": hex(flags)}
            return make_error(MCPError.IDA_ERROR, "Failed to update flags")

        elif action == "set_name":
            ea, err = validate_addr(addr)
            if err: return err
            if not name: return make_error(MCPError.INVALID_ARGS, "name required")
            if idc.set_name(ea, name, ida_name.SN_FORCE): return {"ok": True, "name": name}
            return make_error(MCPError.IDA_ERROR, "Failed to set name")

        elif action == "add_comment":
            ea, err = validate_addr(addr)
            if err: return err
            if comment is None: return make_error(MCPError.INVALID_ARGS, "comment required")
            idc.set_func_cmt(ea, comment, 1 if repeatable else 0)
            return {"ok": True, "comment": comment}

        elif action == "list":
            funcs = []
            total = 0
            query_l = query.lower() if query else None

            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                if named_only and name.startswith("sub_"):
                    continue
                if query_l and query_l not in name.lower():
                    continue

                total += 1
                if total <= offset:
                    continue
                if count != 0 and len(funcs) >= count:
                    continue

                fn = idaapi.get_func(ea)
                entry = {
                    "addr": hex_ea(ea),
                    "name": name,
                    "size": hex_size(fn.end_ea - fn.start_ea),
                    "flags": hex(fn.flags),
                }
                if include_prototype:
                    entry["prototype"] = get_prototype(fn)
                funcs.append(entry)

            return {"ok": True, "functions": funcs, "total": total, "offset": offset, "count": len(funcs)}

        elif action == "info":
            ea, err = validate_addr(addr)
            if err: return err
            fn = idaapi.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            name = ida_funcs.get_func_name(fn.start_ea)
            info = {
                "addr": hex(fn.start_ea),
                "end": hex(fn.end_ea),
                "size": hex(fn.end_ea - fn.start_ea),
                "name": name,
                "flags": hex(fn.flags),
            }
            if include_prototype:
                info["prototype"] = get_prototype(fn)
            if include_stack:
                info["stack_frame"] = get_stack_frame_variables_internal(fn.start_ea, raise_error=False)
            return {"ok": True, "function": info}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================
