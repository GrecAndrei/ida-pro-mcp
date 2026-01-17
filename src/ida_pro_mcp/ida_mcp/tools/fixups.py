
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
# 15. FIXUPS - Relocation/fixup operations
# ============================================================================

@tool
@idawrite
def fixups(
    action: Annotated[Literal["list", "get", "add", "delete"], "Action: list|get|add|delete"],
    addr: Annotated[Optional[str], "Address"] = None,
    target: Annotated[Optional[str], "Target address (for add)"] = None,
    fixup_type: Annotated[int, "Fixup type (for add)"] = 0,
    start: Annotated[Optional[str], "Start address for list"] = None,
    end: Annotated[Optional[str], "End address for list"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max entries"] = 1000,
    **kwargs
) -> dict:
    """
    Manage fixups (relocations) in the database.
    
    Actions:
    - list: List fixups in a range (default: all).
    - get: Get fixup details at `addr`.
    - add: Add a fixup at `addr` targeting `target`.
    - delete: Remove a fixup.
    
    Arguments:
    - fixup_type: Integer type (processor specific).
    - target: Target address for the fixup.
    """
    try:
        import ida_fixup
        
        if action == "list":
            import ida_ida
            # Fix min_ea/max_ea access for IDA 9.0+
            if hasattr(ida_ida, "inf_get_min_ea"):
                min_ea = ida_ida.inf_get_min_ea()
                max_ea = ida_ida.inf_get_max_ea()
            else:
                # Fallback
                min_ea = idaapi.cvar.inf.min_ea
                max_ea = idaapi.cvar.inf.max_ea
                
            if start:
                start_ea, err = validate_addr(start)
                if err: return err
            else:
                start_ea = min_ea
            if end:
                end_ea, err = validate_addr(end)
                if err: return err
            else:
                end_ea = max_ea

            fixup_list = []
            total = 0
            ea = ida_fixup.get_first_fixup_ea()
            while ea != idaapi.BADADDR and (count == 0 or len(fixup_list) < count):
                if start_ea <= ea <= end_ea:
                    fd = ida_fixup.fixup_data_t()
                    if ida_fixup.get_fixup(fd, ea):
                        total += 1
                        if total > offset and (count == 0 or len(fixup_list) < count):
                            fixup_list.append({
                                "addr": hex(ea),
                                "type": fd.get_type(),
                                "target": hex(fd.off) if fd.off != idaapi.BADADDR else None
                            })
                ea = ida_fixup.get_next_fixup_ea(ea)
            return {"ok": True, "fixups": fixup_list, "total": total, "offset": offset, "count": len(fixup_list)}
        
        elif action == "get":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)
            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                return {
                    "addr": addr,
                    "type": fd.get_type(),
                    "target": hex(fd.off) if fd.off != idaapi.BADADDR else None
                }
            return make_error(MCPError.FILE_NOT_FOUND, "No fixup at address")
        
        elif action == "add":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)
            fd = ida_fixup.fixup_data_t()
            fd.set_type(fixup_type)
            if target:
                fd.off = parse_address(target)
            ida_fixup.set_fixup(ea, fd)
            return {"ok": True, "addr": addr}
        
        elif action == "delete":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)
            ida_fixup.del_fixup(ea)
            return {"ok": True, "addr": addr}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 16. DATA_OPS - Data creation operations
# ============================================================================
