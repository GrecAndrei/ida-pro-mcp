
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
# 11. SEGMENTS - Segment management
# ============================================================================

@tool
@idawrite
def segments(
    action: Annotated[Literal["list", "add", "delete", "set_attr", "set_perms", "move"],
                      "Action: list|add|delete|set_attr|set_perms|move"],
    start: Annotated[Optional[str], "Start address (src for move)"] = None,     
    end: Annotated[Optional[str], "End address (dst for move)"] = None,
    name: Annotated[Optional[str], "Segment name"] = None,
    sclass: Annotated[str, "Segment class"] = "DATA",
    attr: Annotated[Optional[str], "Attribute name (for set_attr)"] = None,     
    value: Annotated[Optional[Union[str, int]], "Attribute value (for set_attr)"] = None,
    offset: Annotated[int, "Pagination offset (for list)"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    **kwargs
) -> dict:
    """
    Manage binary segments.
    
    Actions:
    - list: List all segments.
    - add: Create a new segment.
    - delete: Delete a segment by address.
    - set_attr: Update segment metadata.
    - move: Relocate a segment in memory.
    """
    try:
        if action == "list":
            results = []
            total = 0
            for ea in idautils.Segments():
                seg = idaapi.getseg(ea)
                if seg:
                    perms = ""
                    if seg.perm & idaapi.SEGPERM_READ: perms += "r"
                    if seg.perm & idaapi.SEGPERM_WRITE: perms += "w"
                    if seg.perm & idaapi.SEGPERM_EXEC: perms += "x"
                    total += 1
                    if total > offset and (count == 0 or len(results) < count):
                        results.append({"name": ida_segment.get_segm_name(seg), "start": hex(seg.start_ea), "end": hex(seg.end_ea), "perms": perms or "---"})
            return {"ok": True, "segments": results, "total": total, "offset": offset, "count": len(results)}
        
        elif action == "add":
            if not start or not end: return make_error(MCPError.INVALID_ARGS, "start and end required")
            s_ea, err = validate_addr(start)
            if err: return err
            e_ea, err = validate_addr(end)
            if err: return err
            
            seg = idaapi.segment_t()
            seg.start_ea, seg.end_ea = s_ea, e_ea
            if idaapi.add_segm_ex(seg, name or "", sclass, 0): return {"ok": True, "start": hex(s_ea), "end": hex(e_ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to add segment")
        
        elif action == "delete":
            if not start: return make_error(MCPError.INVALID_ARGS, "start required")
            s_ea, err = validate_addr(start)
            if err: return err
            if idaapi.del_segm(s_ea, idaapi.SEGMOD_KILL): return {"ok": True, "start": hex(s_ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to delete segment")
        
        elif action == "set_attr":
            if not start or not attr or value is None: return make_error(MCPError.INVALID_ARGS, "start, attr, and value required")
            s_ea, err = validate_addr(start)
            if err: return err
            seg = idaapi.getseg(s_ea)
            if not seg: return make_error(MCPError.SEGMENT_NOT_FOUND, hex(s_ea))
            if hasattr(seg, attr):
                setattr(seg, attr, value)
                idaapi.update_segm(seg)
                return {"ok": True, "start": hex(s_ea), "attr": attr, "value": value}
            return make_error(MCPError.INVALID_ARGS, f"Unknown attribute: {attr}")

        elif action == "set_perms":
            if not start or value is None:
                return make_error(MCPError.INVALID_ARGS, "start and value required")
            s_ea, err = validate_addr(start)
            if err: return err
            seg = idaapi.getseg(s_ea)
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND, hex(s_ea))
            if isinstance(value, str):
                perms = 0
                v = value.lower()
                if "r" in v: perms |= idaapi.SEGPERM_READ
                if "w" in v: perms |= idaapi.SEGPERM_WRITE
                if "x" in v: perms |= idaapi.SEGPERM_EXEC
                seg.perm = perms
            else:
                seg.perm = int(value)
            idaapi.update_segm(seg)
            return {"ok": True, "start": hex(s_ea), "perms": seg.perm}

        elif action == "move":
            if not start or not end: return make_error(MCPError.INVALID_ARGS, "start and end (new_start) required")
            s_ea, err = validate_addr(start)
            if err: return err
            t_ea, err = validate_addr(end)
            if err: return err
            if idaapi.move_segm(s_ea, t_ea, 0) == idaapi.MOVE_SEGM_OK: return {"ok": True, "old": hex(s_ea), "new": hex(t_ea)}
            return make_error(MCPError.IDA_ERROR, "Failed to move segment")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 12. FILES - Database and file operations
# ============================================================================
