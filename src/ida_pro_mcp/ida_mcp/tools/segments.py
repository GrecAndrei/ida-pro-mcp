
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
    action: Annotated[Literal["list", "add", "delete", "set_attr", "set_perms", "move", "info"],
                      "Action: list|add|delete|set_attr|set_perms|move|info"],
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
    
    ACTIONS:
    
    list - List all segments with basic info
        Params: offset, count (for pagination)
        Returns: {segments: [{name, start, end, size, perms}]}
        
    info - Detailed information about a specific segment
        Params: start (address within segment) or name
        Returns: {segment: {name, start, end, size, perms, class, type, align, bitness, 
                           code_count, data_count, func_count, string_count}}
        
    add - Create a new segment
        Params: start, end, name, sclass
        Returns: {ok, start, end}
        
    delete - Delete a segment
        Params: start (address within segment)
        Returns: {ok, start}
        
    set_attr - Update segment metadata
        Params: start, attr, value
        Available attrs: name, align, comb, perm, bitness, type, color
        Returns: {ok, attr, value}
        
    set_perms - Set segment permissions
        Params: start, value ("rwx" string or integer)
        Returns: {ok, perms}
        
    move - Relocate a segment
        Params: start (current), end (new start address)
        Returns: {ok, old, new}
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
                        results.append({
                            "name": ida_segment.get_segm_name(seg), 
                            "start": hex(seg.start_ea), 
                            "end": hex(seg.end_ea), 
                            "size": hex(seg.end_ea - seg.start_ea),
                            "perms": perms or "---",
                            "class": ida_segment.get_segm_class(seg),
                        })
            return {"ok": True, "segments": results, "total": total, "offset": offset, "count": len(results)}
        
        elif action == "info":
            # Find segment by address or name
            seg = None
            if start:
                s_ea, err = validate_addr(start)
                if err: return err
                seg = idaapi.getseg(s_ea)
            elif name:
                # Find by name
                for ea in idautils.Segments():
                    s = idaapi.getseg(ea)
                    if s and ida_segment.get_segm_name(s) == name:
                        seg = s
                        break
            else:
                return make_error(MCPError.INVALID_ARGS, "start or name required")
                
            if not seg:
                return make_error(MCPError.SEGMENT_NOT_FOUND, "Segment not found")
            
            # Permissions string
            perms = ""
            if seg.perm & idaapi.SEGPERM_READ: perms += "r"
            if seg.perm & idaapi.SEGPERM_WRITE: perms += "w"
            if seg.perm & idaapi.SEGPERM_EXEC: perms += "x"
            
            # Segment type - build dict safely for IDA 9 compatibility
            seg_types = {}
            for attr_name, type_name in [("SEG_CODE", "code"), ("SEG_DATA", "data"), 
                                          ("SEG_BSS", "bss"), ("SEG_STACK", "stack"),
                                          ("SEG_XTRN", "extern"), ("SEG_NULL", "null"),
                                          ("SEG_NORM", "normal"), ("SEG_ABS", "absolute")]:
                if hasattr(ida_segment, attr_name):
                    seg_types[getattr(ida_segment, attr_name)] = type_name
            seg_type = seg_types.get(seg.type, f"type_{seg.type}")
            
            # Count items
            code_count, data_count, func_count, string_count = 0, 0, 0, 0
            head = seg.start_ea
            while head < seg.end_ea:
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_code(flags):
                    code_count += 1
                elif ida_bytes.is_data(flags):
                    data_count += 1
                if ida_bytes.is_strlit(flags):
                    string_count += 1
                head = idc.next_head(head, seg.end_ea)
                if head == idaapi.BADADDR:
                    break
            
            # Count functions
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                func_count += 1
            
            return {
                "ok": True,
                "segment": {
                    "name": ida_segment.get_segm_name(seg),
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": hex(seg.end_ea - seg.start_ea),
                    "perms": perms or "---",
                    "perms_int": seg.perm,
                    "class": ida_segment.get_segm_class(seg),
                    "type": seg_type,
                    "type_int": seg.type,
                    "align": seg.align,
                    "bitness": seg.bitness * 16 if seg.bitness else 0,
                    "comb": seg.comb,
                    "color": hex(seg.color) if seg.color != 0xFFFFFFFF else None,
                    "code_heads": code_count,
                    "data_heads": data_count,
                    "functions": func_count,
                    "strings": string_count,
                }
            }
        
        elif action == "add":
            if not start or not end: return make_error(MCPError.INVALID_ARGS, "start and end required")
            s_ea, err = validate_addr(start)
            if err: return err
            e_ea, err = validate_addr(end)
            if err: return err
            
            seg = idaapi.segment_t()
            seg.start_ea, seg.end_ea = s_ea, e_ea
            if idaapi.add_segm_ex(seg, name or "", sclass, 0): 
                return {"ok": True, "start": hex(s_ea), "end": hex(e_ea), "name": name, "class": sclass}
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
            
            # Handle special attributes
            if attr == "name":
                ida_segment.set_segm_name(seg, str(value))
            elif hasattr(seg, attr):
                setattr(seg, attr, value)
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown attribute: {attr}")
            
            idaapi.update_segm(seg)
            return {"ok": True, "start": hex(s_ea), "attr": attr, "value": value}

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
            
            # Return human-readable perms
            perms_str = ""
            if seg.perm & idaapi.SEGPERM_READ: perms_str += "r"
            if seg.perm & idaapi.SEGPERM_WRITE: perms_str += "w"
            if seg.perm & idaapi.SEGPERM_EXEC: perms_str += "x"
            return {"ok": True, "start": hex(s_ea), "perms": perms_str, "perms_int": seg.perm}

        elif action == "move":
            if not start or not end: return make_error(MCPError.INVALID_ARGS, "start and end (new_start) required")
            s_ea, err = validate_addr(start)
            if err: return err
            t_ea, err = validate_addr(end)
            if err: return err
            result = idaapi.move_segm(s_ea, t_ea, 0)
            if result == idaapi.MOVE_SEGM_OK: 
                return {"ok": True, "old": hex(s_ea), "new": hex(t_ea)}
            
            # Provide better error messages
            move_errors = {
                idaapi.MOVE_SEGM_PARAM: "Invalid parameters",
                idaapi.MOVE_SEGM_ROOM: "Not enough room at destination",
                idaapi.MOVE_SEGM_IDP: "Processor module forbids move",
                idaapi.MOVE_SEGM_CHUNK: "Cannot move chunked function",
                idaapi.MOVE_SEGM_LOADER: "Loader forbids move",
                idaapi.MOVE_SEGM_ODD: "Odd segment boundaries",
                idaapi.MOVE_SEGM_ORPHAN: "Would create orphan bytes",
            }
            error_msg = move_errors.get(result, f"Unknown error code: {result}")
            return make_error(MCPError.IDA_ERROR, f"Failed to move segment: {error_msg}")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 12. FILES - Database and file operations
# ============================================================================
