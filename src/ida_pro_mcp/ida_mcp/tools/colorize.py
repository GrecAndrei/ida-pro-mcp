
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
# 35. COLORIZE - Code Region Coloring
# ============================================================================

@tool
@idawrite
def colorize(
    action: Annotated[Literal["set_func", "set_range", "set_insn", "get", "clear", "palette", "highlight_pattern"],
                      "Action: set_func|set_range|set_insn|get|clear|palette|highlight_pattern"],
    addr: Annotated[Optional[str], "Address or start of range"] = None,
    end_addr: Annotated[Optional[str], "End of range for set_range"] = None,
    color: Annotated[Optional[str], "Color as RGB hex (e.g., 'FF0000') or name"] = None,
    pattern: Annotated[Optional[str], "Byte pattern to highlight"] = None,
    **kwargs
) -> dict:
    """
    Apply visual coloring to the database.
    
    Actions:
    - set_func: Color an entire function.
    - set_range: Color a specific memory range.
    - set_insn: Color a single instruction.
    - get: Retrieve the current color of an address.
    - clear: Reset coloring to default.
    - palette: List common color names and hex values.
    - highlight_pattern: High-performance byte pattern search and color.
    """
    try:
        # Named colors palette (IDA uses BGR format internally)
        COLORS = {
            "red": 0x0000FF, "green": 0x00FF00, "blue": 0xFF0000,
            "yellow": 0x00FFFF, "cyan": 0xFFFF00, "magenta": 0xFF00FF,
            "orange": 0x0080FF, "white": 0xFFFFFF, "black": 0x000000,
            "default": 0xFFFFFFFF
        }
        
        def parse_color(c_str):
            if not c_str: return COLORS["yellow"]
            c_str = c_str.lower().strip().replace("#", "")
            if c_str in COLORS: return COLORS[c_str]
            try:
                if len(c_str) == 6:
                    r, g, b = int(c_str[0:2], 16), int(c_str[2:4], 16), int(c_str[4:6], 16)
                    return (b << 16) | (g << 8) | r
            except: pass
            return COLORS["yellow"]

        if action == "set_func":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            bgr = parse_color(color)
            func = ida_funcs.get_func(ea)
            curr = func.start_ea
            while curr < func.end_ea:
                idc.set_color(curr, idc.CIC_ITEM, bgr)
                curr = idc.next_head(curr, func.end_ea)
            return {"ok": True, "func": idc.get_func_name(func.start_ea), "color": color or "yellow"}

        elif action == "set_range":
            if not addr or not end_addr: return make_error(MCPError.INVALID_ARGS, "addr and end_addr required")
            ea, err = validate_addr(addr)
            if err: return err
            ee, err = validate_addr(end_addr)
            if err: return err
            
            bgr = parse_color(color)
            curr = ea
            while curr < ee:
                idc.set_color(curr, idc.CIC_ITEM, bgr)
                curr = idc.next_head(curr, ee)
            return {"ok": True, "start": hex(ea), "end": hex(ee)}

        elif action == "get":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            color = idc.get_color(ea, idc.CIC_ITEM)
            return {"ok": True, "addr": hex(ea), "color": hex(color)}

        elif action == "highlight_pattern":
            if not pattern: return make_error(MCPError.INVALID_ARGS, "pattern required")
            bgr = parse_color(color)
            
            pt = ida_bytes.compiled_binpat_vec_t()
            if ida_bytes.parse_binpat_str(pt, 0, pattern, 16):
                return make_error(MCPError.INVALID_ARGS, "Invalid pattern")
            
            matches = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                curr = seg.start_ea
                while len(matches) < 100:
                    ea, _ = ida_bytes.bin_search(curr, seg.end_ea, pt, ida_bytes.BIN_SEARCH_FORWARD)
                    if ea == idaapi.BADADDR: break
                    idc.set_color(ea, idc.CIC_ITEM, bgr)
                    matches.append(hex(ea))
                    curr = ea + 1
            return {"ok": True, "count": len(matches), "matches": matches[:20]}

        elif action == "clear":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            # If in function, clear function
            func = ida_funcs.get_func(ea)
            if func:
                curr = func.start_ea
                while curr < func.end_ea:
                    idc.set_color(curr, idc.CIC_ITEM, 0xFFFFFFFF)
                    curr = idc.next_head(curr, func.end_ea)
            else:
                idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFFFF)
            return {"ok": True, "cleared": hex(ea)}

        elif action == "palette":
            return {"ok": True, "colors": list(COLORS.keys())}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# DYNAMIC ANALYSIS TOOLS (36-39) - Static-friendly dynamic analysis helpers
# ============================================================================

# ============================================================================
# 36. TRACE_ANALYSIS - Post-mortem execution trace analysis
# ============================================================================
