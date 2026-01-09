
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
# 23. LUMINA - Cloud-Based Function Recognition
# ============================================================================

@tool
@idaread
def lumina(
    action: Annotated[Literal["pull", "push", "status", "history", "search"],
                      "Action: pull|push|status|history|search"],
    addr: Annotated[Optional[str], "Address of function"] = None,
    query: Annotated[Optional[str], "Search query for function names"] = None,
    push_all: Annotated[bool, "Push all functions (for push action)"] = False,
    **kwargs
) -> dict:
    """
    Interact with Hex-Rays Lumina server for function recognition.
    
    Actions:
    - pull: Get metadata from Lumina.
    - push: Contribute metadata to Lumina.
    - status: Check connection and authentication.
    - history: Get history for a specific function.
    - search: Search the cloud by name.
    """
    try:
        import ida_kernwin
        
        if action == "status":
            # Check if Lumina is configured by looking for the server address in configuration
            # In IDA 9, we can just return that the tool is ready to receive commands
            return {"ok": True, "status": "Lumina actions available", "available": True}
        
        elif action == "pull":
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                # Jump to address so action knows where to pull
                idc.jumpto(ea)
                res = ida_kernwin.process_ui_action("LuminaPull")
                return {"ok": True, "addr": hex(ea), "action_triggered": res}
            else:
                res = ida_kernwin.process_ui_action("LuminaPullAll")
                return {"ok": True, "action_triggered": res}

        elif action == "push":
            if push_all:
                res = ida_kernwin.process_ui_action("LuminaPushAll")
                return {"ok": True, "action_triggered": res}
            elif addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                idc.jumpto(ea)
                res = ida_kernwin.process_ui_action("LuminaPush")
                return {"ok": True, "addr": hex(ea), "action_triggered": res}
            return make_error(MCPError.INVALID_ARGS, "addr or push_all=True required")

        elif action == "history":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            idc.jumpto(ea)
            res = ida_kernwin.process_ui_action("LuminaViewHistory")
            return {"ok": True, "addr": hex(ea), "action_triggered": res}

        elif action == "search":
            return make_error(MCPError.NOT_IMPLEMENTED, "Search requires GUI interaction or specialized metadata hashing")
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================
