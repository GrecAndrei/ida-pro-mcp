
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
        def action_available(action_name):
            try:
                return ida_kernwin.find_action(action_name) is not None
            except Exception:
                return False

        def run_action(action_name, note=None):
            if not action_available(action_name):
                return make_error(MCPError.NOT_IMPLEMENTED, f"Action not available: {action_name}", details={"action": action_name})
            res = ida_kernwin.process_ui_action(action_name)
            payload = {"ok": True, "action": action_name, "action_triggered": res}
            if note:
                payload["note"] = note
            return payload

        if action == "status":
            actions = [
                "LuminaPull",
                "LuminaPullAll",
                "LuminaPush",
                "LuminaPushAll",
                "LuminaViewHistory",
            ]
            availability = {a: action_available(a) for a in actions}
            details = {"actions": availability}
            try:
                import ida_lumina
                details["module_loaded"] = True
                for attr in ["is_inited", "is_connected", "get_lumina_server"]:
                    if hasattr(ida_lumina, attr):
                        try:
                            details[attr] = getattr(ida_lumina, attr)()
                        except Exception:
                            details[attr] = None
            except Exception:
                details["module_loaded"] = False
            return {"ok": True, "status": "Lumina actions inspected", "details": details}

        elif action == "pull":
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                idc.jumpto(ea)
                return run_action("LuminaPull", note="Pulled metadata for current function")
            return run_action("LuminaPullAll", note="Pulled metadata for all functions")

        elif action == "push":
            if push_all:
                return run_action("LuminaPushAll", note="Pushed metadata for all functions")
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                idc.jumpto(ea)
                return run_action("LuminaPush", note="Pushed metadata for current function")
            return make_error(MCPError.INVALID_ARGS, "addr or push_all=True required")

        elif action == "history":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            idc.jumpto(ea)
            return run_action("LuminaViewHistory", note="Opened Lumina history for current function")

        elif action == "search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            return make_error(MCPError.NOT_IMPLEMENTED, "Search requires interactive UI or Lumina client integration")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================  
# 24. SYMBOLS# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================
