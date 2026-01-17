
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
# 13. PLUGINS - Plugin operations
# ============================================================================

@tool
@unsafe
@idawrite
def plugins(
    action: Annotated[Literal["list", "run"], "Action: list|run"],
    name: Annotated[Optional[str], "Plugin name (for run)"] = None,
    arg: Annotated[int, "Plugin argument"] = 0,
    **kwargs
) -> dict:
    """
    Manage IDA plugins.
    
    Actions:
    - list: List loaded plugins (Note: May not be supported in newer IDA versions).
    - run: Run a plugin by name.
    
    Arguments:
    - name: Plugin name (e.g. "Hex-Rays Decompiler").
    - arg: Integer argument for the plugin run call.
    """
    try:
        import ida_loader
        
        if action == "list":
            # Plugin enumeration API removed in IDA 9
            return make_error(MCPError.NOT_IMPLEMENTED, "Plugin listing not supported in this IDA version")

        elif action == "run":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            # Try to run plugin by name
            plugin = ida_loader.find_plugin(name, True)
            if plugin in (None, -1):
                return make_error(MCPError.FILE_NOT_FOUND, f"Plugin not found: {name}")
            if ida_loader.run_plugin(plugin, arg):
                return {"ok": True, "name": name}
            return make_error(MCPError.IDA_ERROR, f"Failed to run plugin: {name}")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 14. TRACE - Trace operations
# ============================================================================
