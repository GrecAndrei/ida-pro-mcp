"""
Unified Edit Hub - Routes edit operations to appropriate tools.
This provides a single entry point for all write operations.
"""

from typing import Annotated, Optional, Literal, Any
import sys
import os

# Infrastructure discovery
try:
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idawrite
    from ida_mcp.error_handling import MCPError, make_error, handle_error
except (ImportError, ValueError):
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
    from rpc import tool, unsafe
    from sync import idawrite
    from error_handling import MCPError, make_error, handle_error


@tool
@unsafe
@idawrite
def edit(
    action: Annotated[Literal["rename", "comment", "type", "patch", "create_func", "bulk"],
                      "Action: rename|comment|type|patch|create_func|bulk"],
    addr: Annotated[Optional[str], "Address to edit"] = None,
    value: Annotated[Optional[str], "New value (name, comment text, or type)"] = None,
    items: Annotated[Optional[list], "List of items for bulk operations"] = None,
    subaction: Annotated[Optional[str], "Sub-action for complex operations"] = None,
    args: Annotated[Optional[dict], "Additional arguments"] = None,
    **kwargs
) -> dict:
    """
    Unified edit hub - single entry point for all write operations.
    
    This tool routes edits to the appropriate underlying tool, making
    modifications simpler and more consistent.
    
    QUICK ACTIONS:
    
    rename - Rename a symbol at address
        Params: addr, value (new name)
        Example: edit(action="rename", addr="0x401000", value="parse_config")
        
    comment - Add/update a comment at address
        Params: addr, value (comment text)
        Example: edit(action="comment", addr="0x401000", value="Initialize configuration")
        
    type - Set type at address
        Params: addr, value (type declaration)
        Example: edit(action="type", addr="0x401000", value="int __cdecl(int argc, char **argv)")
        
    patch - Patch bytes/instruction at address
        Params: addr, value (bytes as hex string or assembly)
        args: {asm: true} to assemble instruction
        Example: edit(action="patch", addr="0x401000", value="90 90")  # NOP NOP
        
    create_func - Create a function at address
        Params: addr
        Example: edit(action="create_func", addr="0x401000")
        
    bulk - Bulk operations
        Params: items (list of {addr, value, action?})
        subaction: rename|comment|type
        Example: edit(action="bulk", subaction="rename", items=[{"addr": "0x401000", "value": "func1"}])
    """
    try:
        args = args or {}
        
        if action == "rename":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (new name) required")
            from .modify import modify as modify_tool
            return modify_tool(action="rename", addr=addr, value=value)
            
        elif action == "comment":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (comment text) required")
            from .modify import modify as modify_tool
            return modify_tool(action="comment", addr=addr, value=value, **args)
            
        elif action == "type":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (type declaration) required")
            from .modify import modify as modify_tool
            return modify_tool(action="set_type", addr=addr, value=value)
            
        elif action == "patch":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if not value:
                return make_error(MCPError.INVALID_ARGS, "value (bytes or asm) required")
            from .modify import modify as modify_tool
            if args.get("asm"):
                return modify_tool(action="patch_asm", addr=addr, value=value)
            else:
                # Direct byte patching
                from .data_ops import data_ops as data_ops_tool
                return data_ops_tool(action="patch", addr=addr, bytes=value)
            
        elif action == "create_func":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            from .funcs import funcs as funcs_tool
            return funcs_tool(action="create", addr=addr)
            
        elif action == "bulk":
            if not items:
                return make_error(MCPError.INVALID_ARGS, "items required for bulk operations")
            sub = subaction or "rename"
            from .bulk import bulk as bulk_tool
            return bulk_tool(action=sub, items=items, **args)
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
