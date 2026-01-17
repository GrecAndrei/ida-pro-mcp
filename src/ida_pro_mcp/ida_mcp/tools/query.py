"""
Unified Query Hub - Routes queries to appropriate tools.
This provides a single entry point for all read operations.
"""

from typing import Annotated, Optional, Literal, Any
import sys
import os

# Infrastructure discovery
try:
    from ida_mcp.rpc import tool
    from ida_mcp.sync import idaread
    from ida_mcp.error_handling import MCPError, make_error, handle_error
except (ImportError, ValueError):
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
    from rpc import tool
    from sync import idaread
    from error_handling import MCPError, make_error, handle_error


@tool
@idaread
def query(
    action: Annotated[Literal["data", "search", "idb", "code", "types"],
                      "Action: data|search|idb|code|types"],
    subaction: Annotated[Optional[str], "Sub-action to perform"] = None,
    args: Annotated[Optional[dict], "Arguments to pass to sub-tool"] = None,
    **kwargs
) -> dict:
    """
    Unified query hub - single entry point for all read operations.
    
    This tool routes queries to the appropriate underlying tool, reducing
    the number of tools an LLM needs to remember.
    
    ACTIONS:
    
    data - Query binary data (functions, strings, imports, exports)
        subaction: functions|strings|imports|exports|globals|lookup
        args: {count, offset, query, addr, ...}
        Example: query(action="data", subaction="functions", args={"count": 10})
        
    search - Search the binary
        subaction: find|callers|callees|api|name|bytes|string
        args: {pattern, limit, ...}
        Example: query(action="search", subaction="find", args={"pattern": "malloc"})
        
    idb - Query database metadata
        subaction: meta|summary|segments|entrypoints
        Example: query(action="idb", subaction="summary")
        
    code - Query code at address
        subaction: decompile|disasm|xrefs_to|xrefs_from|callers|callees
        args: {addr, count, ...}
        Example: query(action="code", subaction="decompile", args={"addr": "0x401000"})
        
    types - Query type information
        subaction: list|get|search_structs
        args: {query, name, ...}
        Example: query(action="types", subaction="list", args={"count": 20})
    """
    try:
        args = args or {}
        
        if action == "data":
            from .data import data as data_tool
            sub = subaction or "functions"
            return data_tool(action=sub, **args)
            
        elif action == "search":
            from .search import search as search_tool
            sub = subaction or "find"
            return search_tool(action=sub, **args)
            
        elif action == "idb":
            from .idb import idb as idb_tool
            sub = subaction or "summary"
            return idb_tool(action=sub, **args)
            
        elif action == "code":
            from .code import code as code_tool
            sub = subaction or "disasm"
            return code_tool(action=sub, **args)
            
        elif action == "types":
            from .types import types as types_tool
            sub = subaction or "list"
            return types_tool(action=sub, **args)
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
