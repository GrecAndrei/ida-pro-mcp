#!/usr/bin/env python3
"""
IDA MCP Daemon Tool Executor
Runs consolidated API tools in headless idat context.

This module provides the necessary shims to import and run
api_consolidated tools without the full MCP server stack.
"""

import json
import sys
import os
import traceback

# Path to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def execute_tool(idb_path: str, tool_name: str, args: dict, output_path: str):
    """
    Execute a tool from api_consolidated and write result to output_path.
    
    This function sets up the necessary shims for the decorators,
    imports the consolidated API, and runs the specified tool.
    """
    
    # Create shim modules for the decorators
    import types
    
    # Create rpc shim module
    rpc_module = types.ModuleType('rpc')
    
    # tool decorator - just returns the function unchanged
    def tool_shim(func):
        return func
    
    # unsafe decorator - just returns the function unchanged
    def unsafe_shim(func):
        return func
    
    rpc_module.tool = tool_shim
    rpc_module.unsafe = unsafe_shim
    sys.modules['rpc'] = rpc_module
    
    # Create sync shim module
    sync_module = types.ModuleType('sync')
    
    # idaread/idawrite decorators - just return the function unchanged
    # (we're already in IDA context)
    def idaread_shim(func):
        return func
    
    def idawrite_shim(func):
        return func
    
    class IDAError(Exception):
        pass
    
    sync_module.idaread = idaread_shim
    sync_module.idawrite = idawrite_shim
    sync_module.IDAError = IDAError
    sys.modules['sync'] = sync_module
    
    # Now import utils (it has no problematic imports)
    ida_mcp_path = os.path.join(SCRIPT_DIR, "src", "ida_pro_mcp", "ida_mcp")
    sys.path.insert(0, ida_mcp_path)
    
    try:
        # Import utils first
        from utils import (
            parse_address, normalize_list_input, normalize_dict_list,
            get_function, get_prototype, get_image_size, looks_like_address,
            get_stack_frame_variables_internal, get_type_by_name,
        )
        
        # Create utils shim  
        utils_module = types.ModuleType('utils')
        utils_module.parse_address = parse_address
        utils_module.normalize_list_input = normalize_list_input
        utils_module.normalize_dict_list = normalize_dict_list
        utils_module.get_function = get_function
        utils_module.get_prototype = get_prototype
        utils_module.get_image_size = get_image_size
        utils_module.looks_like_address = looks_like_address
        utils_module.get_stack_frame_variables_internal = get_stack_frame_variables_internal
        utils_module.get_type_by_name = get_type_by_name
        sys.modules['utils'] = utils_module
        
        # Now import api_consolidated
        import api_consolidated
        
        # Get the tool function
        if not hasattr(api_consolidated, tool_name):
            return {"error": f"Unknown tool: {tool_name}"}
        
        tool_func = getattr(api_consolidated, tool_name)
        
        # Execute the tool
        result = tool_func(**args)
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def main():
    """Main entry point when run as idat script."""
    # Args are passed via environment variables or a config file
    config_path = os.environ.get('IDA_MCP_CONFIG', '')
    
    if not config_path or not os.path.exists(config_path):
        print("ERROR: IDA_MCP_CONFIG not set or file not found")
        return
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    tool_name = config.get('tool', '')
    args = config.get('args', {})
    output_path = config.get('output', '')
    
    result = execute_tool('', tool_name, args, output_path)
    
    with open(output_path, 'w') as f:
        json.dump(result, f, default=str)
    
    import ida_pro
    ida_pro.qexit(0)


if __name__ == '__main__':
    main()
