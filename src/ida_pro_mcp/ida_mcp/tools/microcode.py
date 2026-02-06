
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
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================

@tool
@idaread
def microcode(
    action: Annotated[Literal["get", "blocks", "instructions"], "Action: get|blocks|instructions"],
    addr: Annotated[str, "Function address"],
    maturity: Annotated[int, "Optimization maturity level (0-7)"] = 3,
    **kwargs
) -> dict:
    """
    Access Hex-Rays Microcode (IR) for low-level decompiler analysis.
    
    Actions:
    - get: Get high-level microcode summary for function.
    - blocks: List all micro-blocks (mblock_t) in the function.
    - instructions: List all micro-instructions (minsn_t) in the function.
    """
    try:
        ea, err = validate_addr(addr, require_func=True)
        if err: return err
        
        # Microcode requires Hex-Rays
        if not ida_hexrays.init_hexrays_plugin():
            return make_error(MCPError.IDA_ERROR, "Hex-Rays decompiler not available")
            
        func = ida_funcs.get_func(ea)
        if not func: return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
        
        # IDA 9.2 requires mba_ranges_t
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        # gen_microcode(mbr, hf, retlist, decomp_flags, reqmat)
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, maturity)
        
        if not mba: return make_error(MCPError.IDA_ERROR, f"Failed to generate microcode: {hf.str}")
        
        func_name = idc.get_func_name(ea)
        
        if action == "get":
            return {"ok": True, "function": func_name, "blocks_count": mba.qty, "maturity": maturity}
            
        elif action == "blocks":
            block_lines = []
            for i in range(mba.qty):
                block = mba.get_mblock(i)
                block_lines.append(f"{i}  {hex(block.start)}-{hex(block.end)}  type={block.type}")
            return {"ok": True, "function": func_name, "blocks": "\n".join(block_lines), "count": len(block_lines)}
            
        elif action == "instructions":
            instr_lines = []
            # Iterate through blocks and instructions
            for i in range(mba.qty):
                block = mba.get_mblock(i)
                curr = block.head
                while curr:
                    # Use print1 instead of str() for better performance
                    text = ida_lines.tag_remove(curr.d.print1())
                    instr_lines.append(f"{hex(curr.ea)}  {text}")
                    curr = curr.next
                    if len(instr_lines) >= 500: break
                if len(instr_lines) >= 500: break
            return {"ok": True, "function": func_name, "instructions": "\n".join(instr_lines), "count": len(instr_lines)}
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================
