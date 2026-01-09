
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
# 27. EMULATE - Code Emulation and Snippet Execution
# ============================================================================

@tool
@idaread
def emulate(
    action: Annotated[Literal["static_trace", "appcall", "decrypt_strings", "eval_expr"],
                      "Action: static_trace|appcall|decrypt_strings|eval_expr"],
    addr: Annotated[Optional[str], "Address to trace from or function to call"] = None,
    func_name: Annotated[Optional[str], "Function name for appcall"] = None,
    args: Annotated[Optional[list], "Arguments for appcall"] = None,
    max_steps: Annotated[int, "Maximum instructions to trace"] = 1000,
    **kwargs
) -> dict:
    """
    Tracing and dynamic execution utilities.
    
    Actions:
    - static_trace: Follow control flow from `addr` statically (no register changes).
    - appcall: Call a function with arguments (requires active debugger).
    - decrypt_strings: Heuristic search for string decryption calls.
    - eval_expr: Evaluate value/name at address.
    """
    try:
        if action == "static_trace":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            trace = []
            visited = {ea}
            queue = [ea]
            
            while queue and len(trace) < max_steps:
                curr = queue.pop(0)
                insn = idaapi.insn_t()
                if ida_bytes.decode_insn(insn, curr) <= 0: continue
                
                disasm = idc.generate_disasm_line(curr, 0)
                trace.append({"addr": hex(curr), "disasm": ida_lines.tag_remove(disasm) if disasm else ""})
                
                # Simple flow following
                if idaapi.is_ret_insn(insn): continue
                
                # Get next heads/branches
                next_heads = []
                for xref in idautils.XrefsFrom(curr, 0):
                    if xref.iscode: next_heads.append(xref.to)
                
                if not next_heads: # Fallthrough
                    next_heads.append(idc.next_head(curr))
                    
                for n in next_heads:
                    if n != idaapi.BADADDR and n not in visited:
                        # Only follow if within same function or limited depth
                        if not func or (n >= func.start_ea and n < func.end_ea):
                            visited.add(n)
                            queue.append(n)
            
            return {"ok": True, "start": hex(ea), "trace": trace, "count": len(trace)}
        
        elif action == "appcall":
            if not hasattr(idaapi, 'Appcall'): return make_error(MCPError.NOT_IMPLEMENTED, "Appcall not available")
            
            import ida_dbg
            if not ida_dbg.is_debugger_on():
                return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Appcall requires a running debug session")
            
            if not func_name and not addr: return make_error(MCPError.INVALID_ARGS, "func_name or addr required")
            
            # Resolve address
            ea = idc.get_name_ea_simple(func_name) if func_name else parse_address(addr)
            if ea == idaapi.BADADDR: return make_error(MCPError.ADDRESS_INVALID, f"Function not found: {func_name or addr}")
            
            try:
                # Use Appcall
                result = idaapi.Appcall.func_ptr(ea)(*(args or []))
                return {"ok": True, "function": func_name or hex(ea), "return_value": str(result)}
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Appcall failed: {e}")
        
        elif action == "decrypt_strings":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            calls = []
            for xref in idautils.XrefsTo(ea):
                if xref.iscode:
                    # Look for string args in proximity
                    prev = idc.prev_head(xref.frm)
                    for _ in range(5):
                        if prev == idaapi.BADADDR: break
                        for op_n in range(2):
                            val = idc.get_operand_value(prev, op_n)
                            s = idc.get_strlit_contents(val)
                            if s:
                                calls.append({"call_site": hex(xref.frm), "string_addr": hex(val), "encrypted": s.decode('utf-8', 'replace')})
                        prev = idc.prev_head(prev)
            return {"ok": True, "decrypt_function": hex(ea), "potential_calls": calls}
        
        elif action == "eval_expr":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            return {
                "ok": True,
                "addr": hex(ea),
                "u8": ida_bytes.get_byte(ea),
                "u16": ida_bytes.get_word(ea),
                "u32": ida_bytes.get_dword(ea),
                "u64": ida_bytes.get_qword(ea),
                "name": idc.get_name(ea)
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 28. EXPORT - Export Database in Various Formats
# ============================================================================
