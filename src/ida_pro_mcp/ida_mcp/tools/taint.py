
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
# 38. TAINT - Static Taint/Data Flow Analysis
# ============================================================================

@tool
@idaread
def taint(
    action: Annotated[Literal["find_arg_usage", "trace_return", "find_sinks", "data_flow", "backward_trace", "slice"],
                      "Action: find_arg_usage|trace_return|find_sinks|data_flow|backward_trace|slice"],
    addr: Annotated[Optional[str], "Function or instruction address"] = None,
    arg_num: Annotated[int, "Argument number to trace (0-indexed)"] = 0,
    depth: Annotated[int, "Analysis depth"] = 5,
    **kwargs
) -> dict:
    """
    Static data flow and vulnerability triage utilities.
    
    Actions:
    - find_arg_usage: Identify how a function argument is used in pseudocode.
    - trace_return: Find where a function's return value is used by callers.
    - find_sinks: Find dangerous API calls (system, exec, etc.) reachable from `addr`.
    - data_flow: High-level input/output analysis for a function.
    - backward_trace: Linear backward instruction trace from `addr`.
    - slice: Heuristic argument-to-sink slice using decompiler output.
    """
    try:
        DANGEROUS_SINKS = {
            "network": ["send", "recv", "connect", "WSA", "accept", "http", "curl"],
            "exec": ["system", "exec", "popen", "ShellExecute", "CreateProcess", "eval"],
            "mem": ["VirtualAlloc", "VirtualProtect", "mmap", "mprotect", "memcpy", "strcpy", "gets"],
            "file": ["CreateFile", "ReadFile", "WriteFile", "fopen", "open"]
        }
        
        if action == "find_arg_usage":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc: return make_error(MCPError.IDA_ERROR, "Decompilation failed")
                
                args = [v for v in cfunc.lvars if v.is_arg_var]
                if arg_num >= len(args): return make_error(MCPError.INVALID_ARGS, f"Function only has {len(args)} args")
                
                target = args[arg_num]
                return {
                    "ok": True,
                    "function": idc.get_func_name(ea),
                    "arg": {"name": target.name, "type": str(target.type())},
                    "note": "Use 'ctree' tool to trace specific operations using this variable."
                }
            except: return make_error(MCPError.IDA_ERROR, "Decompiler required for arg usage")
        
        elif action == "find_sinks":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            sinks = []
            visited = {ea}
            queue = [(ea, 0)]
            
            while queue and len(sinks) < 50:
                curr_ea, curr_depth = queue.pop(0)
                if curr_depth >= depth: continue
                
                func = ida_funcs.get_func(curr_ea)
                if not func: continue
                
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            name = idc.get_name(xref.to)
                            if name:
                                # Check sinks
                                for cat, patterns in DANGEROUS_SINKS.items():
                                    if any(p.lower() in name.lower() for p in patterns):
                                        sinks.append({"name": name, "addr": hex(xref.to), "site": hex(item), "category": cat, "depth": curr_depth})
                                        break
                                
                                if xref.to not in visited:
                                    visited.add(xref.to)
                                    queue.append((xref.to, curr_depth + 1))
            
            return {"ok": True, "start": hex(ea), "sinks": sinks}

        elif action == "trace_return":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            results = []
            for xref in idautils.XrefsTo(ea):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                    next_ea = idc.next_head(xref.frm)
                    results.append({
                        "call_site": hex(xref.frm),
                        "caller": idc.get_func_name(xref.frm),
                        "next_insn": ida_lines.tag_remove(idc.generate_disasm_line(next_ea, 0)) if next_ea != idaapi.BADADDR else None
                    })
            return {"ok": True, "function": idc.get_func_name(ea), "usages": results[:50]}

        elif action == "backward_trace":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            trace = []
            curr = ea
            for _ in range(depth * 10): # Trace back N instructions
                curr = idc.prev_head(curr)
                if curr == idaapi.BADADDR or (func and curr < func.start_ea): break
                trace.append({"addr": hex(curr), "disasm": ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))})
            
            return {"ok": True, "target": hex(ea), "trace": list(reversed(trace))}

        elif action == "slice":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err

            if not ida_hexrays.init_hexrays_plugin():
                return make_error(MCPError.IDA_ERROR, "Decompiler required for slice")

            try:
                cfunc = ida_hexrays.decompile(ea)
                if not cfunc:
                    return make_error(MCPError.IDA_ERROR, "Decompilation failed")

                args = [v for v in cfunc.lvars if v.is_arg_var]
                if arg_num >= len(args):
                    return make_error(MCPError.INVALID_ARGS, f"Function only has {len(args)} args")
                arg_name = args[arg_num].name

                text = str(cfunc)
                lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

                sinks = []
                for cat, patterns in DANGEROUS_SINKS.items():
                    for ln in lines:
                        if arg_name in ln and any(p.lower() in ln.lower() for p in patterns):
                            sinks.append({"category": cat, "line": ln})
                            if len(sinks) >= 50:
                                break
                    if len(sinks) >= 50:
                        break

                return {
                    "ok": True,
                    "function": idc.get_func_name(ea),
                    "arg": {"name": arg_name, "type": str(args[arg_num].type())},
                    "sinks": sinks,
                    "note": "Heuristic slice based on decompiler text; confirm in ctree for precision."
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Slice failed: {e}")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 39. COVERAGE - Code Coverage Import and Analysis
# ============================================================================
