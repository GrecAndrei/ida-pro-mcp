
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
# 36. TRACE_ANALYSIS - Post-mortem execution trace analysis
# ============================================================================

@tool
@idaread
def trace_analysis(
    action: Annotated[Literal["import_trace", "analyze_coverage", "find_loops", "extract_api_calls", "basic_blocks_hit"],
                      "Action: import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit"],
    path: Annotated[Optional[str], "Path to trace file"] = None,
    addr: Annotated[Optional[str], "Function or address to analyze"] = None,
    trace_data: Annotated[Optional[list], "List of executed addresses"] = None,
    **kwargs
) -> dict:
    """
    Post-mortem execution trace analysis.
    
    Actions:
    - import_trace: Load a list of addresses from a file or 'trace_data' parameter.
    - analyze_coverage: Calculate global basic block coverage based on the current trace.
    - find_loops: Identify the most frequently executed code regions (hot spots).
    - extract_api_calls: Find and count imported API calls matching the trace.
    - basic_blocks_hit: Per-function block-level coverage analysis.
        Params: addr (optional - defaults to entry point)
    """
    try:
        def load_trace():
            if trace_data and isinstance(trace_data, list):
                return set([int(str(a), 0) for a in trace_data])
            if path:
                p, err = validate_path_safe(path)
                if err: return set()
                addrs = set()
                with open(p, 'r') as f:
                    for line in f:
                        try: addrs.add(int(line.strip(), 0))
                        except: pass
                return addrs
            return set()

        if action == "import_trace":
            if not path and not trace_data:
                return make_error(MCPError.INVALID_ARGS, "path or trace_data required")
            addrs = load_trace()
            return {"ok": True, "path": path, "count": len(addrs), "unique": len(addrs)}
        
        elif action == "analyze_coverage":
            trace_set = load_trace()
            if not trace_set: return make_error(MCPError.INVALID_ARGS, "No trace data")
            
            total_blocks, hit_blocks = 0, 0
            for ea in idautils.Functions():
                func = idaapi.get_func(ea)
                if not func: continue
                for block in idaapi.FlowChart(func):
                    total_blocks += 1
                    # Efficient intersection check
                    if any(a in trace_set for a in range(block.start_ea, block.end_ea)):
                        hit_blocks += 1
            
            return {"ok": True, "total": total_blocks, "hit": hit_blocks, "pct": round(hit_blocks/total_blocks*100, 2) if total_blocks else 0}

        elif action == "find_loops":
            # Requires full list for frequency
            t_list = list(load_trace())
            if not t_list: return make_error(MCPError.INVALID_ARGS, "No trace data")
            from collections import Counter
            loops = []
            for ea, count in Counter(t_list).most_common(20):
                if count > 5:
                    f = ida_funcs.get_func(ea)
                    loops.append({"addr": hex(ea), "hits": count, "func": idc.get_func_name(f.start_ea) if f else None})
            return {"ok": True, "hot_spots": loops}

        elif action == "extract_api_calls":
            trace_set = load_trace()
            calls = []
            for ea in trace_set:
                for xref in idautils.XrefsFrom(ea):
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        name = idc.get_name(xref.to)
                        if name and not name.startswith("sub_"):
                            calls.append(name)
            from collections import Counter
            return {"ok": True, "api_calls": Counter(calls).most_common(50)}

        if action == "basic_blocks_hit":
            trace_set = load_trace()
            if not trace_set: return make_error(MCPError.INVALID_ARGS, "No trace data loaded", "Run import_trace first")
            
            # Entry point resolution compatible with IDA 7.x-9.x
            try:
                start_ea = idaapi.get_inf_structure().start_ea
            except AttributeError:
                import ida_ida
                start_ea = ida_ida.inf_get_start_ea()
                
            target = addr or hex(start_ea)
            ea, err = validate_addr(target, require_func=True)
            if err: return err
            
            blocks = []
            for block in idaapi.FlowChart(ida_funcs.get_func(ea)):
                hit = any(a in trace_set for a in range(block.start_ea, block.end_ea))
                blocks.append({"start": hex(block.start_ea), "end": hex(block.end_ea), "hit": hit})
            return {"ok": True, "function": idc.get_func_name(ea), "blocks": blocks}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================
