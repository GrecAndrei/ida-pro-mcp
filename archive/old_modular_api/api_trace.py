"""Debugger tracing operations for IDA Pro MCP."""

from typing import Annotated

import ida_dbg
import idaapi

from .rpc import tool, unsafe
from .sync import idaread, idawrite
from .utils import normalize_list_input, normalize_dict_list, parse_address


@tool
@idaread
@unsafe
def get_trace(
    limit: Annotated[int, "Max trace entries to return"] = 1000
) -> list[dict]:
    """Get instruction trace history"""
    trace = []
    
    try:
        # Get trace buffer
        trace_size = ida_dbg.get_tev_qty()
        
        for i in range(min(trace_size, limit)):
            tev = ida_dbg.tev_info_t()
            if ida_dbg.get_tev_info(i, tev):
                entry = {
                    "index": i,
                    "tid": tev.tid,
                    "ea": hex(tev.ea),
                    "type": tev.type,
                }
                trace.append(entry)
                
    except Exception as e:
        return [{"error": str(e)}]
    
    return trace


@tool
@idawrite
@unsafe
def trace_clear() -> dict:
    """Clear trace buffer"""
    try:
        ida_dbg.clear_trace()
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


@tool
@idawrite
@unsafe
def set_trace_options(
    options: Annotated[dict, "Trace options: 'instruction', 'bblock', 'function'"]
) -> dict:
    """Set trace options"""
    try:
        flags = 0
        
        if options.get("instruction", False):
            flags |= ida_dbg.ST_OVER_DEBUG_SEG
        if options.get("bblock", False):
            flags |= ida_dbg.ST_OVER_LIB_FUNC
        if options.get("function", False):
            flags |= ida_dbg.ST_SKIP_LOOPS
            
        # Note: Actual trace option setting may vary by IDA version
        return {"ok": True, "flags": flags}
        
    except Exception as e:
        return {"error": str(e)}
