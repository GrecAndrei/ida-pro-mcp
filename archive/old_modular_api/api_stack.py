"""Stack frame operations for IDA Pro MCP.

CONSOLIDATED: Single tool with action parameter.
"""

from typing import Annotated, Literal, Optional
import ida_typeinf
import ida_frame
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    get_stack_frame_variables_internal,
)


@tool
@idawrite
def stack(
    action: Annotated[Literal["get", "declare", "delete"], "Action: get|declare|delete"],
    addr: Annotated[Optional[str], "Function address"] = None,
    addrs: Annotated[Optional[list[str] | str], "Multiple addresses (for get)"] = None,
    name: Annotated[Optional[str], "Variable name (for declare/delete)"] = None,
    offset: Annotated[Optional[str], "Stack offset (for declare)"] = None,
    type: Annotated[Optional[str], "Type name (for declare)"] = None,
) -> dict | list[dict]:
    """Unified stack frame operations: get vars, declare var, delete var"""
    try:
        if action == "get":
            # Get stack frame variables
            target_addrs = normalize_list_input(addrs or addr or [])
            if not target_addrs:
                return {"error": "addr or addrs required for get"}
            
            results = []
            for a in target_addrs:
                try:
                    ea = parse_address(a)
                    vars = get_stack_frame_variables_internal(ea, True)
                    results.append({"addr": a, "vars": vars})
                except Exception as e:
                    results.append({"addr": a, "error": str(e)})
            return results
        
        elif action == "declare":
            # Declare stack variable
            if not addr or not name or not offset or not type:
                return {"error": "addr, name, offset, and type required for declare"}
            
            func = idaapi.get_func(parse_address(addr))
            if not func:
                return {"error": "No function at address"}
            
            off = parse_address(offset)
            
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                return {"error": "No frame for function"}
            
            tif = get_type_by_name(type)
            if not ida_frame.define_stkvar(func, name, off, tif):
                return {"error": "Failed to define stack var"}
            
            return {"addr": addr, "name": name, "offset": offset, "ok": True}
        
        elif action == "delete":
            # Delete stack variable
            if not addr or not name:
                return {"error": "addr and name required for delete"}
            
            func = idaapi.get_func(parse_address(addr))
            if not func:
                return {"error": "No function at address"}
            
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                return {"error": "No frame for function"}
            
            idx, udm = frame_tif.get_udm(name)
            if not udm:
                return {"error": f"Variable '{name}' not found in frame"}
            
            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                return {"error": f"'{name}' is special frame member"}
            
            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            off = udm.offset // 8
            size = udm.size // 8
            
            if ida_frame.is_funcarg_off(func, off):
                return {"error": f"'{name}' is function argument"}
            
            if not ida_frame.delete_frame_members(func, off, off + size):
                return {"error": "Failed to delete"}
            
            return {"addr": addr, "name": name, "ok": True}
        
        else:
            return {"error": f"Unknown action: {action}. Valid: get|declare|delete"}
    
    except Exception as e:
        return {"error": str(e)}
