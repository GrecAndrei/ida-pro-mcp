"""Function lifecycle operations for IDA Pro MCP."""

from typing import Annotated

import ida_funcs
import ida_name
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import normalize_list_input, normalize_dict_list, parse_address


@tool
@idawrite
def make_func(
    items: Annotated[list[dict] | dict, "Items with 'start' and optional 'end' addresses"]
) -> list[dict]:
    """Create function(s) at address range(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        start = item.get("start", "")
        end = item.get("end", "")
        
        try:
            start_ea = parse_address(start)
            end_ea = parse_address(end) if end else idaapi.BADADDR
            
            if ida_funcs.add_func(start_ea, end_ea):
                func = ida_funcs.get_func(start_ea)
                results.append({
                    "start": start,
                    "end": hex(func.end_ea) if func else end,
                    "ok": True
                })
            else:
                # Check if function already exists
                existing = ida_funcs.get_func(start_ea)
                if existing:
                    results.append({"start": start, "error": "Function already exists"})
                else:
                    results.append({"start": start, "error": "Failed to create function"})
        except Exception as e:
            results.append({"start": start, "error": str(e)})
    
    return results


@tool
@idawrite
def del_func(
    addrs: Annotated[list[str] | str, "Function address(es) to delete"]
) -> list[dict]:
    """Delete function(s)"""
    addrs = normalize_list_input(addrs)
    results = []
    
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                results.append({"addr": addr, "error": "No function at address"})
                continue
                
            if ida_funcs.del_func(func.start_ea):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def set_func_flags(
    items: Annotated[list[dict] | dict, "Items with 'addr' and 'flags' (FUNC_NORET, FUNC_LIB, etc)"]
) -> list[dict]:
    """Modify function flags"""
    items = normalize_dict_list(items)
    results = []
    
    # Flag name to value mapping
    FLAG_MAP = {
        "FUNC_NORET": ida_funcs.FUNC_NORET,
        "FUNC_FAR": ida_funcs.FUNC_FAR,
        "FUNC_LIB": ida_funcs.FUNC_LIB,
        "FUNC_STATIC": ida_funcs.FUNC_STATICDEF,
        "FUNC_FRAME": ida_funcs.FUNC_FRAME,
        "FUNC_USERFAR": ida_funcs.FUNC_USERFAR,
        "FUNC_HIDDEN": ida_funcs.FUNC_HIDDEN,
        "FUNC_THUNK": ida_funcs.FUNC_THUNK,
    }
    
    for item in items:
        addr = item.get("addr", "")
        flags = item.get("flags", [])
        clear = item.get("clear", False)
        
        try:
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                results.append({"addr": addr, "error": "No function"})
                continue
            
            # Parse flags
            flag_val = 0
            if isinstance(flags, str):
                flags = [f.strip() for f in flags.split(",")]
            
            for f in flags:
                if f.upper() in FLAG_MAP:
                    flag_val |= FLAG_MAP[f.upper()]
                elif f.isdigit():
                    flag_val |= int(f)
            
            if clear:
                func.flags &= ~flag_val
            else:
                func.flags |= flag_val
            
            ida_funcs.update_func(func)
            results.append({"addr": addr, "flags": hex(func.flags), "ok": True})
            
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def func_cmt(
    items: Annotated[list[dict] | dict, "Items with 'addr', 'cmt', optional 'repeatable'"]
) -> list[dict]:
    """Set/get function comment(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        cmt = item.get("cmt", None)
        repeatable = item.get("repeatable", True)
        
        try:
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            
            if not func:
                results.append({"addr": addr, "error": "No function"})
                continue
            
            if cmt is not None:
                # Set comment
                ida_funcs.set_func_cmt(func, cmt, repeatable)
                results.append({"addr": addr, "ok": True})
            else:
                # Get comment
                existing = ida_funcs.get_func_cmt(func, repeatable)
                results.append({"addr": addr, "cmt": existing or ""})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results
