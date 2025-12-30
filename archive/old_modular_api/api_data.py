"""Data definition operations for IDA Pro MCP."""

from typing import Annotated

import ida_bytes
import ida_nalt
import idaapi
import idc

from .rpc import tool
from .sync import idawrite
from .utils import normalize_list_input, normalize_dict_list, parse_address


# Data type constants
DATA_TYPES = {
    "byte": (ida_bytes.FF_BYTE, 1),
    "word": (ida_bytes.FF_WORD, 2),
    "dword": (ida_bytes.FF_DWORD, 4),
    "qword": (ida_bytes.FF_QWORD, 8),
    "float": (ida_bytes.FF_FLOAT, 4),
    "double": (ida_bytes.FF_DOUBLE, 8),
}


@tool
@idawrite
def make_data(
    items: Annotated[list[dict] | dict, "Items with 'addr', 'type' (byte/word/dword/qword)"]
) -> list[dict]:
    """Define data item(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        dtype = item.get("type", "byte").lower()
        
        try:
            ea = parse_address(addr)
            
            if dtype not in DATA_TYPES:
                results.append({"addr": addr, "error": f"Unknown type: {dtype}"})
                continue
            
            flags, size = DATA_TYPES[dtype]
            
            if idc.create_data(ea, flags, size, idaapi.BADADDR):
                results.append({"addr": addr, "type": dtype, "size": size, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to create data"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def make_array(
    items: Annotated[list[dict] | dict, "Items with 'addr', 'count', optional 'type'"]
) -> list[dict]:
    """Create array(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        count = item.get("count", 0)
        dtype = item.get("type", "byte").lower()
        
        try:
            ea = parse_address(addr)
            
            if dtype not in DATA_TYPES:
                results.append({"addr": addr, "error": f"Unknown type: {dtype}"})
                continue
            
            flags, elem_size = DATA_TYPES[dtype]
            
            # First define the element type
            idc.create_data(ea, flags, elem_size, idaapi.BADADDR)
            
            # Then make it an array
            if idc.make_array(ea, count):
                results.append({
                    "addr": addr,
                    "type": dtype,
                    "count": count,
                    "size": count * elem_size,
                    "ok": True
                })
            else:
                results.append({"addr": addr, "error": "Failed to create array"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def make_str(
    items: Annotated[list[dict] | dict, "Items with 'addr', optional 'len', 'strtype'"]
) -> list[dict]:
    """Create string literal(s)"""
    items = normalize_dict_list(items)
    results = []
    
    # String type mapping
    STR_TYPES = {
        "c": ida_nalt.STRTYPE_C,
        "pascal": ida_nalt.STRTYPE_PASCAL,
        "unicode": ida_nalt.STRTYPE_C_16,
        "utf16": ida_nalt.STRTYPE_C_16,
        "utf32": ida_nalt.STRTYPE_C_32,
    }
    
    for item in items:
        addr = item.get("addr", "")
        length = item.get("len", -1)  # -1 means auto-detect
        strtype = item.get("strtype", "c").lower()
        
        try:
            ea = parse_address(addr)
            st = STR_TYPES.get(strtype, ida_nalt.STRTYPE_C)
            
            if idc.create_strlit(ea, length if length > 0 else idaapi.BADADDR, st):
                # Get the created string
                content = idc.get_strlit_contents(ea, -1, st)
                results.append({
                    "addr": addr,
                    "strtype": strtype,
                    "value": content.decode() if content else "",
                    "ok": True
                })
            else:
                results.append({"addr": addr, "error": "Failed to create string"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def undefine(
    items: Annotated[list[dict] | dict, "Items with 'addr', optional 'size'"]
) -> list[dict]:
    """Undefine byte(s) - remove code/data definition"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        size = item.get("size", 1)
        
        try:
            ea = parse_address(addr)
            
            if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
                results.append({"addr": addr, "size": size, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to undefine"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results
