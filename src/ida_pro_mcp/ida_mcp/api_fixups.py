"""Fixup/Relocation operations for IDA Pro MCP."""

from typing import Annotated

import ida_fixup
import ida_ida
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import normalize_list_input, parse_address


# Fixup type names
FIXUP_TYPES = {
    ida_fixup.FIXUP_OFF8: "off8",
    ida_fixup.FIXUP_OFF16: "off16",
    ida_fixup.FIXUP_OFF32: "off32",
    ida_fixup.FIXUP_SEG16: "seg16",
    ida_fixup.FIXUP_PTR16: "ptr16",
    ida_fixup.FIXUP_PTR32: "ptr32",
}


@tool
@idaread
def list_fixups(
    start: Annotated[str, "Start address"] = None,
    end: Annotated[str, "End address"] = None,
    limit: Annotated[int, "Max fixups to return"] = 1000
) -> list[dict]:
    """List fixups in address range"""
    fixups = []
    
    try:
        start_ea = parse_address(start) if start else ida_ida.inf_get_min_ea()
        end_ea = parse_address(end) if end else ida_ida.inf_get_max_ea()
        
        ea = ida_fixup.get_first_fixup_ea()
        count = 0
        
        while ea != idaapi.BADADDR and count < limit:
            if start_ea <= ea < end_ea:
                fd = ida_fixup.fixup_data_t()
                if ida_fixup.get_fixup(fd, ea):
                    fixups.append({
                        "addr": hex(ea),
                        "type": FIXUP_TYPES.get(fd.get_type(), f"type_{fd.get_type()}"),
                        "target": hex(fd.off) if hasattr(fd, 'off') else hex(fd.get_base()),
                    })
                    count += 1
            
            ea = ida_fixup.get_next_fixup_ea(ea)
            
    except Exception as e:
        return [{"error": str(e)}]
    
    return fixups


@tool
@idaread
def get_fixup(
    addrs: Annotated[list[str] | str, "Address(es) to get fixup info"]
) -> list[dict]:
    """Get fixup info at address(es)"""
    addrs = normalize_list_input(addrs)
    results = []
    
    for addr in addrs:
        try:
            ea = parse_address(addr)
            fd = ida_fixup.fixup_data_t()
            
            if ida_fixup.get_fixup(fd, ea):
                results.append({
                    "addr": addr,
                    "type": FIXUP_TYPES.get(fd.get_type(), f"type_{fd.get_type()}"),
                    "target": hex(fd.off) if hasattr(fd, 'off') else hex(fd.get_base()),
                    "ok": True
                })
            else:
                results.append({"addr": addr, "error": "No fixup at address"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def add_fixup(
    addr: Annotated[str, "Address for fixup"],
    target: Annotated[str, "Target address"],
    fixup_type: Annotated[str, "Type: off8/off16/off32"] = "off32"
) -> dict:
    """Add fixup at address"""
    try:
        ea = parse_address(addr)
        target_ea = parse_address(target)
        
        # Map type string to constant
        type_map = {
            "off8": ida_fixup.FIXUP_OFF8,
            "off16": ida_fixup.FIXUP_OFF16,
            "off32": ida_fixup.FIXUP_OFF32,
        }
        
        ft = type_map.get(fixup_type.lower(), ida_fixup.FIXUP_OFF32)
        
        fd = ida_fixup.fixup_data_t(ft, 0)
        fd.off = target_ea
        
        ida_fixup.set_fixup(ea, fd)
        return {"addr": addr, "target": target, "type": fixup_type, "ok": True}
        
    except Exception as e:
        return {"addr": addr, "error": str(e)}


@tool
@idawrite
def del_fixup(
    addrs: Annotated[list[str] | str, "Address(es) to delete fixup"]
) -> list[dict]:
    """Delete fixup(s)"""
    addrs = normalize_list_input(addrs)
    results = []
    
    for addr in addrs:
        try:
            ea = parse_address(addr)
            ida_fixup.del_fixup(ea)
            results.append({"addr": addr, "ok": True})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results
