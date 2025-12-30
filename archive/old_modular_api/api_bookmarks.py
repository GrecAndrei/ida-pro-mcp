"""Bookmark operations for IDA Pro MCP.

CONSOLIDATED: Single tool with action parameter.
Compatible with IDA 8.x (ida_bookmarks) and IDA 9.0+ (idc).
"""

from typing import Annotated, Optional, Literal

import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idaread, idawrite, IDAError

# ============================================================================
# Version Compatibility Layer
# ============================================================================

IDA_VERSION = idaapi.get_kernel_version()
IDA9 = int(IDA_VERSION.split('.')[0]) >= 9

if IDA9:
    def _get_bookmark(slot):
        try:
            return idc.get_bookmark(slot)
        except:
            return idaapi.BADADDR
    
    def _set_bookmark(ea, slot, desc=""):
        try:
            return idc.set_bookmark(ea, 0, 0, 0, slot, desc)
        except:
            return False
    
    def _del_bookmark(slot):
        try:
            return idc.set_bookmark(idaapi.BADADDR, 0, 0, 0, slot, "")
        except:
            return False
    
    def _jump_to_bookmark(slot):
        ea = _get_bookmark(slot)
        if ea != idaapi.BADADDR:
            return idaapi.jumpto(ea)
        return False
else:
    import ida_bookmarks
    
    def _get_bookmark(slot):
        return ida_bookmarks.get_bookmark(slot)
    
    def _set_bookmark(ea, slot, desc=""):
        return ida_bookmarks.set_bookmark(ea, slot)
    
    def _del_bookmark(slot):
        return ida_bookmarks.del_bookmark(slot)
    
    def _jump_to_bookmark(slot):
        return ida_bookmarks.jump_to_bookmark(slot)


# ============================================================================
# CONSOLIDATED BOOKMARK TOOL (replaces 4 separate tools)
# ============================================================================


@tool
@unsafe
@idawrite
def bookmark(
    action: Annotated[Literal["list", "set", "delete", "jump"], "Action: list|set|delete|jump"],
    slot: Annotated[Optional[int], "Bookmark slot 0-9 (for set/delete/jump)"] = None,
    address: Annotated[Optional[str], "Address hex/name (for set)"] = None,
    description: Annotated[str, "Description (for set)"] = "",
) -> dict:
    """Unified bookmark operations: list, set, delete, jump (slots 0-9)"""
    try:
        if action == "list":
            result = []
            for i in range(10):
                ea = _get_bookmark(i)
                if ea != idaapi.BADADDR:
                    result.append({
                        "slot": i,
                        "address": hex(ea),
                        "name": idc.get_name(ea) or ""
                    })
            return {"bookmarks": result}
        
        elif action == "set":
            if slot is None or address is None:
                return {"error": "slot and address required for set"}
            if not (0 <= slot <= 9):
                return {"error": "Slot must be 0-9"}
            
            ea = idc.get_name_ea_simple(address)
            if ea == idaapi.BADADDR:
                try:
                    ea = int(address, 16)
                except:
                    return {"error": f"Invalid address: {address}"}
            
            if _set_bookmark(ea, slot, description):
                return {"ok": True, "slot": slot, "address": hex(ea)}
            return {"error": "Failed to set bookmark"}
        
        elif action == "delete":
            if slot is None:
                return {"error": "slot required for delete"}
            if not (0 <= slot <= 9):
                return {"error": "Slot must be 0-9"}
            if _del_bookmark(slot):
                return {"ok": True, "slot": slot}
            return {"error": "Failed to delete bookmark"}
        
        elif action == "jump":
            if slot is None:
                return {"error": "slot required for jump"}
            if not (0 <= slot <= 9):
                return {"error": "Slot must be 0-9"}
            if _jump_to_bookmark(slot):
                return {"ok": True}
            return {"error": "Jump failed (bookmark not set?)"}
        
        else:
            return {"error": f"Unknown action: {action}. Valid: list|set|delete|jump"}
    
    except Exception as e:
        return {"error": str(e)}
