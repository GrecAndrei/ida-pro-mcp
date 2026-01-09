"""Enum operations for IDA Pro MCP.

This module provides a SINGLE consolidated enum tool with action parameter.
Compatible with both IDA 8.x (ida_enum) and IDA 9.0+ (ida_typeinf).
"""

from typing import Annotated, Optional, Literal

import idaapi
import idc
import ida_bytes

from .rpc import tool
from .sync import idaread, idawrite, IDAError
from .utils import normalize_list_input

# ============================================================================
# Version Compatibility Layer
# ============================================================================

IDA_VERSION = idaapi.get_kernel_version()
IDA9 = int(IDA_VERSION.split('.')[0]) >= 9

if IDA9:
    import ida_typeinf
    
    def _get_all_enums():
        result = []
        limit = ida_typeinf.get_ordinal_limit(None)
        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                result.append((tif.get_tid(), tif))
        return result
    
    def _get_enum_by_name(name):
        tid = ida_typeinf.get_named_type_tid(name)
        if tid != idaapi.BADADDR:
            tif = ida_typeinf.tinfo_t()
            if tif.get_type_by_tid(tid) and tif.is_enum():
                return tid, tif
        return None, None
    
    def _get_enum_name(eid):
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(eid):
            return tif.get_type_name()
        return None
    
    def _get_enum_members(eid):
        members = []
        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(eid):
            return members
        ei = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(ei):
            for i in range(ei.size()):
                edm = ei[i]
                members.append({"name": edm.name, "value": edm.value})
        return members
    
    def _create_enum(name, is_bitfield=False):
        flags = ida_bytes.hex_flag() if is_bitfield else 0
        return idc.add_enum(name, flags)
    
    def _delete_enum(eid):
        return idc.del_enum(eid)
    
    def _add_enum_member(eid, name, value):
        return idc.add_enum_member(eid, name, value)
    
    def _del_enum_member(eid, value):
        return idc.del_enum_member(eid, value, 0, idaapi.BADADDR)
else:
    import ida_enum
    
    def _get_all_enums():
        result = []
        idx = 0
        while True:
            eid = ida_enum.get_n_enum(idx)
            if eid == idaapi.BADADDR:
                break
            result.append((eid, None))
            idx += 1
        return result
    
    def _get_enum_by_name(name):
        eid = ida_enum.get_enum(name)
        if eid != idaapi.BADADDR:
            return eid, None
        return None, None
    
    def _get_enum_name(eid):
        return ida_enum.get_enum_name(eid)
    
    def _get_enum_members(eid):
        members = []
        def visitor(const_id, value, name):
            members.append({"name": name, "value": value})
            return 0
        ida_enum.for_all_enum_members(eid, visitor)
        return members
    
    def _create_enum(name, is_bitfield=False):
        flags = ida_bytes.hex_flag() if is_bitfield else 0
        return ida_enum.add_enum(idaapi.BADADDR, name, flags)
    
    def _delete_enum(eid):
        ida_enum.del_enum(eid)
        return True
    
    def _add_enum_member(eid, name, value):
        return ida_enum.add_enum_member(eid, name, value)
    
    def _del_enum_member(eid, value):
        const_id = ida_enum.get_enum_member(eid, value, 0, idaapi.BADADDR)
        if const_id != idaapi.BADADDR:
            return ida_enum.del_enum_member(eid, value, 0, idaapi.BADADDR)
        return False


# ============================================================================
# CONSOLIDATED ENUM TOOL (replaces 8 separate tools)
# ============================================================================


@tool
@idawrite
def enum(
    action: Annotated[Literal["list", "info", "create", "delete", "add_member", "del_member", "apply", "search"], 
                      "Action: list|info|create|delete|add_member|del_member|apply|search"],
    name: Annotated[Optional[str], "Enum name (for info/create/delete/add_member/apply)"] = None,
    member_name: Annotated[Optional[str], "Member name (for add_member)"] = None,
    value: Annotated[Optional[int], "Value (for add_member/del_member/search)"] = None,
    addr: Annotated[Optional[str], "Address (for apply)"] = None,
    operand: Annotated[Optional[int], "Operand number 0/1 (for apply)"] = None,
    bitfield: Annotated[bool, "Is bitfield enum (for create)"] = False,
) -> dict:
    """Unified enum operations: list, info, create, delete, add_member, del_member, apply, search"""
    try:
        if action == "list":
            # List all enums
            result = []
            for eid, tif in _get_all_enums():
                ename = _get_enum_name(eid)
                members = _get_enum_members(eid)
                result.append({
                    "name": ename,
                    "id": hex(eid),
                    "member_count": len(members),
                })
            return {"enums": result}
        
        elif action == "info":
            if not name:
                return {"error": "name required for info"}
            eid, tif = _get_enum_by_name(name)
            if eid is None:
                return {"error": f"Enum not found: {name}"}
            members = _get_enum_members(eid)
            return {"name": name, "id": hex(eid), "members": members}
        
        elif action == "create":
            if not name:
                return {"error": "name required for create"}
            existing, _ = _get_enum_by_name(name)
            if existing is not None:
                return {"error": f"Enum '{name}' already exists"}
            eid = _create_enum(name, bitfield)
            if eid == idaapi.BADADDR:
                return {"error": f"Failed to create enum '{name}'"}
            return {"name": name, "id": hex(eid), "ok": True}
        
        elif action == "delete":
            if not name:
                return {"error": "name required for delete"}
            eid, _ = _get_enum_by_name(name)
            if eid is None:
                return {"error": f"Enum '{name}' not found"}
            _delete_enum(eid)
            return {"name": name, "ok": True}
        
        elif action == "add_member":
            if not name or not member_name or value is None:
                return {"error": "name, member_name, and value required for add_member"}
            eid, _ = _get_enum_by_name(name)
            if eid is None:
                return {"error": f"Enum '{name}' not found"}
            result = _add_enum_member(eid, member_name, value)
            if result == 0:
                return {"enum": name, "member": member_name, "value": value, "ok": True}
            return {"error": f"Failed to add member (code: {result})"}
        
        elif action == "del_member":
            if not name or value is None:
                return {"error": "name and value required for del_member"}
            eid, _ = _get_enum_by_name(name)
            if eid is None:
                return {"error": f"Enum '{name}' not found"}
            if _del_enum_member(eid, value):
                return {"enum": name, "value": value, "ok": True}
            return {"error": f"Failed to delete member with value {value}"}
        
        elif action == "apply":
            if not addr or operand is None or not name:
                return {"error": "addr, operand, and name required for apply"}
            from .utils import parse_address
            ea = parse_address(addr)
            eid, _ = _get_enum_by_name(name)
            if eid is None:
                return {"error": f"Enum '{name}' not found"}
            if idc.op_enum(ea, operand, eid, 0):
                return {"addr": addr, "operand": operand, "enum": name, "ok": True}
            return {"error": "Failed to apply enum"}
        
        elif action == "search":
            if value is None:
                return {"error": "value required for search"}
            result = []
            for eid, tif in _get_all_enums():
                ename = _get_enum_name(eid)
                members = _get_enum_members(eid)
                for member in members:
                    if member["value"] == value:
                        result.append({"enum": ename, "member": member["name"], "value": value})
            return {"matches": result}
        
        else:
            return {"error": f"Unknown action: {action}. Valid: list|info|create|delete|add_member|del_member|apply|search"}
    
    except Exception as e:
        return {"error": str(e)}
