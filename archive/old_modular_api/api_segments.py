"""Segment manipulation operations for IDA Pro MCP."""

from typing import Annotated

import ida_segment
import ida_bytes
import idaapi

from .rpc import tool, unsafe
from .sync import idaread, idawrite
from .utils import normalize_list_input, normalize_dict_list, parse_address


# Segment class constants
SEG_CLASSES = {
    "code": "CODE",
    "data": "DATA", 
    "bss": "BSS",
    "stack": "STACK",
    "const": "CONST",
    "xtrn": "XTRN",
}


@tool
@unsafe
@idawrite
def add_seg(
    items: Annotated[list[dict] | dict, "Items with 'start', 'end', 'name', optional 'class'"]
) -> list[dict]:
    """Create segment(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        start = item.get("start", "")
        end = item.get("end", "")
        name = item.get("name", "seg")
        seg_class = item.get("class", "DATA")
        
        try:
            start_ea = parse_address(start)
            end_ea = parse_address(end)
            
            # Normalize class name
            seg_class = SEG_CLASSES.get(seg_class.lower(), seg_class.upper())
            
            if ida_segment.add_segm(0, start_ea, end_ea, name, seg_class):
                results.append({
                    "start": start,
                    "end": end,
                    "name": name,
                    "class": seg_class,
                    "ok": True
                })
            else:
                results.append({"start": start, "error": "Failed to create segment"})
                
        except Exception as e:
            results.append({"start": start, "error": str(e)})
    
    return results


@tool
@unsafe
@idawrite
def del_seg(
    addrs: Annotated[list[str] | str, "Address(es) within segment(s) to delete"]
) -> list[dict]:
    """Delete segment(s)"""
    addrs = normalize_list_input(addrs)
    results = []
    
    for addr in addrs:
        try:
            ea = parse_address(addr)
            seg = ida_segment.getseg(ea)
            
            if not seg:
                results.append({"addr": addr, "error": "No segment at address"})
                continue
            
            if ida_segment.del_segm(seg.start_ea, ida_segment.SEGMOD_KILL):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@idawrite
def set_seg_attr(
    items: Annotated[list[dict] | dict, "Items with 'addr' and attributes to set"]
) -> list[dict]:
    """Modify segment attributes"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        
        try:
            ea = parse_address(addr)
            seg = ida_segment.getseg(ea)
            
            if not seg:
                results.append({"addr": addr, "error": "No segment"})
                continue
            
            modified = []
            
            # Name
            if "name" in item:
                ida_segment.set_segm_name(seg, item["name"])
                modified.append("name")
            
            # Class
            if "class" in item:
                seg_class = SEG_CLASSES.get(item["class"].lower(), item["class"].upper())
                ida_segment.set_segm_class(seg, seg_class)
                modified.append("class")
            
            # Permissions (RWX)
            if "perm" in item:
                perm_str = item["perm"].upper()
                perm = 0
                if "R" in perm_str:
                    perm |= ida_segment.SEGPERM_READ
                if "W" in perm_str:
                    perm |= ida_segment.SEGPERM_WRITE
                if "X" in perm_str:
                    perm |= ida_segment.SEGPERM_EXEC
                seg.perm = perm
                ida_segment.update_segm(seg)
                modified.append("perm")
            
            # Alignment
            if "align" in item:
                seg.align = item["align"]
                ida_segment.update_segm(seg)
                modified.append("align")
            
            results.append({"addr": addr, "modified": modified, "ok": True})
            
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results


@tool
@unsafe
@idawrite
def move_seg(
    items: Annotated[list[dict] | dict, "Items with 'addr' (in segment) and 'to' (new base)"]
) -> list[dict]:
    """Rebase segment(s)"""
    items = normalize_dict_list(items)
    results = []
    
    for item in items:
        addr = item.get("addr", "")
        to_addr = item.get("to", "")
        
        try:
            ea = parse_address(addr)
            new_base = parse_address(to_addr)
            
            seg = ida_segment.getseg(ea)
            if not seg:
                results.append({"addr": addr, "error": "No segment"})
                continue
            
            # Calculate delta
            delta = new_base - seg.start_ea
            
            if ida_segment.move_segm(seg.start_ea, new_base, ida_segment.MSF_FIXONCE):
                results.append({
                    "addr": addr,
                    "old_base": hex(seg.start_ea),
                    "new_base": hex(new_base),
                    "delta": hex(delta),
                    "ok": True
                })
            else:
                results.append({"addr": addr, "error": "Failed to move segment"})
                
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    
    return results
