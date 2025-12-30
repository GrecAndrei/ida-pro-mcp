"""Antigravity-optimized Agentic Tools for IDA Pro.

This module provides high-level, consolidated tools designed to reduce 
round-trips and optimize context usage for AI agents.
"""

from typing import Annotated, Optional, Any

import idaapi
import idc
import ida_funcs
import ida_bytes
import ida_name
import ida_hexrays
import ida_xref
import ida_segment
import ida_lines

from .rpc import tool
from .sync import idaread
from .utils import normalize_list_input

# Import existing core functions to reuse logic
# (In a real scenario, we might call them directly or refactor logic)
# For now, we reimplement lightweight versions or wrap logic.

@tool
@idaread
def analyze_function(
    name_or_addr: Annotated[str, "Function name or address"],
    detail_level: Annotated[str, "'summary', 'full', 'code_only'"] = "full"
) -> dict:
    """Consolidated function analysis tool.
    
    Returns a unified view of a function including:
    - Metadata (start, end, flags)
    - Pseudocode (if available)
    - Disassembly (if requested or no pseudocode)
    - Xrefs to/from
    """
    ea = api_common_resolve_addr(name_or_addr)
    if ea == idaapi.BADADDR:
        return {"error": f"Address not found: {name_or_addr}"}
        
    func = ida_funcs.get_func(ea)
    if not func:
        return {"error": f"Not a function: {hex(ea)}"}
        
    result = {
        "name": ida_name.get_name(func.start_ea),
        "address": hex(func.start_ea),
        "end": hex(func.end_ea),
        "size": func.size(),
    }
    
    # 1. Decompilation
    decompiled = None
    try:
        if ida_hexrays.init_hexrays_plugin():
             cfunc = ida_hexrays.decompile(func.start_ea)
             if cfunc:
                 decompiled = str(cfunc)
    except Exception:
        # Decompilation failed - will show fallback message
        pass
        
    if decompiled:
        result["pseudocode"] = decompiled
    else:
        result["pseudocode"] = "<Decompilation failed or not available>"
        
    # 2. Xrefs
    if detail_level != "code_only":
        # Callers
        callers = []
        for xref in idautils_xrefs_to(func.start_ea):
            callers.append(hex(xref))
        result["callers_count"] = len(callers)
        result["callers_sample"] = callers[:5] # Limit context
        
        # Callees (scanned from code usually, or xrefs from)
        # Using ida_xref.xrefblk_t
        callees = []
        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(func.start_ea, ida_xref.XREF_ALL)
        while ok and xb.is_from < func.end_ea:
            if xb.is_call: # Code ref?
                 callees.append(hex(xb.to))
            ok = xb.next_from()
        result["callees_count"] = len(callees)
        # Unique callees only?
        
    # 3. Disassembly (fallback when decompilation unavailable)
    if detail_level == "full" and not decompiled:
        # Get simplified disassembly as fallback
        disasm_lines = []
        ea = func.start_ea
        for _ in range(50):  # Limit to first 50 instructions
            if ea >= func.end_ea:
                break
            line = idc.generate_disasm_line(ea, 0)
            if line:
                disasm_lines.append(f"{hex(ea)}: {ida_lines.tag_remove(line)}")
            ea = idc.next_head(ea, func.end_ea)
            if ea == idaapi.BADADDR:
                break
        result["disassembly"] = "\n".join(disasm_lines)
        
    return result

@tool
@idaread
def explore_address(
    address: Annotated[str, "Address or Name"]
) -> dict:
    """Smart context-aware lookup.
    
    Determines if address is Function, Data, String, or Unknown,
    and returns relevant context in one go.
    """
    ea = api_common_resolve_addr(address)
    if ea == idaapi.BADADDR:
        return {"error": "Not found"}
        
    # Check type
    flags = ida_bytes.get_flags(ea)
    
    info = {
        "address": hex(ea),
        "name": ida_name.get_name(ea),
        "section": ida_segment.get_segm_name(ida_segment.getseg(ea))
    }
    
    if ida_bytes.is_code(flags):
        func = ida_funcs.get_func(ea)
        if func:
            info["type"] = "function"
            info["func_start"] = hex(func.start_ea)
            # Add a few lines of decompilation or disasm as preview
            try:
                if ida_hexrays.init_hexrays_plugin():
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        lines = str(cfunc).split('\n')[:5]  # First 5 lines
                        info["snippet"] = '\n'.join(lines)
            except Exception:
                # Fallback to disassembly snippet
                disasm = idc.generate_disasm_line(func.start_ea, 0)
                info["snippet"] = ida_lines.tag_remove(disasm) if disasm else ""
        else:
            info["type"] = "code_chunk"
            info["disasm"] = idc.generate_disasm_line(ea, 0)
            
    elif ida_bytes.is_strlit(flags):
        info["type"] = "string"
        info["value"] = str(idc.get_strlit_contents(ea))
        
    elif ida_bytes.is_data(flags):
        info["type"] = "data"
        info["value"] = hex(idc.get_wide_dword(ea))  # Read as dword
        
    else:
        info["type"] = "unknown/undefined"
        
    # Xrefs
    refs = []
    for xref in idautils_xrefs_to(ea):
        refs.append(hex(xref))
    info["prospect_xrefs"] = refs[:10]
    
    return info

# -- Helpers --

def api_common_resolve_addr(addr_str: str) -> int:
    ea = ida_name.get_name_ea_simple(addr_str)
    if ea != idaapi.BADADDR:
        return ea
    try:
        return int(addr_str, 16)
    except:
        return idaapi.BADADDR

def idautils_xrefs_to(ea):
    """Minimal reimplementation of idautils.XrefsTo for getting cross-references."""
    xrefs = []
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, ida_xref.XREF_ALL)
    while ok:
        xrefs.append(xb.frm)
        ok = xb.next_to()
    return xrefs


# ============================================================================
# Semantic Aliases (Verb-Noun Pattern)
# ============================================================================

@tool
@idaread
def find_references(
    address: Annotated[str, "Address/Name to find references to"]
) -> list[str]:
    """Semantic alias for finding cross-references (xrefs).
    
    Returns a list of addresses that reference the target.
    """
    ea = api_common_resolve_addr(address)
    if ea == idaapi.BADADDR:
        return ["<Address not found>"]
        
    refs = []
    # Combine Code + Data refs
    # Use internal helper
    for xref in idautils_xrefs_to(ea):
        refs.append(hex(xref))
    return refs

@tool
@idaread
def search_everything(
    query: Annotated[str, "Text/pattern to search for (glob-style)"],
    limit: Annotated[int, "Max results per category"] = 50
) -> dict:
    """Unified search: looks in function names, global names, strings, and comments.
    
    Uses glob-style pattern matching (* = any chars, ? = single char).
    Returns results grouped by category.
    """
    import fnmatch
    import idautils
    import ida_name
    import ida_bytes
    
    results = {
        "functions": [],
        "globals": [],
        "strings": [],
        "total": 0
    }
    
    # Normalize pattern for case-insensitive matching
    pattern_lower = query.lower()
    
    # 1. Search function names
    for func_ea in idautils.Functions():
        if len(results["functions"]) >= limit:
            break
        name = ida_funcs.get_func_name(func_ea)
        if name and fnmatch.fnmatch(name.lower(), pattern_lower):
            results["functions"].append({
                "address": hex(func_ea),
                "name": name
            })
    
    # 2. Search global names (non-function named items)
    for ea, name in idautils.Names():
        if len(results["globals"]) >= limit:
            break
        if fnmatch.fnmatch(name.lower(), pattern_lower):
            # Skip if it's a function (already covered)
            if not ida_funcs.get_func(ea):
                results["globals"].append({
                    "address": hex(ea),
                    "name": name
                })
    
    # 3. Search strings
    for s in idautils.Strings():
        if len(results["strings"]) >= limit:
            break
        try:
            string_val = str(s)
            if fnmatch.fnmatch(string_val.lower(), pattern_lower):
                results["strings"].append({
                    "address": hex(s.ea),
                    "value": string_val[:100]  # Truncate long strings
                })
        except Exception:
            continue
    
    results["total"] = len(results["functions"]) + len(results["globals"]) + len(results["strings"])
    
    return results

