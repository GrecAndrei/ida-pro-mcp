"""Signature and Type Library operations for IDA Pro MCP.

CONSOLIDATED: Single tool with action parameter for FLIRT, TIL, and Lumina.
"""

import os
from typing import Annotated, Optional, Literal

import idaapi
import ida_libfuncs
import idc

from .rpc import tool, unsafe
from .sync import idaread, idawrite, IDAError
from .utils import normalize_list_input, parse_address


@tool
@unsafe
@idawrite  
def signatures(
    action: Annotated[Literal[
        "list_applied", "list_available", "apply",  # FLIRT
        "list_tils", "load_til", "loaded_tils",     # TIL
        "lumina_pull", "lumina_push"                 # Lumina
    ], "Action to perform"],
    name: Annotated[Optional[str], "Signature/TIL name (for apply/load_til)"] = None,
    addrs: Annotated[Optional[list[str] | str], "Addresses (for lumina)"] = None,
) -> dict:
    """Unified signatures/TIL/Lumina tool: list_applied, list_available, apply, list_tils, load_til, loaded_tils, lumina_pull, lumina_push"""
    try:
        # ================================================================
        # FLIRT Signatures
        # ================================================================
        if action == "list_applied":
            lib_count = ida_libfuncs.get_libfuncs_st_count()
            return {
                "library_function_count": lib_count,
                "note": "Use list_available to see .sig files, or View > Signatures in IDA."
            }
        
        elif action == "list_available":
            sig_dir = idc.idadir("sig")
            if not sig_dir or not os.path.exists(sig_dir):
                return {"signatures": [], "error": "Signature directory not found"}
            
            sigs = []
            for root, dirs, files in os.walk(sig_dir):
                for file in files:
                    if file.lower().endswith(".sig"):
                        name = os.path.splitext(file)[0]
                        rel_dir = os.path.relpath(root, sig_dir)
                        if rel_dir == ".":
                            sigs.append(name)
                        else:
                            sigs.append(f"{rel_dir}/{name}")
            return {"signatures": sorted(sigs)}
        
        elif action == "apply":
            if not name:
                return {"error": "name required for apply"}
            ida_libfuncs.plan_to_apply_ldes(name)
            return {"ok": True, "message": f"Signature '{name}' scheduled. Run analysis to apply."}
        
        # ================================================================
        # Type Libraries (TIL)
        # ================================================================
        elif action == "list_tils":
            import ida_typeinf
            til_dir = idc.idadir("til")
            if not til_dir or not os.path.exists(til_dir):
                return {"tils": [], "error": "TIL directory not found"}
            
            tils = []
            for root, dirs, files in os.walk(til_dir):
                for file in files:
                    if file.lower().endswith(".til"):
                        n = os.path.splitext(file)[0]
                        rel_dir = os.path.relpath(root, til_dir)
                        if rel_dir == ".":
                            tils.append(n)
                        else:
                            tils.append(f"{rel_dir}/{n}")
            return {"tils": sorted(tils)}
        
        elif action == "load_til":
            if not name:
                return {"error": "name required for load_til"}
            import ida_typeinf
            if ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT):
                return {"name": name, "ok": True}
            return {"name": name, "error": "Failed to load TIL (may already be loaded)"}
        
        elif action == "loaded_tils":
            import ida_typeinf
            result = []
            for i in range(ida_typeinf.get_idb_tils_qty()):
                t = ida_typeinf.get_idb_til(i)
                if t:
                    result.append(t.name)
            return {"loaded": result}
        
        # ================================================================
        # Lumina
        # ================================================================
        elif action == "lumina_pull":
            try:
                import ida_lumina
            except ImportError:
                return {"error": "Lumina not available in this IDA version"}
            
            if not ida_lumina.is_lumina_enabled():
                return {"error": "Lumina not enabled. Enable in Options > Lumina."}
            
            if addrs:
                addrs = normalize_list_input(addrs)
                eas = [parse_address(a) for a in addrs]
                result = ida_lumina.pull_md(eas)
            else:
                result = ida_lumina.pull_all_mds()
            return {"ok": True, "pulled": result}
        
        elif action == "lumina_push":
            try:
                import ida_lumina
            except ImportError:
                return {"error": "Lumina not available"}
            
            if not ida_lumina.is_lumina_enabled():
                return {"error": "Lumina not enabled"}
            
            if addrs:
                addrs = normalize_list_input(addrs)
                eas = [parse_address(a) for a in addrs]
                result = ida_lumina.push_md(eas)
            else:
                result = ida_lumina.push_all_mds()
            return {"ok": True, "pushed": result}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    except Exception as e:
        return {"error": str(e)}
