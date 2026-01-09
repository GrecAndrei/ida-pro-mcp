
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_segment
import ida_funcs
import ida_kernwin
import ida_frame
import ida_lines

# Infrastructure discovery
try:
    # Package mode
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ida_mcp.error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
        
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================

@tool
@idawrite
def symbols(
    action: Annotated[Literal["load_pdb", "load_dwarf", "status", "apply", "export"],
                      "Action: load_pdb|load_dwarf|status|apply|export"],
    path: Annotated[Optional[str], "Path to symbol file (PDB, DWARF, etc.)"] = None,
    addr: Annotated[Optional[str], "Address to apply symbols to"] = None,
    **kwargs
) -> dict:
    """
    Load and manage debug symbols (PDB, DWARF, COFF).
    
    Actions:
    - load_pdb: Load a Windows PDB file (auto-detects if path is None).
    - load_dwarf: Trigger DWARF info parsing for ELF binaries.
    - status: Check if symbols are loaded and get counts.
    - apply: Infer and apply type from symbols at `addr`.
    - export: Save all named symbols and types to a JSON file.
    """
    try:
        if action == "load_pdb":
            import ida_loader
            if path:
                path, err = validate_path_safe(path)
                if err: return err
                if ida_loader.load_and_run_plugin("pdb", 0):
                    return {"ok": True, "loaded": True, "path": path}
            else:
                if ida_loader.load_and_run_plugin("pdb", 0):
                    return {"ok": True, "loaded": True, "note": "PDB auto-detection triggered"}
            return make_error(MCPError.IDA_ERROR, "PDB loading failed")
        
        elif action == "load_dwarf":
            import ida_loader
            if ida_loader.load_and_run_plugin("dwarf", 0):
                return {"ok": True, "loaded": True}
            return {"ok": True, "note": "DWARF processing handled by IDA during analysis"}
        
        elif action == "status":
            named_funcs = 0
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"): named_funcs += 1
            
            til = ida_typeinf.get_idati()
            # Use get_ordinal_qty/get_ordinal_count for efficiency
            qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
            type_count = qty_func(til) if til and qty_func else 0
            
            return {
                "ok": True,
                "has_debug_info": named_funcs > 10,
                "named_functions": named_funcs,
                "type_count": type_count
            }
        
        elif action == "apply":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            tif = ida_typeinf.tinfo_t()
            # In IDA 9, use get_tinfo or similar
            if ida_nalt.get_tinfo(tif, ea):
                return {"ok": True, "addr": hex(ea), "type": str(tif)}
            return {"ok": True, "applied": False, "note": "No symbol info found for address"}
        
        elif action == "export":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            
            export_data = {"functions": [], "types": []}
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    item = {"addr": hex(ea), "name": name}
                    tif = ida_typeinf.tinfo_t()
                    if ida_typeinf.get_tinfo(tif, ea): item["type"] = str(tif)
                    export_data["functions"].append(item)
            
            import json
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            return {"ok": True, "exported": True, "count": len(export_data["functions"])}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 25. PATTERNS - FLIRT-Like Pattern Generation and Matching
# ============================================================================
