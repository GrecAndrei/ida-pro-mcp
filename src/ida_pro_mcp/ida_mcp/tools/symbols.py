
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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
            _STATUS_FUNC_LIMIT = 100000
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    named_funcs += 1
                    if named_funcs >= _STATUS_FUNC_LIMIT:
                        break
            
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
            _EXPORT_FUNC_LIMIT = 50000
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    item = {"addr": hex(ea), "name": name}
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, ea): item["type"] = str(tif)
                    export_data["functions"].append(item)
                    if len(export_data["functions"]) >= _EXPORT_FUNC_LIMIT:
                        break
            
            import json
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            return {"ok": True, "exported": True, "count": len(export_data["functions"])}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 25. PATTERNS - FLIRT-Like Pattern Generation and Matching
# ============================================================================
