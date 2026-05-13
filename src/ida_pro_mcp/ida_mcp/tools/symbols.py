
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
                if err:
                    return err
                if not os.path.exists(path):
                    return make_error(MCPError.FILE_NOT_FOUND, f"PDB file not found: {path}")
                # Set the PDB path via environment so the plugin picks it up
                os.environ["_NT_SYMBOL_PATH"] = os.path.dirname(path)
                os.environ["IDA_PDB_PATH"] = path
            if ida_loader.load_and_run_plugin("pdb", 0):
                return {"ok": True, "loaded": True, "path": path or "auto-detected"}
            return make_error(MCPError.IDA_ERROR, "PDB loading failed or no PDB available")
        
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
            if not addr:
                ea = idaapi.get_screen_ea()
                if ea == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, "addr required")
            else:
                ea, err = validate_addr(addr)
                if err:
                    return err

            tif = ida_typeinf.tinfo_t()
            # Try to get existing type info first
            if ida_nalt.get_tinfo(tif, ea):
                # Re-apply it to force propagation to decompiler
                if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                    return {"ok": True, "addr": hex(ea), "type": str(tif), "applied": True}
                return {"ok": True, "addr": hex(ea), "type": str(tif), "applied": False,
                        "note": "Type read but re-apply failed"}

            # Try to infer from function prototype in TIL
            func = ida_funcs.get_func(ea)
            if func:
                name = idc.get_func_name(func.start_ea)
                if name:
                    til = ida_typeinf.get_idati()
                    if til and ida_typeinf.get_named_type(til, name, ida_typeinf.NTF_TYPE, tif):
                        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                            return {"ok": True, "addr": hex(ea), "type": str(tif), "applied": True,
                                    "source": "til"}

            return {"ok": True, "applied": False, "addr": hex(ea),
                    "note": "No type info found; use types(action='set_prototype') to set one"}
        
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
