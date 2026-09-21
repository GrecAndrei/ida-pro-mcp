
import contextlib

from ._common import (
    Annotated,
    Literal,
    MCPError,
    Optional,
    handle_error,
    ida_bytes,
    ida_funcs,
    ida_name,
    ida_nalt,
    ida_typeinf,
    idaapi,
    idautils,
    idawrite,
    idc,
    make_error,
    os,
    tool,
    validate_addr,
    validate_path_safe,
)

from .. import compat as _compat


# ============================================================================
# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================

@tool
@idawrite
def symbols(
    action: Annotated[Literal["load_pdb", "load_dwarf", "status", "apply", "export", "import_system_map"],
                      "Action: load_pdb|load_dwarf|status|apply|export|import_system_map"],
    path: Annotated[Optional[str], "Path to symbol file (PDB, DWARF, System.map, etc.)"] = None,
    addr: Annotated[Optional[str], "Address to apply symbols to"] = None,
    address_delta: Annotated[Optional[int], "Address offset to add to symbol addresses (for rebased/raw kernels)"] = 0,
    limit: Annotated[Optional[int], "Maximum symbols to import (default 10000, max 50000)"] = 10000,
    filter_types: Annotated[Optional[str], "Filter symbol types (e.g. 'Tt' for code, 'Dd' for data, or empty for all)"] = None,
    create_functions: Annotated[Optional[bool], "Create functions for code symbols ('T'/'t')"] = False,
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
    - import_system_map: Import bounded Linux/System.map symbols with an optional
      virtual-address delta for a raw or relocated kernel image.
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
            return make_error(MCPError.IDA_ERROR, "DWARF plugin failed to load or run")

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
            func_start = _compat.get_func_start(ea)
            if func_start is not None:
                name = idc.get_func_name(func_start)
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

        elif action == "import_system_map":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path is required for import_system_map")
            path, err = validate_path_safe(path)
            if err:
                return err
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"System.map file not found: {path}")

            # Coerce the signed virtual-address delta.  Do not silently turn a
            # malformed delta into zero: that can place every kernel symbol at
            # the wrong address while still reporting success.
            raw_delta = address_delta
            if raw_delta is None or (raw_delta == 0 and kwargs.get("delta") is not None):
                raw_delta = kwargs.get("delta", kwargs.get("address_delta", raw_delta if raw_delta is not None else 0))
            try:
                if isinstance(raw_delta, bool):
                    raise ValueError("boolean is not an address delta")
                if isinstance(raw_delta, int):
                    delta = raw_delta
                else:
                    delta_text = str(raw_delta).strip()
                    try:
                        delta = int(delta_text, 0)
                    except ValueError:
                        delta = int(delta_text, 16)
            except (TypeError, ValueError):
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Invalid address_delta: {raw_delta!r}",
                    hint="Use a signed integer or hex value such as 0xffff800000000000.",
                )

            try:
                max_limit = min(50000, max(1, int(limit or 10000)))
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "limit must be an integer")
            f_types = set(str(filter_types).strip()) if filter_types else None
            create_raw = create_functions if create_functions is not None else kwargs.get("create_functions", False)
            create_funcs = create_raw if isinstance(create_raw, bool) else str(create_raw).strip().lower() in {"1", "true", "yes", "on"}
            max_lines = max(1000, min(1_000_000, max_limit * 20))

            imported = 0
            skipped = 0
            out_of_range = 0
            total_lines = 0
            truncated = False
            sample = []

            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    if total_lines > max_lines:
                        truncated = True
                        break
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 3:
                        skipped += 1
                        continue
                    addr_str, sym_type, sym_name = parts[0], parts[1], parts[2]
                    if f_types and sym_type not in f_types:
                        continue
                    try:
                        sym_ea = int(addr_str, 16)
                    except ValueError:
                        skipped += 1
                        continue
                    target_ea = sym_ea + delta
                    if not 0 <= target_ea <= 0xffffffffffffffff:
                        out_of_range += 1
                        skipped += 1
                        continue
                    if not ida_bytes.is_loaded(target_ea):
                        skipped += 1
                        continue

                    if idc.set_name(target_ea, sym_name, ida_name.SN_FORCE):
                        imported += 1
                        if len(sample) < 10:
                            sample.append({
                                "addr": hex(target_ea),
                                "orig_addr": hex(sym_ea),
                                "type": sym_type,
                                "name": sym_name,
                            })
                        if create_funcs and sym_type in "Tt":
                            fn = _compat.get_func_info(target_ea)
                            if fn is None:
                                with contextlib.suppress(Exception):
                                    ida_funcs.add_func(target_ea)
                    else:
                        skipped += 1

                    if imported >= max_limit:
                        truncated = True
                        break

            return {
                "ok": True,
                "action": "import_system_map",
                "imported": imported,
                "skipped": skipped,
                "out_of_range": out_of_range,
                "total_lines": total_lines,
                "truncated": truncated,
                "line_limit": max_lines,
                "delta": hex(delta) if delta >= 0 else f"-{abs(delta):#x}",
                "limit": max_limit,
                "sample": sample,
                "note": f"Imported {imported} symbols from System.map (delta: {hex(delta) if delta >= 0 else f'-{abs(delta):#x}'}).",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 25. PATTERNS - FLIRT-Like Pattern Generation and Matching
# ============================================================================
