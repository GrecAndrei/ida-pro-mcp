
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 25. PATTERNS - FLIRT-Like Pattern Generation and Matching
# ============================================================================

@tool
@idaread
def patterns(
    action: Annotated[Literal["generate", "match", "list_sigs", "apply_sig", "create_sig", "matched"],
                      "Action: generate|match|list_sigs|apply_sig|create_sig|matched"],
    addr: Annotated[Optional[str], "Function address for pattern operations"] = None,
    pattern: Annotated[Optional[str], "Pattern to match (hex with ?? wildcards)"] = None,
    name: Annotated[Optional[str], "Signature name"] = None,
    length: Annotated[int, "Pattern length in bytes"] = 32,
    offset: Annotated[int, "Pagination offset (list_sigs)"] = 0,
    count: Annotated[int, "Max results (list_sigs/match)"] = 100,
    **kwargs
) -> dict:
    """
    Generate and match function signatures (FLIRT-like patterns).
    
    Actions:
    - generate: Create a hex pattern with wildcards for relocations.
    - match: Find functions matching a hex pattern.
    - list_sigs: List available FLIRT .sig files.
    - apply_sig: Apply a named signature file.
    - create_sig: Generate metadata for a single function signature.
    """
    try:
        import ida_fixup
        
        if action == "generate":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            # Read function bytes
            func_size = min(length, func.end_ea - func.start_ea)
            func_bytes = ida_bytes.get_bytes(func.start_ea, func_size)
            if not func_bytes: return make_error(MCPError.ADDRESS_INVALID, "Could not read bytes")
            
            p_parts, m_parts = [], []
            for i, b in enumerate(func_bytes):
                curr_ea = func.start_ea + i
                fix = ida_fixup.fixup_data_t()
                if ida_fixup.get_fixup(fix, curr_ea):
                    p_parts.append("??")
                    m_parts.append("0")
                else:
                    p_parts.append(f"{b:02X}")
                    m_parts.append("1")
            
            return {"ok": True, "addr": hex(func.start_ea), "name": idc.get_func_name(ea),
                    "pattern": " ".join(p_parts), "mask": "".join(m_parts), "length": func_size}
        
        elif action == "match":
            if not pattern: return make_error(MCPError.INVALID_ARGS, "pattern required")
            p_bytes, mask = [], []
            try:
                for part in pattern.split():
                    if "?" in part:
                        p_bytes.append(0)
                        mask.append(False)
                    else:
                        p_bytes.append(int(part, 16))
                        mask.append(True)
            except: return make_error(MCPError.INVALID_ARGS, "Invalid hex in pattern")
            
            matches = []
            total = 0
            for ea in idautils.Functions():
                fb = ida_bytes.get_bytes(ea, len(p_bytes))
                if not fb or len(fb) < len(p_bytes): continue
                if all(fb[i] == p_bytes[i] for i in range(len(p_bytes)) if mask[i]):
                    total += 1
                    if total > offset and (count == 0 or len(matches) < count):
                        matches.append(f"{hex(ea)}  {idc.get_func_name(ea)}")
            return {"ok": True, "pattern": pattern, "matches": "\n".join(matches), "total": total, "offset": offset, "count": len(matches)}
        
        elif action == "list_sigs":
            # IDA 9.2 changed idadir() - try multiple approaches
            sig_dirs = []
            
            # Try idaapi.get_ida_subdirs (IDA 9.x)
            if hasattr(idaapi, 'get_ida_subdirs'):
                try:
                    sig_dirs = list(idaapi.get_ida_subdirs('sig'))
                except:
                    pass
            
            # Fallback to IDADIR environment variable
            if not sig_dirs:
                idadir = os.environ.get('IDADIR', '')
                if idadir:
                    sig_dirs = [os.path.join(idadir, 'sig')]
            
            # Fallback to idc.get_ida_subdirs or idaapi path
            if not sig_dirs and hasattr(idc, 'get_ida_subdirs'):
                try:
                    sig_dirs = list(idc.get_ida_subdirs('sig'))
                except:
                    pass
            
            sigs = []
            for sig_dir in sig_dirs:
                if os.path.exists(sig_dir):
                    for root, _, files in os.walk(sig_dir):
                        for f in files:
                            if f.lower().endswith(".sig"):
                                sigs.append(os.path.splitext(os.path.relpath(os.path.join(root, f), sig_dir))[0])

            signatures = sorted(list(set(sigs)))
            total = len(signatures)
            if count == 0:
                page = signatures[offset:]
            else:
                page = signatures[offset:offset + count]
            return {"ok": True, "signatures": page, "total": total, "offset": offset, "count": len(page), "sig_dirs": sig_dirs}
        
        elif action == "apply_sig":
            if not name: return make_error(MCPError.INVALID_ARGS, "name required")
            import ida_libfuncs
            ida_libfuncs.plan_to_apply_ldes(name)
            return {"ok": True, "name": name, "note": "Signature application planned and awaiting auto-analysis"}
        
        elif action == "create_sig":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            import zlib
            fb = ida_bytes.get_bytes(ea, 32)
            if not fb: return make_error(MCPError.ADDRESS_INVALID, "Could not read bytes")
            return {"ok": True, "signature": {"name": name or idc.get_func_name(ea), "addr": hex(ea), "crc16": hex(zlib.crc32(fb) & 0xFFFF)}}
        
        elif action == "matched":
            # Show functions that were identified by FLIRT signatures
            matched_lines = []
            unmatched_count = 0
            
            for ea in idautils.Functions():
                func_name = idc.get_func_name(ea)
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                
                is_lib = bool(func.flags & ida_funcs.FUNC_LIB)
                has_name = func_name and not func_name.startswith("sub_") and not func_name.startswith("nullsub_")
                is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)
                
                if is_lib or (has_name and not func_name.startswith("_")):
                    size = func.end_ea - func.start_ea
                    
                    lib_hint = ""
                    if func_name.startswith("_"): lib_hint = "crt"
                    elif "printf" in func_name.lower() or "scanf" in func_name.lower(): lib_hint = "stdio"
                    elif "malloc" in func_name.lower() or "free" in func_name.lower(): lib_hint = "stdlib"
                    elif "str" in func_name.lower()[:4]: lib_hint = "string"
                    elif "mem" in func_name.lower()[:4]: lib_hint = "memory"
                    elif func_name.startswith("__"): lib_hint = "compiler_rt"
                    
                    flags_str = []
                    if is_lib: flags_str.append("lib")
                    if is_thunk: flags_str.append("thunk")
                    if lib_hint: flags_str.append(lib_hint)
                    
                    matched_lines.append(f"{hex(ea)}  size={size}  {func_name}  [{','.join(flags_str)}]")
                else:
                    unmatched_count += 1
                
                if len(matched_lines) >= count:
                    break
            
            page = matched_lines[offset:offset+count]
            return {
                "ok": True,
                "matched_functions": "\n".join(page),
                "total_matched": len(matched_lines),
                "total_unmatched": unmatched_count,
                "offset": offset,
                "count": len(page)
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 26. STRUCTS - Automatic Structure Recovery and Analysis
# ============================================================================
