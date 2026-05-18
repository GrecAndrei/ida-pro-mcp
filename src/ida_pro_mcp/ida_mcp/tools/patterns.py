
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
    action: Annotated[Literal["generate", "match", "list_sigs", "apply_sig", "create_sig", "matched", "yara_from_func", "flirt_generate", "match_yara"],
                      "Action: generate|match|list_sigs|apply_sig|create_sig|matched|yara_from_func|flirt_generate|match_yara"],
    addr: Annotated[Optional[str], "Function address for pattern operations"] = None,
    pattern: Annotated[Optional[str], "Pattern to match (hex with ?? wildcards)"] = None,
    name: Annotated[Optional[str], "Signature name"] = None,
    length: Annotated[int, "Pattern length in bytes"] = 32,
    offset: Annotated[int, "Pagination offset (list_sigs)"] = 0,
    count: Annotated[int, "Max results (list_sigs/match)"] = 100,
    **kwargs
) -> dict:
    """
    Generate and match function signatures (FLIRT-like patterns) and YARA rules.
    
    Actions:
    - generate: Create a hex pattern with wildcards for relocations.
    - match: Find functions matching a hex pattern.
    - list_sigs: List available FLIRT .sig files.
    - apply_sig: Apply a named signature file.
    - create_sig: Generate metadata for a single function signature.
    - yara_from_func: Build a YARA rule from non-relocatable function bytes.
    - flirt_generate: Build FLIRT-like signature metadata (CRC16 + masked prefix).
    - match_yara: Run YARA rule over input binary (or fallback byte-pattern search).
    """
    try:
        import hashlib
        import zlib
        import ida_fixup

        def _func_bytes_and_mask(ea: int, max_len: int) -> tuple[bytes, list[int], list[str]]:
            func = ida_funcs.get_func(ea)
            if not func:
                return b"", [], []
            n = min(max_len, int(func.end_ea - func.start_ea))
            fb = ida_bytes.get_bytes(func.start_ea, n) or b""
            mask: list[int] = []
            parts: list[str] = []
            for i, b in enumerate(fb):
                curr = func.start_ea + i
                fix = ida_fixup.fixup_data_t()
                reloc = bool(ida_fixup.get_fixup(fix, curr))
                if reloc:
                    mask.append(0)
                    parts.append("??")
                else:
                    mask.append(1)
                    parts.append(f"{b:02X}")
            return fb, mask, parts
        
        if action == "generate":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
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

        elif action == "yara_from_func":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            fb, mask, parts = _func_bytes_and_mask(func.start_ea, max(32, min(length, 256)))
            if not fb:
                return make_error(MCPError.ADDRESS_INVALID, "Could not read function bytes")
            clean_bytes = [p for p, m in zip(parts, mask) if m == 1]
            seq = " ".join(clean_bytes[:48]) if clean_bytes else "00"
            fname = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            file_sha = ""
            try:
                in_path = idc.get_input_file_path() or ""
                if in_path and os.path.exists(in_path):
                    with open(in_path, "rb") as fh:
                        file_sha = hashlib.sha256(fh.read()).hexdigest()
            except Exception:
                pass
            rule_name = (name or fname).replace(" ", "_").replace("-", "_")
            yara_rule = (
                f"rule {rule_name} {{\n"
                f"  meta:\n"
                f"    function = \"{fname}\"\n"
                f"    binary_sha256 = \"{file_sha}\"\n"
                f"    ida_version = \"{getattr(idaapi, 'get_kernel_version', lambda: 'unknown')()}\"\n"
                f"  strings:\n"
                f"    $a = {{ {seq} }}\n"
                f"  condition:\n"
                f"    $a\n"
                f"}}"
            )
            return {"ok": True, "addr": hex(func.start_ea), "name": fname, "rule": yara_rule}

        elif action == "flirt_generate":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            fb, mask, parts = _func_bytes_and_mask(func.start_ea, max(32, min(length, 256)))
            if not fb:
                return make_error(MCPError.ADDRESS_INVALID, "Could not read function bytes")
            crc16 = zlib.crc32(fb) & 0xFFFF
            cref_mask = "".join("1" if m else "0" for m in mask[:64])
            return {
                "ok": True,
                "signature": {
                    "name": name or (idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"),
                    "addr": hex(func.start_ea),
                    "length": len(fb),
                    "crc16": hex(crc16),
                    "leading_bytes": " ".join(parts[:64]),
                    "cref_mask": cref_mask,
                },
                "note": "FLIRT-like metadata generated from bytes and relocation mask.",
            }

        elif action == "match_yara":
            rule = str(kwargs.get("rule") or pattern or "").strip()
            if not rule:
                return make_error(MCPError.INVALID_ARGS, "rule required")
            in_path = ""
            try:
                in_path = idc.get_input_file_path() or ""
            except Exception:
                in_path = ""
            matches = []
            yara_err = None
            if in_path and os.path.exists(in_path):
                try:
                    import yara  # type: ignore
                    yr = yara.compile(source=rule)
                    for m in yr.match(in_path):
                        for s in getattr(m, "strings", []) or []:
                            off = getattr(s, "offset", None)
                            if off is not None:
                                matches.append({"offset": int(off), "addr": hex(int(off)), "rule": m.rule})
                    return {"ok": True, "engine": "yara-python", "matches": matches, "count": len(matches)}
                except Exception as e:
                    yara_err = str(e)
            # Fallback: parse first hex-string and run byte scan.
            import re
            hex_blocks = re.findall(r"\{([^}]+)\}", rule)
            if not hex_blocks:
                return {"ok": True, "engine": "fallback", "matches": [], "count": 0, "warning": yara_err or "No hex pattern block found"}
            pat = " ".join(hex_blocks[0].split())
            p_bytes, p_mask = [], []
            for part in pat.split():
                if "?" in part:
                    p_bytes.append(0); p_mask.append(False)
                else:
                    p_bytes.append(int(part, 16)); p_mask.append(True)
            if not in_path or not os.path.exists(in_path):
                return {"ok": True, "engine": "fallback", "matches": [], "count": 0, "warning": yara_err or "input file unavailable"}
            data = open(in_path, "rb").read()
            for i in range(0, max(0, len(data) - len(p_bytes) + 1)):
                if all(data[i + j] == p_bytes[j] for j in range(len(p_bytes)) if p_mask[j]):
                    matches.append({"offset": i, "addr": hex(i)})
                    if len(matches) >= max(1, count):
                        break
            return {"ok": True, "engine": "fallback", "matches": matches, "count": len(matches), "warning": yara_err}
        
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
            except Exception: return make_error(MCPError.INVALID_ARGS, "Invalid hex in pattern")
            
            matches = []
            total = 0
            _scan_limit = 200000
            for _scan_idx, ea in enumerate(idautils.Functions()):
                if _scan_idx >= _scan_limit:
                    break
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
                except Exception:
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
                except Exception:
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
            _scan_limit = 200000
            
            for _scan_idx, ea in enumerate(idautils.Functions()):
                if _scan_idx >= _scan_limit:
                    break
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
