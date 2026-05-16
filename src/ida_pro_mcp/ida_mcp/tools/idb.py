try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import ida_entry
import ida_ida
import os

try:
    from ida_pro_mcp.host.arch_profile import infer_binary_arch_profile
except Exception:
    infer_binary_arch_profile = None  # type: ignore

def _get_path(module, names):
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)()
    return None

def _safe_inf_get(attr_name, fallback=None):
    """Safely get ida_ida.inf_get_* or fallback to idc.get_inf_attr."""
    getter = getattr(ida_ida, f"inf_get_{attr_name}", None)
    if getter:
        try:
            return getter()
        except Exception:
            pass
    # Fallback to idc
    attr = getattr(idc, f"INF_{attr_name.upper()}", None)
    if attr is not None:
        return idc.get_inf_attr(attr)
    return fallback

@tool
def idb(
    action: Annotated[Literal["meta", "summary", "segments", "entrypoints", "bookmarks", "overview", "architecture_profile"],
                      "Action: meta|summary|segments|entrypoints|bookmarks|overview|architecture_profile"] = "summary",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    **kwargs
) -> Any:
    """
    IDA database metadata and structural information.
    
    ACTIONS:
    
    meta - Comprehensive binary metadata
        Returns: {binary_path, idb_path, processor, bitness, compiler, image_base, 
                  min_ea, max_ea, file_type, md5, sha256, crc32, timestamps}
    
    summary - Quick analysis summary with statistics
        Returns: {functions, named_functions, segments, strings, imports, exports,
                  comments, analysis_ok, coverage_estimate}
    
    overview - One-shot context for LLMs: meta + summary + segments + entrypoints combined
        Returns: {meta, summary, segments, entrypoints} - everything needed to start analysis

    architecture_profile - Current IDB architecture profile + raw-binary inference guidance
        Returns: {current, inferred_from_binary, raw_binary_mode, recommendations}
    
    segments - Detailed segment information with permissions and attributes
        Params: offset, count (for pagination)
        Returns: {segments: [{name, start, end, size, perms, class, align, type, flags}]}
    
    entrypoints - All entry points with type classification
        Returns: {entrypoints: [{name, addr, ordinal, type, is_main}]}
    
    bookmarks - IDA native bookmarks
        Returns: {bookmarks: [{index, addr, desc}]}
    """
    try:
        if action == "meta":
            return {"ok": True, **idb_meta()}
        if action == "summary":
            return {"ok": True, **idb_summary()}
        if action == "overview":
            meta = idb_meta()
            summary = idb_summary()
            segs = idb_segments_detailed()
            entries = idb_entrypoints_detailed()
            arch_profile = idb_architecture_profile(meta=meta, summary=summary)
            result = {
                "ok": True,
                "meta": meta,
                "summary": summary,
                "segments": segs[:20],
                "entrypoints": entries.get("entrypoints", [])[:30],
                "architecture_profile": arch_profile,
            }
            # Firmware detection hint
            is_firmware = bool(arch_profile.get("raw_binary_mode"))
            if is_firmware:
                result["firmware_detected"] = True
                result["next_actions"] = [
                    "firmware_view(action='triage_snapshot')",
                    "firmware_view(action='detect_load_address')",
                    "firmware_view(action='detect_vector_table')",
                    "firmware_view(action='detect_mmio')",
                    "llm_helpers(action='guided_analysis')",
                ]
            else:
                result["next_actions"] = [
                    "data(action='imports')",
                    "search(action='find', pattern='main')",
                    "llm_helpers(action='cheatsheet')",
                ]
            return result
        if action == "segments":
            segs = idb_segments_detailed()
            total = len(segs)
            if count == 0:
                page = segs[offset:]
            else:
                page = segs[offset:offset + count]
            return {"ok": True, "segments": page, "total": total, "offset": offset, "count": len(page)}
        if action == "entrypoints":
            return {"ok": True, **idb_entrypoints_detailed()}
        if action == "bookmarks":
            return {"ok": True, **idb_bookmarks()}
        if action == "architecture_profile":
            return {"ok": True, **idb_architecture_profile()}
        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e, "idb")

@idaread
def idb_meta():
    """Rich metadata about the binary and IDB."""
    binary_path = _get_path(ida_nalt, ["get_input_file_path"]) or _get_path(idaapi, ["get_input_file_path"]) or "unknown"
    idb_path = _get_path(idaapi, ["get_idb_path"]) or _get_path(idc, ["get_idb_path"]) or "unknown"
    
    # Get min/max EA
    min_ea = _safe_inf_get("min_ea", 0)
    max_ea = _safe_inf_get("max_ea", 0)
    
    # File hashes if available
    md5 = ida_nalt.retrieve_input_file_md5() if hasattr(ida_nalt, "retrieve_input_file_md5") else None
    sha256 = ida_nalt.retrieve_input_file_sha256() if hasattr(ida_nalt, "retrieve_input_file_sha256") else None
    crc32 = ida_nalt.retrieve_input_file_crc32() if hasattr(ida_nalt, "retrieve_input_file_crc32") else None
    
    # Compiler info
    comp = _safe_inf_get("cc_id", 0)
    compiler_names = {0: "unknown", 1: "visual_c", 2: "borland", 3: "watcom", 
                      6: "gnu", 7: "visual_cxx", 8: "bp", 9: "clang"}
    
    # File type
    file_type = _inf_filetype_id()
    
    return {
        "binary_path": binary_path,
        "idb_path": idb_path,
        "processor": _inf_procname(),
        "bitness": _inf_bitness(),
        "file_type": _filetype_name(file_type),
        "file_type_id": file_type,
        "compiler": compiler_names.get(comp, f"compiler_{comp}"),
        "image_base": hex(_safe_inf_get("baseaddr", 0)),
        "min_ea": hex(min_ea) if min_ea else None,
        "max_ea": hex(max_ea) if max_ea else None,
        "image_size": hex(max_ea - min_ea) if min_ea and max_ea else None,
        "md5": md5.hex() if md5 else None,
        "sha256": sha256.hex() if sha256 else None,
        "crc32": hex(crc32) if crc32 else None,
        "is_dll": ida_ida.inf_is_dll() if hasattr(ida_ida, "inf_is_dll") else None,
        "is_be": ida_ida.inf_is_be() if hasattr(ida_ida, "inf_is_be") else None,
    }

@idaread
def idb_segments_detailed():
    """Detailed segment information."""
    segments = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if not seg:
            continue
            
        # Permissions string
        perms = ""
        if seg.perm & idaapi.SEGPERM_READ: perms += "r"
        if seg.perm & idaapi.SEGPERM_WRITE: perms += "w"
        if seg.perm & idaapi.SEGPERM_EXEC: perms += "x"
        
        # Segment type - build dict safely for IDA 9 compatibility
        seg_types = {}
        for attr_name, type_name in [("SEG_CODE", "code"), ("SEG_DATA", "data"), 
                                      ("SEG_BSS", "bss"), ("SEG_STACK", "stack"),
                                      ("SEG_XTRN", "extern"), ("SEG_NULL", "null"),
                                      ("SEG_NORM", "normal"), ("SEG_ABS", "absolute")]:
            if hasattr(ida_segment, attr_name):
                seg_types[getattr(ida_segment, attr_name)] = type_name
        seg_type = seg_types.get(seg.type, f"type_{seg.type}")
        
        # Count items in segment
        code_count = 0
        data_count = 0
        head = seg.start_ea
        while head < seg.end_ea and code_count + data_count < 10000:
            flags = ida_bytes.get_flags(head)
            if ida_bytes.is_code(flags):
                code_count += 1
            elif ida_bytes.is_data(flags):
                data_count += 1
            head = idc.next_head(head, seg.end_ea)
            if head == idaapi.BADADDR:
                break
        
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.end_ea - seg.start_ea),
            "perms": perms or "---",
            "class": ida_segment.get_segm_class(seg),
            "type": seg_type,
            "align": seg.align,
            "bitness": seg.bitness * 16 if seg.bitness else 0,
            "code_heads": code_count,
            "data_heads": data_count,
        })
    return segments

@idaread
def idb_entrypoints_detailed():
    """Entry points with classification."""
    entries = []
    main_names = {"main", "_main", "WinMain", "_WinMain@16", "wmain", "_wmain", 
                  "DllMain", "_DllMain@12", "DllEntryPoint", "start", "_start"}
    
    for i in range(ida_entry.get_entry_qty()):
        ord_val = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord_val)
        name = ida_entry.get_entry_name(ord_val)
        
        # Classify entry type
        entry_type = "export"
        if i == 0:
            entry_type = "entry_point"
        elif name and name in main_names:
            entry_type = "main"
        elif name and name.startswith("Dll"):
            entry_type = "dll_entry"
            
        # Get function info if available
        func = ida_funcs.get_func(ea)
        func_size = None
        if func:
            func_size = hex(func.end_ea - func.start_ea)
            
        entries.append({
            "name": name,
            "addr": hex(ea),
            "ordinal": ord_val,
            "type": entry_type,
            "is_main": name in main_names if name else False,
            "func_size": func_size
        })
    return {"entrypoints": entries, "count": len(entries)}

@idaread
def idb_bookmarks():
    """Get IDA native bookmarks."""
    bookmarks = []
    try:
        for i in range(1000):
            ea = idc.get_bookmark(i)
            if ea == idaapi.BADADDR:
                break
            desc = idc.get_bookmark_desc(i)
            func = ida_funcs.get_func(ea)
            bookmarks.append({
                "index": i, 
                "addr": hex(ea), 
                "desc": desc or "",
                "func": idc.get_func_name(func.start_ea) if func else None
            })
    except AttributeError:
        pass
    return {"bookmarks": bookmarks, "count": len(bookmarks)}

@idaread
def idb_summary():
    """Comprehensive analysis summary."""
    # Count functions
    all_funcs = list(idautils.Functions())
    named_funcs = sum(1 for ea in all_funcs if not idc.get_func_name(ea).startswith("sub_"))
    
    # Count strings
    string_count = idaapi.get_strlist_qty()
    
    # Count imports/exports
    import_count = 0
    for i in range(ida_nalt.get_import_module_qty()):
        def count_cb(ea, name, ordinal):
            nonlocal import_count
            import_count += 1
            return True
        ida_nalt.enum_import_names(i, count_cb)
    
    export_count = ida_entry.get_entry_qty()
    
    # Count comments
    comment_count = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        head = seg.start_ea
        limit = 0
        while head < seg.end_ea and limit < 50000:
            if idc.get_cmt(head, 0) or idc.get_cmt(head, 1):
                comment_count += 1
            head = idc.next_head(head, seg.end_ea)
            if head == idaapi.BADADDR:
                break
            limit += 1
    
    # Coverage estimate
    total_code_bytes = 0
    defined_code_bytes = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg and seg.perm & idaapi.SEGPERM_EXEC:
            seg_size = seg.end_ea - seg.start_ea
            total_code_bytes += seg_size
            head = seg.start_ea
            while head < seg.end_ea:
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_code(flags):
                    defined_code_bytes += idc.get_item_size(head)
                head = idc.next_head(head, seg.end_ea)
                if head == idaapi.BADADDR:
                    break
    
    coverage = round(defined_code_bytes / total_code_bytes * 100, 1) if total_code_bytes > 0 else 0
    
    return {
        "functions": len(all_funcs),
        "named_functions": named_funcs,
        "auto_named_functions": len(all_funcs) - named_funcs,
        "segments": len(list(idautils.Segments())),
        "strings": string_count,
        "imports": import_count,
        "exports": export_count,
        "comments": comment_count,
        "analysis_ok": idaapi.auto_is_ok(),
        "code_coverage_pct": coverage,
        "defined_code_bytes": defined_code_bytes,
        "total_code_bytes": total_code_bytes,
    }


@idaread
def idb_architecture_profile(meta=None, summary=None):
    if meta is None:
        meta = idb_meta()
    if summary is None:
        summary = idb_summary()

    binary_path = str(meta.get("binary_path") or "")
    inferred = {}
    if callable(infer_binary_arch_profile) and binary_path and os.path.exists(binary_path):
        try:
            inferred = infer_binary_arch_profile(binary_path) or {}
        except Exception:
            inferred = {}

    current = {
        "processor": meta.get("processor"),
        "bitness": meta.get("bitness"),
        "endian": "big" if meta.get("is_be") else "little",
        "file_type": meta.get("file_type"),
    }
    file_type = str(meta.get("file_type") or "").strip().lower()
    import_count = int((summary or {}).get("imports", 0) or 0)
    proc = str(meta.get("processor") or "").strip().lower()
    raw_mode = bool(
        file_type in ("raw", "unknown", "")
        or (proc in ("arm", "mips", "ppc", "msp430", "avr", "xtensa") and import_count == 0)
    )
    recs = []
    if raw_mode:
        recs.append("workflow(action='triage_fast')")
        recs.append("firmware_view(action='triage_snapshot')")
        recs.append("analysis(action='set_architecture', processor='<candidate>', bitness=<16|32|64>, endian='<little|big>')")
    return {
        "current": current,
        "inferred_from_binary": inferred,
        "raw_binary_mode": raw_mode,
        "recommendations": recs,
    }
