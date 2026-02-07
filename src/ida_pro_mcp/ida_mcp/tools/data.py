
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================

@tool
@idaread
def data(
    action: Annotated[Literal["functions", "globals", "strings", "imports", "exports", "lookup", "bulk_query"],
                      "Action: functions|globals|strings|imports|exports|lookup|bulk_query"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    include_prototype: Annotated[bool, "Include function prototypes (functions action)"] = False,
    include_xrefs: Annotated[bool, "Include cross-reference counts"] = False,
    min_size: Annotated[Optional[int], "Minimum function size filter"] = None,
    named_only: Annotated[bool, "Only return named (non-sub_) items"] = False,
    **kwargs
) -> dict:
    """
    Query, filter, and list data items: functions, globals, strings, imports.
    All list actions return compact text (one item per line) to minimize LLM context usage.
    
    ACTIONS:
    
    functions - List all defined functions with optional filtering
        Params: query (name filter), offset, count, include_prototype, include_xrefs, 
                min_size, named_only
        Returns: {functions: "addr  size  name [prototype] [xrefs]\\n...", total, offset, count}
        
    globals - List global names/variables (non-functions)
        Params: query (name filter), offset, count, include_xrefs
        Returns: {globals: "addr  name  size=N [type] [xrefs=N]\\n...", total, offset, count}
        
    strings - List string literals with filtering
        Params: query (content filter), offset, count
        Returns: {strings: "addr  xrefs=N  string_value\\n...", total, offset, count}
        
    imports - List imported modules and functions
        Params: query (filter by module or function name), offset, count
        Returns: {imports: "addr  module  name\\n...", total, offset, count}
        
    exports - List exported entry points
        Params: offset, count
        Returns: {exports: "addr  name  size\\n...", total, offset, count}
        
    lookup - Resolve a name to address or address to name
        Params: query (name or address)
        Returns: {addr, name, type, size}
        
    bulk_query - Execute multiple queries in one call
        Params: items (list of {kind, query, offset, count})
        Returns: {results: [{index, kind, result}]}
    """
    try:
        if action == "functions":
            func_lines = []
            
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                
                # Filter by named_only
                if named_only and name.startswith("sub_"):
                    continue
                    
                fn = idaapi.get_func(ea)
                if not fn:
                    continue
                    
                # Filter by min_size
                func_size = fn.end_ea - fn.start_ea
                if min_size and func_size < min_size:
                    continue
                    
                if not _matcher or _matcher(name):
                    total += 1
                    
                    # Collect paginated results
                    if total > offset and (count == 0 or len(func_lines) < count):
                        parts = [hex_ea(ea), hex_size(func_size), name]
                        
                        if include_prototype:
                            parts.append(get_prototype(fn))
                            
                        if include_xrefs:
                            xrefs_to = len(list(idautils.XrefsTo(ea)))
                            xrefs_from = len(list(idautils.XrefsFrom(ea)))
                            parts.append(f"xrefs_to={xrefs_to}")
                            parts.append(f"xrefs_from={xrefs_from}")
                            
                        func_lines.append("  ".join(parts))
            
            result = {"ok": True, "functions": "\n".join(func_lines), "total": total, "offset": offset, "count": len(func_lines)}
            if total == 0:
                result["warning"] = "No functions found matching query."
            return result
        
        elif action == "globals":
            glob_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            for ea, name in idautils.Names():
                if idaapi.get_func(ea):
                    continue
                    
                if named_only and (name.startswith("unk_") or name.startswith("off_") or 
                                   name.startswith("loc_") or name.startswith("byte_") or
                                   name.startswith("word_") or name.startswith("dword_") or
                                   name.startswith("qword_")):
                    continue
                    
                if not _matcher or _matcher(name):
                    total += 1
                    if total > offset and (count == 0 or len(glob_lines) < count):
                        parts = [hex_ea(ea), name]
                        
                        # Get size
                        size = idc.get_item_size(ea)
                        parts.append(f"size={size}")
                        
                        # Try to get type
                        tif = ida_typeinf.tinfo_t()
                        if ida_nalt.get_tinfo(tif, ea):
                            parts.append(str(tif))
                            
                        if include_xrefs:
                            parts.append(f"xrefs={len(list(idautils.XrefsTo(ea)))}")
                            
                        glob_lines.append("  ".join(parts))
            
            return {"ok": True, "globals": "\n".join(glob_lines), "total": total, "offset": offset, "count": len(glob_lines)}
        
        elif action == "strings":
            str_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            for i in range(idaapi.get_strlist_qty()):
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if not content: continue
                        
                        s = content.decode("utf-8", errors="replace")
                        if len(s) < 4: continue
                        
                        # Section check - skip strings in executable sections (likely false positives)
                        seg = idaapi.getseg(sc.ea)
                        if seg and (seg.perm & idaapi.SEGPERM_EXEC) and len(s) < 12:
                            continue
                        
                        # Meaningful check - relax for longer strings
                        if len(s) < 20:
                            alnum_count = sum(1 for c in s if c.isalnum() or c in ' ._-/:=()[]{}\\n\\t')
                            if alnum_count / len(s) < 0.6: continue
                        
                        if not _matcher or _matcher(s):
                            total += 1
                            if total > offset and (count == 0 or len(str_lines) < count):
                                xref_count = len(list(idautils.XrefsTo(sc.ea)))
                                str_lines.append(f"{hex_ea(sc.ea)}  xrefs={xref_count}  {s[:500]}")
                    except Exception:
                        pass
            
            return {"ok": True, "strings": "\n".join(str_lines), "total": total, "offset": offset, "count": len(str_lines)}
        
        elif action == "imports":
            import_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            
            for i in range(ida_nalt.get_import_module_qty()):
                module = ida_nalt.get_import_module_name(i)
                
                # Check module filter
                if _matcher and not _matcher(module):
                    # Still check individual function names
                    pass
                
                # Collect imports
                mod_imports = []
                def cb(ea, name, ordinal):
                    imp_name = name or f"ord_{ordinal}"
                    if not _matcher or _matcher(module) or _matcher(imp_name):
                        mod_imports.append((ea, imp_name, module, ordinal))
                    return True
                ida_nalt.enum_import_names(i, cb)
                
                for ea, imp_name, mod, ordinal in mod_imports:
                    total += 1
                    if total > offset and (count == 0 or len(import_lines) < count):
                        import_lines.append(f"{hex_ea(ea)}  {mod}  {imp_name}")
                        
            return {"ok": True, "imports": "\n".join(import_lines), "total": total, "offset": offset, "count": len(import_lines)}
        
        elif action == "exports":
            export_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            
            # Resolve API
            _qty = getattr(idaapi, "get_entry_qty", None)
            _ordinal = getattr(idaapi, "get_entry_ordinal", None)
            _entry = getattr(idaapi, "get_entry", None)
            _name = getattr(idaapi, "get_entry_name", None)
            
            if not _qty:
                try:
                    import ida_entry
                    if hasattr(ida_entry, 'get_entry_qty'):
                        _qty = ida_entry.get_entry_qty
                        _ordinal = ida_entry.get_entry_ordinal
                        _entry = ida_entry.get_entry
                        _name = ida_entry.get_entry_name
                    else:
                        raise AttributeError("ida_entry has no get_entry_qty")
                except (ImportError, AttributeError):
                    if hasattr(ida_nalt, 'get_entry_qty'):
                        _qty = ida_nalt.get_entry_qty
                        _ordinal = ida_nalt.get_entry_ordinal
                        _entry = ida_nalt.get_entry
                        _name = ida_nalt.get_entry_name
                    else:
                        return make_error(MCPError.IDA_ERROR, "Entry API not available in this IDA version")

            for i in range(_qty()):
                ordinal = _ordinal(i)
                ea = _entry(ordinal)
                name = _name(ordinal)
                
                if query and not _matcher((name or "")):
                    continue
                    
                total += 1
                if total > offset and (count == 0 or len(export_lines) < count):
                    func = idaapi.get_func(ea)
                    size_str = hex_size(func.end_ea - func.start_ea) if func else ""
                    export_lines.append(f"{hex_ea(ea)}  {name}  {size_str}")
                    
            return {"ok": True, "exports": "\n".join(export_lines), "total": total, "offset": offset, "count": len(export_lines)}
        
        elif action == "lookup":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for lookup")
            try:
                result = resolve_symbol(query)
                # Enhance with additional info
                ea = parse_address(result.get("addr", query)) if result.get("addr") else None
                if ea:
                    result["size"] = idc.get_item_size(ea)
                    func = idaapi.get_func(ea)
                    if func:
                        result["is_function"] = True
                        result["func_size"] = hex(func.end_ea - func.start_ea)
                    else:
                        result["is_function"] = False
                return {"ok": True, **result}
            except Exception as e:
                return make_error(MCPError.FILE_NOT_FOUND, str(e))

        elif action == "bulk_query":
            items = kwargs.get("items") or kwargs.get("queries") or []
            if not isinstance(items, list):
                return make_error(MCPError.INVALID_ARGS, "items must be a list")
            results = []
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    results.append({"index": i, "error": "invalid item"})
                    continue
                kind = item.get("kind") or item.get("action")
                if not kind:
                    results.append({"index": i, "error": "missing kind"})
                    continue
                sub_query = item.get("query")
                sub_offset = item.get("offset", 0)
                sub_count = item.get("count", 100)
                res = data(action=kind, query=sub_query, offset=sub_offset, count=sub_count)
                results.append({"index": i, "kind": kind, "result": res})
            return {"ok": True, "results": results, "count": len(results)}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================
