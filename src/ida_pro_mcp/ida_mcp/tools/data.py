
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
    action: Annotated[Literal["functions", "globals", "strings", "imports", "exports", "lookup", "bulk_query", "capability_matrix"],
                      "Action: functions|globals|strings|imports|exports|lookup|bulk_query|capability_matrix"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup (regex/glob/substring/semantic auto-detected)"] = None,
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
    Pattern filters use shared auto-detect matching (regex/glob/substring/semantic).
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
        Params: query (content filter), offset, count, include_xrefs
        Returns: {strings: "addr  [xrefs=N]  string_value\\n...", total, offset, count}
        
    imports - List imported modules and functions
        Params: query (filter by module or function name), offset, count
        Returns: {imports: "addr  module  name\\n...", total, offset, count}
        
    exports - List exported entry points
        Params: offset, count
        Returns: {exports: "addr  name  size\\n...", total, offset, count}
        
        lookup - Resolve a name to address or address to name (exact first, then pattern fallback)
        Params: query (name or address)
        Returns: {addr, name, type, size} or {matches, count} when no exact symbol is found
        
    bulk_query - Execute multiple queries in one call
        Params: items (list of {kind, query, offset, count, include_prototype, include_xrefs, min_size, named_only})
        Returns: {results: [{index, kind, result}]}

    capability_matrix - Build a binary capability matrix from imports and function classifications.
        Returns: {matrix: {category: count}, top_categories, risk_indicators, note}
        Use for: Quick triage and malware capability assessment.
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
                        # Always include capped xref count (hot functions can have thousands)
                        xrefs_to = sum(1 for _ in zip(idautils.XrefsTo(ea), range(999)))
                        parts = [hex_ea(ea), hex_size(func_size), f"xrefs={xrefs_to}", name]
                        
                        if include_prototype:
                            parts.append(get_prototype(fn))
                            
                        if include_xrefs:
                            xrefs_from = sum(1 for _ in zip(idautils.XrefsFrom(ea), range(999)))
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
                if not name:
                    continue
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
                        try:
                            if ida_nalt.get_tinfo(tif, ea):
                                parts.append(str(tif))
                        except (TypeError, AttributeError, RuntimeError):
                            pass
                            
                        if include_xrefs:
                            parts.append(f"xrefs={len(list(idautils.XrefsTo(ea)))}")
                            
                        glob_lines.append("  ".join(parts))
            
            return {"ok": True, "globals": "\n".join(glob_lines), "total": total, "offset": offset, "count": len(glob_lines)}
        
        elif action == "strings":
            str_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            strings_iter = None
            try:
                strings_iter = idautils.Strings()
            except Exception:
                strings_iter = None

            if strings_iter is not None:
                for s in strings_iter:
                    try:
                        content = str(s)
                        if isinstance(content, bytes):
                            content = content.decode("utf-8", errors="replace")
                        if not content:
                            continue
                        if len(content) < 4:
                            continue

                        seg = idaapi.getseg(s.ea)
                        if seg and (seg.perm & idaapi.SEGPERM_EXEC) and len(content) < 12:
                            continue

                        if len(content) < 20:
                            alnum_count = sum(
                                1 for c in content if c.isalnum() or c in " ._-/:=()[]{}\\n\\t"
                            )
                            if alnum_count / len(content) < 0.6:
                                continue

                        if not _matcher or _matcher(content):
                            total += 1
                            if total > offset and (count == 0 or len(str_lines) < count):
                                xref_count = sum(1 for _ in zip(idautils.XrefsTo(s.ea), range(999)))
                                parts = [hex_ea(s.ea), f"xrefs={xref_count}", content[:500]]
                                str_lines.append("  ".join(parts))
                    except Exception:
                        continue
            else:
                strlist_qty = getattr(idaapi, "get_strlist_qty", None)
                strlist_item = getattr(idaapi, "get_strlist_item", None)
                if strlist_qty and strlist_item:
                    for i in range(strlist_qty()):
                        sc = idaapi.string_info_t()
                        if strlist_item(sc, i):
                            try:
                                # get_strlit_contents signature varies across IDA versions.
                                try:
                                    content = idc.get_strlit_contents(sc.ea, sc.length, sc.type)
                                except TypeError:
                                    content = idc.get_strlit_contents(sc.ea)
                                if not content:
                                    continue
                                if isinstance(content, bytes):
                                    s = content.decode("utf-8", errors="replace")
                                else:
                                    s = content
                                if len(s) < 4:
                                    continue

                                seg = idaapi.getseg(sc.ea)
                                if seg and (seg.perm & idaapi.SEGPERM_EXEC) and len(s) < 12:
                                    continue

                                if len(s) < 20:
                                    alnum_count = sum(
                                        1 for c in s if c.isalnum() or c in " ._-/:=()[]{}\\n\\t"
                                    )
                                    if alnum_count / len(s) < 0.6:
                                        continue

                                if not _matcher or _matcher(s):
                                    total += 1
                                    if total > offset and (count == 0 or len(str_lines) < count):
                                        xref_count = sum(1 for _ in zip(idautils.XrefsTo(sc.ea), range(999)))
                                        parts = [hex_ea(sc.ea), f"xrefs={xref_count}", s[:500]]
                                        str_lines.append("  ".join(parts))
                            except Exception:
                                continue
            
            return {"ok": True, "strings": "\n".join(str_lines), "total": total, "offset": offset, "count": len(str_lines)}
        
        elif action == "imports":
            import_lines = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            
            for i in range(ida_nalt.get_import_module_qty()):
                module = ida_nalt.get_import_module_name(i) or f"module_{i}"
                
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
                # Fallback: search names with smart pattern matching when exact resolution fails.
                matcher = compile_smart_pattern(query, case_sensitive=False)
                matches = []
                for ea, name in idautils.Names():
                    if not name:
                        continue
                    if not matcher(name):
                        continue
                    item = {"addr": hex_ea(ea), "name": name}
                    func = idaapi.get_func(ea)
                    item["type"] = "function" if func else "symbol"
                    if func:
                        item["func_size"] = hex_size(func.end_ea - func.start_ea)
                    else:
                        item["size"] = idc.get_item_size(ea)
                    matches.append(item)
                    if len(matches) >= 200:
                        break
                if matches:
                    page = matches[offset : offset + count] if count != 0 else matches[offset:]
                    lines = [f"{m['addr']}  {m['name']}  {m['type']}" for m in page]
                    return {
                        "ok": True,
                        "query": query,
                        "exact_match": False,
                        "matches": "\n".join(lines),
                        "items": page,
                        "total": len(matches),
                        "offset": offset,
                        "count": len(page),
                        "note": "No exact symbol match; returning pattern-matched symbols",
                    }
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
                sub_args = {
                    "action": kind,
                    "query": item.get("query"),
                    "offset": item.get("offset", 0),
                    "count": item.get("count", 100),
                }
                for key in ("include_prototype", "include_xrefs", "min_size", "named_only"):
                    if key in item:
                        sub_args[key] = item.get(key)
                res = data(**sub_args)
                results.append({"index": i, "kind": kind, "result": res})
            return {"ok": True, "results": results, "count": len(results)}

        elif action == "capability_matrix":
            # Build capability matrix from imports and function API usage
            matrix = {cat: 0 for cat in API_CATEGORIES}
            risk_indicators = []
            
            # Analyze imports
            imports = {}
            def imp_cb(ea, name, ordinal):
                if name:
                    imports[name] = ea
                return True
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                ida_nalt.enum_import_names(i, imp_cb)
            
            for name in imports:
                low = name.lower()
                for cat, apis in API_CATEGORIES.items():
                    for api in apis:
                        if api.lower() in low:
                            matrix[cat] += 1
                            break
                # Risk indicators
                if low in DANGEROUS_APIS or any(low.endswith(s) for s in ("A", "W", "@plt", "@PLT") if low[:-len(s)] in DANGEROUS_APIS):
                    risk_indicators.append(name)
            
            # Analyze functions for API calls (sample first 200)
            func_count = 0
            for func_ea in idautils.Functions():
                if func_count >= 200:
                    break
                func_count += 1
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue
                for head in idautils.Heads(fn.start_ea, fn.end_ea):
                    for xref in idautils.CodeRefsFrom(head, 0):
                        callee = idc.get_func_name(xref) or ""
                        if callee:
                            low = callee.lower()
                            for cat, apis in API_CATEGORIES.items():
                                for api in apis:
                                    if api.lower() in low:
                                        matrix[cat] += 1
                                        break
                            if low in DANGEROUS_APIS:
                                risk_indicators.append(callee)
            
            # Sort categories by count
            sorted_cats = sorted(matrix.items(), key=lambda x: -x[1])
            top_categories = [f"{cat}:{count}" for cat, count in sorted_cats if count > 0][:10]
            
            # Determine binary type heuristic
            binary_type = "unknown"
            if matrix.get("network", 0) > 5 and matrix.get("crypto", 0) > 2:
                binary_type = "malware_or_security_tool"
            elif matrix.get("network", 0) > 10:
                binary_type = "server_or_network_app"
            elif matrix.get("ui", 0) > 10:
                binary_type = "gui_application"
            elif matrix.get("file_io", 0) > 10 and matrix.get("string_ops", 0) > 5:
                binary_type = "utility"
            elif matrix.get("crypto", 0) > 5:
                binary_type = "crypto_tool"
            elif matrix.get("process", 0) > 5:
                binary_type = "system_tool"
            
            return {
                "ok": True,
                "matrix": {k: v for k, v in sorted_cats if v > 0},
                "top_categories": top_categories,
                "binary_type_heuristic": binary_type,
                "risk_indicators": sorted(set(risk_indicators))[:20],
                "total_imports": len(imports),
                "note": "Capability matrix derived from import analysis and function API call patterns. Use for quick triage.",
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================
