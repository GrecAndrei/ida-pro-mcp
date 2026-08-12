
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

# Bounded cache of full (filtered-but-unpaginated) walks for the list actions.
# Pagination then slices offset/count without re-walking idautils.Functions()/
# Names()/Strings() on every page. Keyed by (action, filters, idb fingerprint)
# so a stale page can never be served for a different binary or after new
# functions were created.
_WALK_CACHE: dict = {}
_WALK_CACHE_MAX = 16


def _walk_cache_get(key):
    val = _WALK_CACHE.get(key)
    if val is not None:
        _WALK_CACHE.pop(key)
        _WALK_CACHE[key] = val  # LRU touch
    return val


def _walk_cache_put(key, val):
    if key in _WALK_CACHE:
        _WALK_CACHE.pop(key)
    _WALK_CACHE[key] = val
    if len(_WALK_CACHE) > _WALK_CACHE_MAX:
        _WALK_CACHE.pop(next(iter(_WALK_CACHE)))


def _walk_fingerprint():
    """Opaque IDB identity for the walk cache: root filename + function qty.

    Bounded staleness guard: a page-N lookup never serves a different binary's
    walk, and a rename/creation that changes the function count busts the cache.
    """
    try:
        root = ida_nalt.get_root_filename()
    except Exception:
        root = ""
    try:
        fq = idaapi.get_func_qty()
    except Exception:
        fq = -1
    return (root, fq)


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================

@tool
@idaread
def data(
    action: Annotated[Literal["functions", "annotations", "globals", "strings", "imports", "exports", "lookup", "bulk_query", "capability_matrix", "string_xrefs", "read_bytes"],
                      "Action: functions|annotations|globals|strings|imports|exports|lookup|bulk_query|capability_matrix|string_xrefs|read_bytes"],
    query: Annotated[Optional[str], "Filter pattern or name/address for lookup (regex/glob/substring/semantic auto-detected)"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    include_prototype: Annotated[bool, "Include function prototypes (functions action)"] = False,
    include_xrefs: Annotated[bool, "Include cross-reference counts"] = False,
    min_size: Annotated[Optional[int], "Minimum function size filter"] = None,
    min_xrefs: Annotated[Optional[int], "For functions action: keep only functions with >= this many xrefs_to. Cheap filter that avoids paying for thousands of stub functions."] = None,
    named_only: Annotated[bool, "Only return named (non-sub_) items"] = False,
    min_len: Annotated[int, "Minimum string length for strings action"] = 6,
    structured: Annotated[bool, "When true, also return an 'items' list of structured records alongside the compact text"] = False,
    **kwargs
) -> dict:
    """
    Query, filter, and list data items: functions, globals, strings, imports.
    Pattern filters use shared auto-detect matching (regex/glob/substring/semantic).
    All list actions return compact text (one item per line) to minimize LLM context usage.

    ACTIONS:

    functions - List all defined functions with optional filtering
        Params: query (name filter), offset, count, include_prototype, include_xrefs,
                min_size, min_xrefs (>= N xrefs_to), named_only
        Returns: {functions: "addr  size  name [prototype] [xrefs]\\n...", total, offset, count}
        Tip: setting min_xrefs=3 cuts the long tail of stub functions so callers
        don't pay to paginate thousands of zero-caller entries.

    annotations - List functions carrying recorded understanding: a non-auto name
        or a comment. The only read path for comments in the tool surface.
        Params: query (name filter), offset, count
        Returns: {annotations: [{addr, name, auto_named, comment?, repeatable_comment?}], total}

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

    string_xrefs - Build a string->referencing-function map with ranking and module clustering.
        Returns: {top_strings, module_map, total_strings_scanned}

    read_bytes - Read raw bytes at an address with hex dump and ASCII preview.
        Params: addr (hex address string), size (max 4096, default 64)
        Returns: {ok, addr, size, hex, dump}
    """
    try:
        if action == "functions":
            _key = ("functions", query, min_size, named_only, min_xrefs, _walk_fingerprint())
            walk = _walk_cache_get(_key)
            if walk is None:
                walk = []
                _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
                for ea in idautils.Functions():
                    name = ida_funcs.get_func_name(ea)

                    # Filter by named_only
                    if named_only and name.startswith("sub_"):
                        continue

                    fn = _compat.get_func_info(ea)
                    if fn is None:
                        continue

                    # Filter by min_size
                    func_size = fn.end_ea - fn.start_ea
                    if min_size and func_size < min_size:
                        continue

                    # Filter by min_xrefs (cheap single pass; collects via XrefsTo).
                    # Without this filter an `idautils.Functions()` walk on a
                    # large binary can return thousands of stub functions with
                    # zero callers. Pre-filtering here means agents don't pay
                    # the cost of paginating junk results.
                    if min_xrefs is not None:
                        # Count only up to the requested threshold: gives an exact
                        # ">= min_xrefs" answer without paying for every xref on the
                        # hottest functions (no 999 cap, so min_xrefs > 999 works).
                        xref_count = 0
                        for _ in idautils.XrefsTo(ea):
                            xref_count += 1
                            if xref_count >= min_xrefs:
                                break
                        if xref_count < min_xrefs:
                            continue

                    if not _matcher or _matcher(name):
                        walk.append({"ea": ea, "name": name, "size": func_size})
                _walk_cache_put(_key, walk)

            # Slice the cached full walk by offset/count; the expensive
            # Functions() walk runs once per (query, filters, idb) not per page.
            total = len(walk)
            page = walk[offset:offset + count] if count != 0 else walk[offset:]
            func_lines = []
            func_items: list[dict] = []
            for rec in page:
                ea = rec["ea"]
                name = rec["name"]
                func_size = rec["size"]
                fn = idaapi.get_func(ea)
                # Always include capped xref count (hot functions can have thousands)
                xrefs_to = sum(1 for _ in zip(idautils.XrefsTo(ea), range(999), strict=False))
                parts = [hex_ea(ea), hex_size(func_size), f"xrefs={xrefs_to}", name]

                if include_prototype:
                    parts.append(get_prototype(fn))

                if include_xrefs:
                    xrefs_from = sum(1 for _ in zip(idautils.XrefsFrom(ea), range(999), strict=False))
                    parts.append(f"xrefs_from={xrefs_from}")

                func_lines.append("  ".join(parts))
                if structured:
                    item: dict = {"addr": hex_ea(ea), "name": name, "size": func_size, "xrefs_to": xrefs_to}
                    if include_prototype:
                        item["prototype"] = get_prototype(fn)
                    if include_xrefs:
                        item["xrefs_from"] = xrefs_from
                    func_items.append(item)

            result: dict = {
                "ok": True,
                "functions": "\n".join(func_lines),
                "total": total,
                "offset": offset,
                "count": len(func_lines),
            }
            if structured:
                result["items"] = func_items
            if total == 0:
                result["warning"] = "No functions found matching query."
            return result

        elif action == "annotations":
            # Names and comments an analyst (or a previous session) already
            # applied. This is the only read path for comments: everything
            # else in the tool surface can write them but not get them back,
            # so understanding recorded in the IDB was invisible to the host.
            ann_items: list[dict] = []
            total = 0
            _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea) or ""
                auto_named = (
                    not name
                    or name.startswith(("sub_", "j_", "loc_", "nullsub_", "unknown_libname_"))
                )
                comments = {}
                for label, repeatable in (("comment", False), ("repeatable_comment", True)):
                    try:
                        text = idc.get_func_cmt(ea, repeatable) or ""
                    except Exception:
                        text = ""
                    if text.strip():
                        comments[label] = text.strip()
                # A function with an auto name and no comment carries no
                # recorded understanding; skip it rather than paginate noise.
                if auto_named and not comments:
                    continue
                if _matcher and not _matcher(name):
                    continue
                total += 1
                if total > offset and (count == 0 or len(ann_items) < count):
                    item = {"addr": hex_ea(ea), "name": name, "auto_named": auto_named}
                    item.update(comments)
                    ann_items.append(item)
            return {
                "ok": True,
                "annotations": ann_items,
                "total": total,
                "offset": offset,
                "count": len(ann_items),
            }

        elif action == "globals":
            _key = ("globals", query, named_only, _walk_fingerprint())
            walk = _walk_cache_get(_key)
            if walk is None:
                walk = []
                _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
                for ea, name in idautils.Names():
                    if not name:
                        continue
                    if _compat.get_func_start(ea) is not None:
                        continue
                    if named_only and (name.startswith(("unk_", "off_", "loc_", "byte_", "word_", "dword_", "qword_"))):
                        continue

                    if not _matcher or _matcher(name):
                        walk.append((ea, name))
                _walk_cache_put(_key, walk)

            # Slice the cached full Names() walk; per-page work only recomputes
            # size/type/xrefs for the items actually returned.
            total = len(walk)
            page = walk[offset:offset + count] if count != 0 else walk[offset:]
            glob_lines = []
            for ea, name in page:
                parts = [hex_ea(ea), name]

                # Get size
                size = idc.get_item_size(ea)
                parts.append(f"size={size}")

                # Try to get type
                tif = ida_typeinf.tinfo_t()
                try:
                    if ida_nalt.get_tinfo(tif, ea):
                        parts.append(str(tif))
                        # If it's a struct, enumerate fields
                        if tif.is_struct():
                            udt = ida_typeinf.udt_type_data_t()
                            if tif.get_udt_details(udt):
                                fields = []
                                for i in range(min(udt.size(), 16)):
                                    member = udt[i]
                                    fname = str(getattr(member, "name", "") or "")
                                    ftype = str(getattr(member, "type", "") or "")
                                    foff = int(getattr(member, "offset", 0) or 0)
                                    fields.append(f"{fname}:{ftype}@{hex(foff)}")
                                if fields:
                                    parts.append(f"fields=[{', '.join(fields)}]")
                except (TypeError, AttributeError, RuntimeError):
                    pass

                if include_xrefs:
                    # Cap at 999 like functions/strings — globals can have
                    # tens of thousands of refs; avoid building the full list.
                    xrefs_count = sum(1 for _ in zip(idautils.XrefsTo(ea), range(999), strict=False))
                    parts.append(f"xrefs={xrefs_count}")

                glob_lines.append("  ".join(parts))

            return {"ok": True, "globals": "\n".join(glob_lines), "total": total, "offset": offset, "count": len(glob_lines)}

        elif action == "strings":
            _key = ("strings", query, min_len, _walk_fingerprint())
            walk = _walk_cache_get(_key)
            if walk is None:
                walk = []
                _matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
                try:
                    min_len = max(1, int(min_len))
                except Exception:
                    min_len = 6
                # Raw blobs are noisy before code/data heads exist.
                if _inf_filetype_id() in {0, 2, 17} and min_len < 8:
                    min_len = 8
                # Adaptive printable-ratio gate for short strings.
                ratio_samples = []
                try:
                    _probe = idautils.Strings()
                    _n = 0
                    for _s in _probe:
                        if _n >= 800:
                            break
                        _c = str(_s)
                        if isinstance(_c, bytes):
                            _c = _c.decode("utf-8", errors="replace")
                        if _c and len(_c) < 20:
                            _a = sum(1 for _ch in _c if _ch.isalnum() or _ch in " ._-/:=()[]{}\n\t")
                            ratio_samples.append(_a / max(1, len(_c)))
                        _n += 1
                except Exception:
                    ratio_samples = []
                if ratio_samples:
                    ratio_samples.sort()
                    q50 = ratio_samples[len(ratio_samples) // 2]
                    q75 = ratio_samples[min(len(ratio_samples) - 1, int(round((len(ratio_samples) - 1) * 0.75)))]
                    printable_gate = q50
                    if q75 > q50:
                        printable_gate = q50 + 0.5 * (q75 - q50)
                else:
                    printable_gate = 0.6
                strings_iter = None
                try:
                    strings_iter = idautils.Strings()
                except Exception:
                    strings_iter = None

                def _accept(ea, content):
                    if not content:
                        return False
                    if len(content) < min_len:
                        return False
                    seg = idaapi.getseg(ea)
                    if seg and (seg.perm & idaapi.SEGPERM_EXEC) and len(content) < 12:
                        return False
                    if len(content) < 20:
                        alnum_count = sum(
                            1 for c in content if c.isalnum() or c in " ._-/:=()[]{}\n\t"
                        )
                        if (alnum_count / len(content)) < printable_gate:
                            return False
                    return not (_matcher and not _matcher(content))

                if strings_iter is not None:
                    for s in strings_iter:
                        try:
                            content = str(s)
                            if isinstance(content, bytes):
                                content = content.decode("utf-8", errors="replace")
                            if _accept(s.ea, content):
                                walk.append((s.ea, content))
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
                                    content = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
                                    if _accept(sc.ea, content):
                                        walk.append((sc.ea, content))
                                except Exception:
                                    continue
                _walk_cache_put(_key, walk)

            # Slice the cached full Strings() walk; xref counts are recomputed
            # only for the page actually returned.
            total = len(walk)
            page = walk[offset:offset + count] if count != 0 else walk[offset:]
            str_lines = []
            for ea, content in page:
                xref_count = sum(1 for _ in zip(idautils.XrefsTo(ea), range(999), strict=False))
                parts = [hex_ea(ea), f"xrefs={xref_count}", content[:500]]
                str_lines.append("  ".join(parts))

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
                mod_imports: list = []
                def cb(ea, name, ordinal, _module=module, _mod_imports=mod_imports):
                    imp_name = name or f"ord_{ordinal}"
                    if not _matcher or _matcher(_module) or _matcher(imp_name):
                        _mod_imports.append((ea, imp_name, _module, ordinal))
                    return True
                ida_nalt.enum_import_names(i, cb)

                for ea, imp_name, mod, _ordinal in mod_imports:
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

                if query and not _matcher(name or ""):
                    continue

                total += 1
                if total > offset and (count == 0 or len(export_lines) < count):
                    func = _compat.get_func_info(ea)
                    size_str = hex_size(func.end_ea - func.start_ea) if func is not None else ""
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
                    func = _compat.get_func_info(ea)
                    if func is not None:
                        result["is_function"] = True
                        result["func_size"] = hex(func.end_ea - func.start_ea)
                    else:
                        result["is_function"] = False
                result["exact_match"] = True
                result["query"] = query
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
                    func = _compat.get_func_info(ea)
                    item["type"] = "function" if func is not None else "symbol"
                    if func is not None:
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
            if not isinstance(items, list) or not items:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "bulk_query requires items=[{kind, query, ...}, ...]. "
                    "Example: data(action='bulk_query', items=["
                    "{'kind':'functions','count':10},"
                    "{'kind':'strings','query':'http'},"
                    "{'kind':'imports'}])"
                )
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
            matrix = dict.fromkeys(API_CATEGORIES, 0)
            risk_indicators = []
            # DANGEROUS_APIS keys are mixed-case (VirtualAlloc, ShellExecuteA, ...);
            # match case-insensitively so imports with any casing are flagged.
            _danger_low = {api.lower() for api in DANGEROUS_APIS}
            _suffixes = ("a", "w", "@plt")

            def _is_dangerous(low: str) -> bool:
                if low in _danger_low:
                    return True
                return any(
                    low.endswith(s) and low[: len(low) - len(s)] in _danger_low
                    for s in _suffixes
                )

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
                if _is_dangerous(low):
                    risk_indicators.append(name)

            # Analyze functions for API calls (sample first 200)
            func_count = 0
            for func_ea in idautils.Functions():
                if func_count >= 200:
                    break
                func_count += 1
                fn = _compat.get_func_info(func_ea)
                if fn is None:
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
                            if _is_dangerous(low):
                                risk_indicators.append(callee)

            # Sort categories by count
            sorted_cats = sorted(matrix.items(), key=lambda x: -x[1])
            top_categories = [f"{cat}:{count}" for cat, count in sorted_cats if count > 0][:10]

            # Determine binary type from adaptive category prominence.
            binary_type = "unknown"
            vals = sorted(float(v or 0) for v in matrix.values())
            if vals:
                q50 = vals[len(vals) // 2]
                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                gate = q75 + max(0.0, q75 - q50)
            else:
                gate = 0.0
            network = float(matrix.get("network", 0) or 0.0)
            crypto = float(matrix.get("crypto", 0) or 0.0)
            ui = float(matrix.get("ui", 0) or 0.0)
            fio = float(matrix.get("file_io", 0) or 0.0)
            str_ops = float(matrix.get("string_ops", 0) or 0.0)
            process = float(matrix.get("process", 0) or 0.0)
            if network >= gate and crypto >= q50:
                binary_type = "malware_or_security_tool"
            elif network >= gate:
                binary_type = "server_or_network_app"
            elif ui >= gate:
                binary_type = "gui_application"
            elif fio >= gate and str_ops >= q50:
                binary_type = "utility"
            elif crypto >= gate:
                binary_type = "crypto_tool"
            elif process >= gate:
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

        elif action == "string_xrefs":
            def _score_string(text: str, ref_count: int) -> float:
                low = text.lower()
                score = float(ref_count)
                signals = (
                    "version", "copyright", "error", "assert",
                    "module", "fatal", "panic", "exception", "fail",
                    "wifi_", "bt_", "ble_", "eth_", "usb_", "uart_",
                )
                for token in signals:
                    if token in low:
                        score += 2.0
                if "%" in text:
                    score += 1.0
                if len(text) <= 120:
                    score += 0.5
                return score

            def _module_key(text: str) -> str:
                s = text.strip()
                for sep in ("::", "_", ".", ":", "/", "-"):
                    if sep in s:
                        part = s.split(sep, 1)[0].strip()
                        if part:
                            return part.lower()[:32]
                chunks = s.split()
                if chunks:
                    return chunks[0].lower()[:32]
                return "misc"

            entries = []
            unref_entries = []
            total_scanned = 0
            strings_iter = idautils.Strings()
            for s in strings_iter:
                try:
                    content = str(s)
                    if isinstance(content, bytes):
                        content = content.decode("utf-8", errors="replace")
                    if not content:
                        continue
                    if len(content) < max(4, int(min_len)):
                        continue
                    total_scanned += 1
                    refs = []
                    seen_funcs = set()
                    for xr in idautils.XrefsTo(s.ea):
                        frm = getattr(xr, "frm", None)
                        if frm is None:
                            continue
                        fstart = _compat.get_func_start(frm)
                        if fstart is None:
                            continue
                        if fstart in seen_funcs:
                            continue
                        seen_funcs.add(fstart)
                        refs.append({
                            "addr": hex_ea(fstart),
                            "name": ida_funcs.get_func_name(fstart) or f"sub_{fstart:x}",
                        })
                    ref_count = len(refs)
                    rec = {
                        "string_addr": hex_ea(s.ea),
                        "string": content[:300],
                        "ref_count": ref_count,
                        "interesting_score": round(_score_string(content, ref_count), 3),
                        "referencing_functions": refs[:50],
                        "_module_key": _module_key(content),
                    }
                    # Zero-ref strings are kept (they were silently dropped
                    # before): unreferenced version/config blobs are often the
                    # interesting strings on a raw blob or a partially analyzed
                    # binary. They land in strings_without_refs with their score.
                    if ref_count == 0:
                        unref_entries.append(rec)
                    else:
                        entries.append(rec)
                except Exception:
                    continue

            entries.sort(key=lambda x: (x["interesting_score"], x["ref_count"]), reverse=True)
            top_entries = entries[:50]
            unref_entries.sort(key=lambda x: (x["interesting_score"], x["ref_count"]), reverse=True)
            top_unref = unref_entries[:50]

            module_map = {}
            for ent in top_entries:
                mk = ent.get("_module_key", "misc")
                rec = module_map.setdefault(mk, {"strings": 0, "functions": set()})
                rec["strings"] += 1
                for f in ent.get("referencing_functions", []):
                    rec["functions"].add(f.get("name", ""))

            module_map_out = {}
            for mk, rec in module_map.items():
                funcs = sorted(x for x in rec["functions"] if x)
                module_map_out[mk] = {
                    "strings": rec["strings"],
                    "function_count": len(funcs),
                    "functions": funcs[:30],
                }

            for ent in top_entries:
                ent.pop("_module_key", None)
            for ent in top_unref:
                ent.pop("_module_key", None)

            result = {
                "ok": True,
                "top_strings": top_entries,
                "module_map": module_map_out,
                "total_strings_scanned": total_scanned,
                "count": len(top_entries),
            }
            if top_unref:
                result["strings_without_refs"] = top_unref
                try:
                    _is_raw = _inf_filetype_id() in {0, 2, 17}
                except Exception:
                    _is_raw = False
                try:
                    _is_riscv = bool(is_riscv_family())
                except Exception:
                    _is_riscv = False
                if _is_raw or _is_riscv:
                    _note = (
                        "strings_without_refs are unreferenced strings "
                        "(often version/config blobs); on raw blobs or when the "
                        "RISC-V GP register is unset, data xref resolution may be incomplete."
                    )
                else:
                    _note = (
                        "strings_without_refs are unreferenced strings "
                        "(often version/config blobs); data xref resolution may be incomplete."
                    )
                result["note"] = _note
            return result

        elif action == "read_bytes":
            addr_val = kwargs.get("addr") or query
            if not addr_val:
                return make_error(MCPError.INVALID_ARGS, "addr required for read_bytes")
            ea, err = validate_addr(addr_val)
            if err:
                return err
            size = max(1, min(4096, int(kwargs.get("size") or count or 64)))
            raw = ida_bytes.get_bytes(ea, size)
            if raw is None:
                return make_error(MCPError.IDA_ERROR, f"Could not read {size} bytes at {hex(ea)}")
            hex_str = raw.hex()
            # Format as hex dump: 16 bytes per row with ASCII preview
            rows = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                rows.append(f"{hex(ea + i):>10}:  {hex_part}  |{ascii_part}|")
            return {
                "ok": True,
                "addr": hex(ea),
                "size": size,
                "hex": hex_str,
                "dump": "\n".join(rows),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================
