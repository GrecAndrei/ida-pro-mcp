
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# CLASSIFY - Function and Binary Purpose Classification for LLMs
# ============================================================================

try:
    from ._api_categories import API_CATEGORIES as _CATEGORY_APIS, API_TO_CATEGORY as _API_TO_CATEGORY
except ImportError:
    from _api_categories import API_CATEGORIES as _CATEGORY_APIS, API_TO_CATEGORY as _API_TO_CATEGORY  # type: ignore[import-not-found]


def _get_func_callees(func_ea, max_items=200):
    """Return list of callee names for the function at func_ea."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    callees = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            name = idc.get_func_name(xref)
            if name and name not in callees:
                callees.append(name)
                if len(callees) >= max_items:
                    return callees
    return callees


def _classify_func(func_ea):
    """Classify a single function based on its API calls. Returns (category, apis_matched, all_callees)."""
    callees = _get_func_callees(func_ea)
    category_hits = {}
    matched_apis = {}
    for callee in callees:
        # Strip common suffixes (A/W for Windows APIs, @plt for ELF)
        cat = _API_TO_CATEGORY.get(_normalize_api_name(callee).lower())
        if cat:
            category_hits[cat] = category_hits.get(cat, 0) + 1
            matched_apis.setdefault(cat, []).append(callee)
    if not category_hits:
        return "unknown", {}, callees
    top_cat = max(category_hits, key=category_hits.get)
    return top_cat, matched_apis, callees


def _count_func_instructions(func_ea, max_insns=10000):
    """Count instructions in a function (architecture-neutral)."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return 0
    count = 0
    for _ in idautils.Heads(fn.start_ea, fn.end_ea):
        count += 1
        if count >= max_insns:
            break
    return count


def _get_xrefs_to_count(ea, max_xrefs=5000):
    """Count code cross-references to an address."""
    count = 0
    for xref in idautils.XrefsTo(ea, 0):
        if xref.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN):
            count += 1
            if count >= max_xrefs:
                break
    return count


def _normalize_api_name(name: str) -> str:
    """Normalize API names for category matching."""
    base = name or ""
    for suffix in ("A", "W", "@plt", "@PLT"):
        if base.endswith(suffix):
            return base[:-len(suffix)]
    return base


def _collect_schema_hints(fn, fname: str, callees: list[str], insn_count: int, xref_count: int) -> tuple[set[str], set[str]]:
    """Collect compiler and structural hints for schema induction."""
    compiler_hints: set[str] = set()
    structural_features: set[str] = set()

    flags = getattr(fn, "flags", 0) if fn else 0
    fn_name = (fname or "").lower()
    callee_bases = {_normalize_api_name(c).lower() for c in callees if c}

    try:
        seg = ida_segment.getseg(fn.start_ea) if fn else None
        seg_name = (ida_segment.get_segm_name(seg) if seg else "") or ""
    except Exception:
        seg_name = ""
    seg_low = seg_name.lower()

    if flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        compiler_hints.update({"library_or_thunk", "compiler_generated"})
        structural_features.add("thunk")

    if fn_name.startswith(("j_", "nullsub_")) or fn_name.startswith("__"):
        compiler_hints.add("compiler_generated")
        structural_features.add("compiler_stub")

    if "stack_chk" in fn_name or "security_check_cookie" in fn_name or "chkstk" in fn_name:
        compiler_hints.add("stack_protector")

    if any(token in callee_bases for token in {
        "__stack_chk_fail", "__security_check_cookie", "__chkstk",
        "__cxa_finalize", "__libc_start_main", "__gmon_start__",
    }):
        compiler_hints.add("runtime_support")

    if any(token in seg_low for token in (".plt", ".plt.sec", ".got", ".idata", ".crt")):
        compiler_hints.add("import_thunk")
        structural_features.add("import_stub")

    if any(token in seg_low for token in (".init", ".fini", ".ctors", ".dtors", ".init_array", ".fini_array")):
        compiler_hints.add("runtime_initializer")
        structural_features.add("initializer")

    if insn_count <= 4:
        structural_features.add("very_small")
    elif insn_count <= 10:
        structural_features.add("small")

    if len(callees) == 0:
        structural_features.add("leaf")
    elif len(callees) == 1 and insn_count <= 12:
        structural_features.add("wrapper")

    if xref_count == 0:
        structural_features.add("orphan")
    elif xref_count > 20:
        structural_features.add("highly_referenced")

    if fn_name and not fn_name.startswith(("sub_", "loc_", "unk_")):
        structural_features.add("named_entry")

    if "main" in fn_name or "start" in fn_name or "entry" in fn_name:
        structural_features.add("entry_like")

    return compiler_hints, structural_features


# ============================================================================
# VOERA: Schema Induction for Structured Semantic Retrieval
# ============================================================================

def _induce_function_schema(func_ea: int) -> dict:
    """Induce a structured attribute-value schema for a single function.
    
    Returns dict with behavior_tags, dangerous_apis, string_refs, vuln_class,
    compiler_hints, and structural_features.
    """
    schema = {
        "behavior_tags": set(),
        "dangerous_apis": set(),
        "string_refs": set(),
        "vuln_class": set(),
        "compiler_hints": set(),
        "structural_features": set(),
    }
    
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return schema
    
    callees = _get_func_callees(func_ea)
    
    # Category-based behavior tags
    category_hits = {}
    matched_apis = {}
    for callee in callees:
        base = _normalize_api_name(callee)
        cat = _API_TO_CATEGORY.get(base.lower())
        if cat:
            category_hits[cat] = category_hits.get(cat, 0) + 1
            matched_apis.setdefault(cat, []).append(callee)
            schema["behavior_tags"].add(cat)

    # Broader semantic tags used by structured search should be available here
    # too so classify() and search(action="structured") stay aligned.
    try:
        for tag, apis in _CATEGORY_APIS.items():
            for api in apis:
                api_base = _normalize_api_name(api).lower()
                if any(_normalize_api_name(callee).lower() == api_base for callee in callees):
                    schema["behavior_tags"].add(tag)
                    break
    except Exception:
        pass
    
    # Dangerous API detection
    for callee in callees:
        if callee in DANGEROUS_APIS:
            schema["dangerous_apis"].add(callee)
            schema["vuln_class"].add("dangerous_api")
        base = _normalize_api_name(callee)
        if base in DANGEROUS_APIS:
            schema["dangerous_apis"].add(callee)
            schema["vuln_class"].add("dangerous_api")
    
    # String references
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for dref in idautils.DataRefsFrom(head):
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                s = idc.get_strlit_contents(dref, -1, stype)
                if s:
                    s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    schema["string_refs"].add(s[:80])
                    # Heuristic behavior tags from strings
                    if any(proto in s for proto in ("http://", "https://", "ftp://")):
                        schema["behavior_tags"].add("network")
                    if "HKEY_" in s or "Software\\" in s:
                        schema["behavior_tags"].add("registry")
                    if s.startswith("C:\\") or "/home/" in s or "/usr/" in s:
                        schema["behavior_tags"].add("file_io")
                    if any(cmd in s for cmd in ("cmd.exe", "/bin/sh", "powershell", "bash")):
                        schema["behavior_tags"].add("process")
                        schema["vuln_class"].add("command_injection")

    # Compiler / structural hints
    insn_count = _count_func_instructions(func_ea)
    xref_count = _get_xrefs_to_count(func_ea)
    compiler_hints, structural_features = _collect_schema_hints(
        fn,
        idc.get_func_name(func_ea) or "",
        callees,
        insn_count,
        xref_count,
    )
    schema["compiler_hints"].update(compiler_hints)
    schema["structural_features"].update(structural_features)

    # Structural features
    if insn_count < 5:
        schema["structural_features"].add("very_small")
    elif insn_count > 500:
        schema["structural_features"].add("very_large")
    
    # Loop detection
    try:
        fc = idaapi.FlowChart(fn)
        for block in fc:
            for succ in block.succs():
                if succ.start_ea <= block.start_ea:
                    schema["structural_features"].add("has_loops")
                    break
            if "has_loops" in schema["structural_features"]:
                break
    except Exception:
        pass
    
    # Convert sets to sorted lists for JSON serialization
    return {k: sorted(v) for k, v in schema.items()}


@tool
@idaread
def classify(
    action: Annotated[Literal["function", "binary", "all_functions", "library_code",
                               "wrappers", "callbacks", "initializers",
                               "error_handlers", "hot_functions", "orphans", "induce_schema", "anchor_coverage"],
                      "Classification action"],
    addr: Annotated[Optional[str], "Function address for single-function actions"] = None,
    limit: Annotated[int, "Max results"] = 50,
    category: Annotated[Optional[str], "Filter by category"] = None,
) -> dict:
    """
    Classify functions and binary by purpose using API call patterns and structural analysis.

    ACTIONS:

    function - Classify a single function's purpose based on APIs, strings, and patterns.
        Params: addr (required)
        Returns: {category, apis_matched, all_callees, confidence}
        Categories: crypto, network, file_io, memory, string_ops, math, ui, registry,
                    process, authentication, logging, error_handling, serialization,
                    compression, unknown

    binary - Classify the binary's overall purpose/type.
        Returns: {type, categories, import_profile, function_count}

    all_functions - Classify all functions and return category distribution.
        Params: limit, category (optional filter)
        Returns: {distribution, functions}

    library_code - Identify library/compiler-generated code vs user code.
        Params: limit
        Returns: {library, user, summary}

    wrappers - Find wrapper functions (thin functions that just call another function).
        Params: limit
        Returns: {wrappers}

    callbacks - Identify callback functions (passed as function pointers in code).
        Params: limit
        Returns: {callbacks}

    initializers - Find initialization/setup functions.
        Params: limit
        Returns: {initializers}

    error_handlers - Find error handling/cleanup functions.
        Params: limit
        Returns: {error_handlers}

    hot_functions - Find most-called functions (central to program logic).
        Params: limit
        Returns: {hot_functions}

    orphans - Find orphan functions (no callers).
        Params: limit
        Returns: {orphans}

    induce_schema - Induce structured attribute-value schema for a function (VOERA SchemaBoot).
        Params: addr (required)
        Returns: {schema: {behavior_tags, dangerous_apis, string_refs, vuln_class, compiler_hints, structural_features}}
        Use for structured semantic retrieval and precise filtering.

    anchor_coverage - Coverage report for BehaviorClassifier anchors over current IDB.
        Params: limit (max funcs sampled)
        Returns: {anchors: [{label, hit_count, top_example}]}
    """
    try:
        # ----------------------------------------------------------------
        # ACTION: function
        # ----------------------------------------------------------------
        if action == "function":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'function' action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            cat, matched, callees = _classify_func(ea)
            insn_count = _count_func_instructions(ea)
            xref_count = _get_xrefs_to_count(ea)
            fn = ida_funcs.get_func(ea)
            str_refs = []
            if fn:
                for head in idautils.Heads(fn.start_ea, fn.end_ea):
                    for dref in idautils.DataRefsFrom(head):
                        stype = idc.get_str_type(dref)
                        if stype is not None and stype >= 0:
                            s = idc.get_strlit_contents(dref, -1, stype)
                            if s:
                                s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                                if s not in str_refs:
                                    str_refs.append(s)
            total_matched = sum(len(v) for v in matched.values())
            confidence = "high" if total_matched >= 3 else ("medium" if total_matched >= 1 else "low")
            schema = _induce_function_schema(ea)
            schema_tags = list(schema.get("behavior_tags", [])) if isinstance(schema, dict) else []
            if cat == "unknown" and schema_tags:
                cat = schema_tags[0]
                confidence = "medium"

            # Augment with BehaviorClassifier (embedding-based, zero-shot)
            behavior_tags = []
            try:
                pseudo = None
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        pseudo = str(cfunc)
                except Exception:
                    pass
                if pseudo:
                    try:
                        from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                    except ImportError:
                        from host.intelligence import BgeCodeEmbedder, BehaviorClassifier  # type: ignore
                    embedder = BgeCodeEmbedder()
                    classifier = BehaviorClassifier.instance(embedder)
                    behavior_tags = classifier.classify(pseudo, threshold=0.0, top_k=6)
                    if behavior_tags:
                        scores = sorted(float(h.get("confidence") or h.get("score") or 0.0) for h in behavior_tags)
                        q50 = scores[len(scores) // 2]
                        q75 = scores[min(len(scores) - 1, int(round((len(scores) - 1) * 0.75)))]
                        gate = q50 + max(0.0, q75 - q50)
                        strong = [h for h in behavior_tags if float(h.get("confidence") or h.get("score") or 0.0) >= gate]
                        if strong:
                            behavior_tags = strong
                            cat = behavior_tags[0]["behavior"]
                            confidence = "high"
            except Exception:
                pass

            return {
                "ok": True,
                "address": hex(ea),
                "name": fname,
                "category": cat,
                "confidence": confidence,
                "apis_matched": matched,
                "all_callees": callees,
                "string_refs": str_refs[:20],
                "instruction_count": insn_count,
                "incoming_xrefs": xref_count,
                "behavior_tags": behavior_tags,
                "schema": schema,
            }

        # ----------------------------------------------------------------
        # ACTION: binary
        # ----------------------------------------------------------------
        elif action == "binary":
            category_counts = {}
            total_funcs = 0
            import_names = []
            for ea in idautils.Functions():
                total_funcs += 1
                cat, _, _ = _classify_func(ea)
                category_counts[cat] = category_counts.get(cat, 0) + 1
            # Collect imports
            nimps = ida_nalt.get_import_module_qty()
            import_modules = []
            for i in range(nimps):
                mod = ida_nalt.get_import_module_name(i)
                if mod:
                    import_modules.append(mod)
            # Heuristic binary type classification
            binary_type = "unknown"
            c = category_counts
            if c.get("network", 0) > 5 and c.get("crypto", 0) > 2:
                binary_type = "malware_or_security_tool"
            elif c.get("network", 0) > 10:
                binary_type = "server_or_network_app"
            elif c.get("ui", 0) > 10:
                binary_type = "gui_application"
            elif c.get("file_io", 0) > 10 and c.get("string_ops", 0) > 5:
                binary_type = "utility"
            elif c.get("crypto", 0) > 5:
                binary_type = "crypto_tool"
            elif c.get("math", 0) > 5:
                binary_type = "scientific_or_game"
            elif c.get("registry", 0) > 5:
                binary_type = "system_tool"
            elif c.get("process", 0) > 5:
                binary_type = "system_tool"
            elif total_funcs > 0 and c.get("unknown", 0) == total_funcs:
                binary_type = "library_or_driver"
            # Check for driver indicators
            for mod in import_modules:
                if mod.lower() in ("ntoskrnl.exe", "hal.dll", "ndis.sys", "wdm"):
                    binary_type = "driver"
                    break
            return {
                "ok": True,
                "binary_type": binary_type,
                "function_count": total_funcs,
                "category_distribution": category_counts,
                "import_modules": import_modules[:30],
            }

        # ----------------------------------------------------------------
        # ACTION: all_functions
        # ----------------------------------------------------------------
        elif action == "all_functions":
            distribution = {}
            functions = []

            # Try to get BehaviorClassifier for unnamed functions
            _classifier = None
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                _classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
            except Exception:
                pass

            for ea in idautils.Functions():
                cat, matched, _ = _classify_func(ea)
                fname = idc.get_func_name(ea)
                # For unnamed functions, try BehaviorClassifier (more accurate than heuristic)
                if _classifier and (fname.startswith("sub_") or fname.startswith("nullsub_")):
                    try:
                        cfunc = ida_hexrays.decompile(ea)
                        if cfunc:
                            hits = _classifier.classify(str(cfunc)[:2000], threshold=0.0, top_k=3, block=False)
                            if hits:
                                hs = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in hits)
                                q50 = hs[len(hs) // 2]
                                q75 = hs[min(len(hs) - 1, int(round((len(hs) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                filtered = [h for h in hits if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate]
                                if filtered:
                                    cat = filtered[0]["behavior"]
                    except Exception:
                        pass
                distribution[cat] = distribution.get(cat, 0) + 1
                if category and cat != category:
                    continue
                if len(functions) < limit:
                    functions.append(f"{hex(ea)}  {fname}  {cat}")
            return {
                "ok": True,
                "distribution": distribution,
                "functions": functions,
                "total": sum(distribution.values()),
            }

        # ----------------------------------------------------------------
        # ACTION: library_code
        # ----------------------------------------------------------------
        elif action == "library_code":
            library_funcs = []
            user_funcs = []
            for ea in idautils.Functions():
                fn = ida_funcs.get_func(ea)
                if not fn:
                    continue
                fname = idc.get_func_name(ea)
                flags = fn.flags
                is_lib = bool(flags & ida_funcs.FUNC_LIB)
                is_thunk = bool(flags & ida_funcs.FUNC_THUNK)
                # Also check name patterns for compiler-generated code
                is_compiler = fname.startswith("__") or \
                              fname.startswith("j_") or fname.startswith("nullsub_")
                if is_lib or is_thunk or is_compiler:
                    if len(library_funcs) < limit:
                        tag = "lib" if is_lib else ("thunk" if is_thunk else "compiler")
                        library_funcs.append(f"{hex(ea)}  {fname}  [{tag}]")
                else:
                    if len(user_funcs) < limit:
                        user_funcs.append(f"{hex(ea)}  {fname}")
            lib_count = 0
            for ea in idautils.Functions():
                fn = ida_funcs.get_func(ea)
                if not fn:
                    continue
                fname_chk = idc.get_func_name(ea)
                if (fn.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK)) or \
                   fname_chk.startswith("__") or fname_chk.startswith("j_") or \
                   fname_chk.startswith("nullsub_"):
                    lib_count += 1
            total = sum(1 for _ in idautils.Functions())
            return {
                "ok": True,
                "library_count": lib_count,
                "user_count": total - lib_count,
                "total": total,
                "library": library_funcs,
                "user": user_funcs,
            }

        # ----------------------------------------------------------------
        # ACTION: wrappers
        # ----------------------------------------------------------------
        elif action == "wrappers":
            wrappers = []
            for ea in idautils.Functions():
                insn_count = _count_func_instructions(ea)
                if insn_count > 5:
                    continue
                callees = _get_func_callees(ea)
                if len(callees) == 1:
                    fname = idc.get_func_name(ea)
                    target = callees[0]
                    wrappers.append(f"{hex(ea)}  {fname}  -> {target}  ({insn_count} insns)")
                    if len(wrappers) >= limit:
                        break
            return {"ok": True, "wrappers": wrappers, "count": len(wrappers)}

        # ----------------------------------------------------------------
        # ACTION: callbacks
        # ----------------------------------------------------------------
        elif action == "callbacks":
            callbacks = []
            seen = set()
            for ea in idautils.Functions():
                fn = ida_funcs.get_func(ea)
                if not fn:
                    continue
                # Check for data xrefs TO this function from code
                for xref in idautils.XrefsTo(ea, 0):
                    # Data reference from code = function address used as operand
                    if xref.type in (idaapi.dr_O, idaapi.dr_I):
                        # Verify the source is inside a function (code context)
                        src_fn = ida_funcs.get_func(xref.frm)
                        if src_fn and ea not in seen:
                            seen.add(ea)
                            fname = idc.get_func_name(ea)
                            src_name = idc.get_func_name(src_fn.start_ea)
                            callbacks.append(f"{hex(ea)}  {fname}  (ref from {src_name} at {hex(xref.frm)})")
                            break
                if len(callbacks) >= limit:
                    break
            return {"ok": True, "callbacks": callbacks, "count": len(callbacks)}

        # ----------------------------------------------------------------
        # ACTION: initializers
        # ----------------------------------------------------------------
        elif action == "initializers":
            init_patterns = [
                "init", "setup", "start", "create", "register", "install",
                "configure", "bootstrap", "prepare", "open", "begin",
                "ctor", "constructor", "dllmain", "winmain", "main",
                "_init", "__init", ".init",
            ]
            initializers = []
            for ea in idautils.Functions():
                fname = idc.get_func_name(ea).lower()
                matched = False
                for pat in init_patterns:
                    if pat in fname:
                        matched = True
                        break
                if not matched:
                    # Check if function is called from known init contexts
                    # e.g., in .init_array / .ctors segments
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        for xref in idautils.XrefsTo(ea, 0):
                            seg = ida_segment.getseg(xref.frm)
                            if seg:
                                seg_name = ida_segment.get_segm_name(seg).lower()
                                if any(s in seg_name for s in (".init", ".ctors", ".CRT")):
                                    matched = True
                                    break
                if matched:
                    fname_orig = idc.get_func_name(ea)
                    initializers.append(f"{hex(ea)}  {fname_orig}")
                    if len(initializers) >= limit:
                        break
            return {"ok": True, "initializers": initializers, "count": len(initializers)}

        # ----------------------------------------------------------------
        # ACTION: error_handlers
        # ----------------------------------------------------------------
        elif action == "error_handlers":
            error_apis = set()
            for api in _CATEGORY_APIS.get("error_handling", []):
                error_apis.add(api.lower())
            error_name_patterns = [
                "error", "err_", "fail", "exception", "cleanup",
                "handler", "abort", "panic", "fatal", "throw",
                "catch", "finally", "unwind", "terminate",
            ]
            results = []
            for ea in idautils.Functions():
                fname = idc.get_func_name(ea).lower()
                # Check name patterns
                name_match = any(pat in fname for pat in error_name_patterns)
                # Check if function calls error-related APIs
                api_match = False
                callees = _get_func_callees(ea)
                for callee in callees:
                    base = callee
                    for suffix in ("A", "W", "@plt", "@PLT"):
                        if base.endswith(suffix):
                            base = base[:-len(suffix)]
                            break
                    if base.lower() in error_apis:
                        api_match = True
                        break
                if name_match or api_match:
                    fname_orig = idc.get_func_name(ea)
                    reason = "name" if name_match else "api"
                    results.append(f"{hex(ea)}  {fname_orig}  [{reason}]")
                    if len(results) >= limit:
                        break
            return {"ok": True, "error_handlers": results, "count": len(results)}

        # ----------------------------------------------------------------
        # ACTION: hot_functions
        # ----------------------------------------------------------------
        elif action == "hot_functions":
            func_xrefs = []
            for ea in idautils.Functions():
                count = _get_xrefs_to_count(ea)
                fname = idc.get_func_name(ea)
                func_xrefs.append((count, ea, fname))
            func_xrefs.sort(key=lambda x: x[0], reverse=True)
            results = []
            for count, ea, fname in func_xrefs[:limit]:
                results.append(f"{hex(ea)}  {fname}  xrefs={count}")
            return {"ok": True, "hot_functions": results, "count": len(results)}

        # ----------------------------------------------------------------
        # ACTION: orphans
        # ----------------------------------------------------------------
        elif action == "orphans":
            orphans = []
            for ea in idautils.Functions():
                fn = ida_funcs.get_func(ea)
                if not fn:
                    continue
                # Skip library/thunk functions
                if fn.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
                    continue
                count = _get_xrefs_to_count(ea)
                if count == 0:
                    fname = idc.get_func_name(ea)
                    insn_count = _count_func_instructions(ea)
                    orphans.append(f"{hex(ea)}  {fname}  ({insn_count} insns)")
                    if len(orphans) >= limit:
                        break
            return {"ok": True, "orphans": orphans, "count": len(orphans)}

        # ----------------------------------------------------------------
        # ACTION: induce_schema (VOERA SchemaBoot for RE)
        # ----------------------------------------------------------------
        elif action == "induce_schema":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for induce_schema")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            schema = _induce_function_schema(ea)
            return {
                "ok": True,
                "addr": hex(ea),
                "name": fname,
                "schema": schema,
                "note": "Structured schema induced from API calls, strings, and structural analysis. Use with search(action='structured', constraints=...) for precise filtering.",
            }

        elif action == "anchor_coverage":
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
            except ImportError:
                from host.intelligence import BgeCodeEmbedder, BehaviorClassifier  # type: ignore
            bc = BehaviorClassifier.instance(BgeCodeEmbedder())
            max_funcs = max(1, int(limit))
            rep = bc.anchor_coverage_report(min_similarity=0.4, max_funcs=max_funcs)
            rep["ok"] = True
            return rep

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
