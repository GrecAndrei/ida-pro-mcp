import contextlib

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .code_helpers import *
except ImportError:
    from code_helpers import *  # type: ignore[import-not-found]

@tool
@idaread
def code(
    action: Annotated[Literal[
        "decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field",
        "callees", "callers", "blocks", "callgraph", "export",
        "find_paths", "strings_in_func", "diff_functions", "semantic_decompile",
        "decomp_dataflow", "decompile_chain", "smart_decompile", "explain",
        "trace_argument_origin", "decompile_all"
    ], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es) - hex string or name"] = None,
    addr: Annotated[Optional[str], "Single address (alias for addrs)"] = None,
    max_items: Annotated[int, "Max items to return"] = 1000,
    max_depth: Annotated[int, "Max depth for callgraph/find_paths"] = 5,
    format: Annotated[Literal["json", "c_header", "prototypes"], "Export format"] = "json",
    disasm_style: Annotated[Literal["csmini", "classic", "annotated"], "Disassembly line style"] = "csmini",
    include_bytes: Annotated[bool, "Include instruction bytes in disassembly output"] = False,
    end: Annotated[Optional[str], "Optional end address for disasm range"] = None,
    limit: Annotated[Optional[int], "Alias for max_items (especially useful with disasm)"] = None,
    window: Annotated[Optional[int], "Disasm: number of instructions BEFORE and AFTER the start address (centered view). Overrides function-bounded default."] = None,
    field_name: Annotated[Optional[str], "Struct field name (for xrefs_to_field)"] = None,
    target: Annotated[Optional[str], "Target address (for find_paths)"] = None,
    comment: Annotated[Optional[str], "Comment text (for annotate action)"] = None,
    **kwargs
) -> list[dict] | dict:
    """
    Perform code analysis, decompilation, and graph traversal.

    ACTIONS:

    decompile - Decompile function to Pseudo-C (requires Hex-Rays)
        Params: addrs (REQUIRED)
        Returns: [{addr, code, prototype}] or {addr, error}
        Example: code(action="decompile", addrs="0x401000")
        Example: code(action="decompile", addrs=["main", "0x402000"])

    disasm - Get assembly listing (LLM-compact text, one line per instruction)
        Params: addrs (REQUIRED), optional end, window (±N instructions around addrs),
                disasm_style (csmini|classic|annotated), include_bytes, limit
        Returns: [{addr, name, disasm: "*addr:instr\\n*addr:instr\\n...", count, style, range}]
        Example: code(action="disasm", addrs="0x401000")
        Example: code(action="disasm", addrs="0x125b0", end="0x12640", limit=160, disasm_style="csmini")
        Example: code(action="disasm", addrs="0x4010a0", window=20)   # ±20 instructions around 0x4010a0

    xrefs_to - Get cross-references TO an address (compact text, includes function names)
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: "addr  type  func_name\\n...", count}]
        Example: code(action="xrefs_to", addrs="0x401000")

    xrefs_from - Get cross-references FROM an address (compact text, includes names)
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: "addr  type  name\\n...", count}]
        Example: code(action="xrefs_from", addrs="0x401000")

    callees - List functions called BY this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callees: "addr  name\\n...", count}]
        Example: code(action="callees", addrs="main")

    callers - List functions that CALL this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callers: "addr  name\\n...", count}]
        Example: code(action="callers", addrs="printf")

    blocks - Get basic blocks (compact text with successors/predecessors)
        Params: addrs (REQUIRED)
        Returns: [{addr, blocks: "start-end  succs=[...]  preds=[...]\\n...", count}]
        Example: code(action="blocks", addrs="0x401000")

    analyze - Comprehensive analysis (decompile + callees + callers + strings)
        Params: addrs (REQUIRED)
        Returns: [{addr, pseudocode, prototype, callees, callers, strings}]
        Example: code(action="analyze", addrs="main")
        Best for: Getting full context about a function in one call

    callgraph - Generate call graph from starting function (compact text)
        Params: addrs (REQUIRED), max_depth (default 5)
        Returns: [{addr, nodes: "addr  depth=N  name\\n...", edges: "addr -> addr\\n..."}]
        Example: code(action="callgraph", addrs="main", max_depth=3)

    find_paths - Find call-graph paths from one function to another (BFS over call graph)
        Note: this traverses the call graph (function-to-function), not intra-function CFG.
        For intra-function basic block paths, use cfg_analysis(action="paths").
        Params: addrs (REQUIRED - start function), target (REQUIRED - target function)
        Returns: {from, to, paths: [[addr1, addr2, ...], ...]}
        Example: code(action="find_paths", addrs="0x401000", target="0x402000")

    strings_in_func - List strings referenced in function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, strings: "addr  string_value\\n...", count}]
        Example: code(action="strings_in_func", addrs="main")

    diff_functions - Compare two functions' decompilation side by side
        Params: addrs (REQUIRED - exactly 2 addresses)
        Returns: {func_a, func_b, diff: "unified diff text", similarity: float}
        Example: code(action="diff_functions", addrs=["0x401000", "0x402000"])

    semantic_decompile - High-complexity semantic decompilation profile
        Params: addrs (REQUIRED)
        Returns: [{addr, pseudocode, semantic_summary, cfg_semantics, decomp_dataflow}]
        Includes complexity metrics, control-flow semantics, and variable dependency hubs.

    decomp_dataflow - Build decompiler-derived variable dependency graph
        Params: addrs (REQUIRED)
        Returns: [{addr, function, dataflow: {nodes, edges, top_hubs, ...}}]

    decompile_chain - Decompile function with caller/callee context
        Params: addrs (REQUIRED), max_depth (default 2 for callers/callees count)
        Returns: [{addr, function, pseudocode, callers_context: [{addr, name, pseudocode}], callees_context: [{addr, name, pseudocode}]}]
        Best for: Understanding a function within its call graph neighborhood.

    trace_argument_origin - Trace a function argument backward through callers.
        Params: addrs (REQUIRED - target function), arg_index (REQUIRED - 0-based argument index),
                max_depth (default 4), max_callers_per_level (default 10)
        Returns: {target, argument_name, prototype, trace_tree: [...]}
        Each trace entry: {depth, caller_addr, caller_name, call_site, call_line, arg_source, arg_type}
        Example: code(action="trace_argument_origin", addrs="0x401000", arg_index=2)
        Best for: Finding where a specific value (e.g., a key, buffer size, or flag) originates.
    """
    try:
        # decompile_all doesn't need addrs — it uses a name filter
        if action == "decompile_all":
            query = kwargs.get("query")
            matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            all_funcs = []
            for func_ea in idautils.Functions():
                name = ida_funcs.get_func_name(func_ea) or ""
                if matcher and not matcher(name):
                    continue
                all_funcs.append(func_ea)
            if not all_funcs:
                return {"ok": True, "results": [], "count": 0,
                        "note": f"No functions matching '{query}'."}
            all_results = []
            for func_ea in all_funcs:
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func_ea)
                    if cfunc:
                        all_results.append({
                            "ok": True,
                            "addr": hex_ea(func_ea),
                            "name": ida_funcs.get_func_name(func_ea) or "",
                            "code": str(cfunc),
                            "prototype": get_prototype(idaapi.get_func(func_ea)),
                        })
                    else:
                        all_results.append({
                            "addr": hex_ea(func_ea),
                            "name": ida_funcs.get_func_name(func_ea) or "",
                            "error": dec_err.get("message", "Decompilation failed") if isinstance(dec_err, dict) else "Decompilation failed",
                        })
                except Exception as e:
                    all_results.append({
                        "addr": hex_ea(func_ea),
                        "name": ida_funcs.get_func_name(func_ea) or "",
                        "error": str(e),
                    })
            return {"ok": True, "results": all_results, "count": len(all_results),
                    "query": query or "", "total_functions": len(all_funcs)}

        # Support both addr (singular) and addrs (plural) for compatibility
        if not addrs and addr:
            addrs = addr
        if not addrs:
            return make_error(MCPError.INVALID_ARGS, "addrs or addr parameter required")
        if action == "disasm":
            disasm_max = limit if isinstance(limit, int) else max_items
            if not isinstance(disasm_max, int):
                try:
                    disasm_max = int(disasm_max)
                except (TypeError, ValueError):
                    disasm_max = DISASM_MAX_LINES
            # Clamp disasm rows even when caller uses max_items directly.
            max_items = min(max(disasm_max, 1), DISASM_MAX_LINES)
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            ea, error = validate_addr(addr)
            if error:
                results.append({"addr": addr, **error})
                continue

            if action == "decompile":
                func = idaapi.get_func(ea)
                if not func:
                    # Find nearest function for better error
                    prev_func = _get_prev_func(ea)
                    next_func = _get_next_func(ea)
                    suggestion = ""
                    if prev_func:
                        suggestion = f" Try {hex_ea(prev_func.start_ea)} ({ida_funcs.get_func_name(prev_func.start_ea) or 'unnamed'})"
                    elif next_func:
                        suggestion = f" Try {hex_ea(next_func.start_ea)} ({ida_funcs.get_func_name(next_func.start_ea) or 'unnamed'})"

                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}.{suggestion}", details={"addr": addr}))
                    continue

                # Thunk auto-resolution: if this is a thunk, follow to the real implementation
                thunk_target = None
                flags = func.flags if hasattr(func, 'flags') else 0
                if flags & ida_funcs.FUNC_THUNK:
                    try:
                        target_ea = idaapi.calc_thunk_func_target(func)
                        if target_ea and target_ea != idaapi.BADADDR:
                            thunk_target = target_ea
                    except Exception:
                        pass

                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    if cfunc:
                        pseudo = str(cfunc)
                        # If thunk, append the real implementation info
                        if thunk_target:
                            target_name = idc.get_name(thunk_target) or ""
                            try:
                                import ida_nalt
                                demangled = ida_nalt.demangle_name(target_name, ida_nalt.get_short_name_synonym()) or target_name
                                if "(" in demangled:
                                    demangled = demangled[:demangled.index("(")].strip()
                            except Exception:
                                demangled = target_name
                            pseudo = f"// THUNK -> {hex(thunk_target)} ({demangled})\n{pseudo}"
                        result_entry = {
                            "ok": True,
                            "addr": hex_ea(func.start_ea),
                            "code": pseudo,
                            "prototype": get_prototype(func),
                        }
                        # Inline enrichment shared with smart_decompile so the two
                        # decompilation entrypoints do not drift apart.
                        try:
                            enrichment = _build_decompile_enrichment(
                                func.start_ea,
                                cfunc,
                                pseudo,
                                detailed_dangerous=False,
                                include_switch_cases=False,
                                api_limit=12,
                            )
                            for key, value in enrichment.items():
                                if value:
                                    result_entry[key] = value
                        except Exception:
                            pass
                        results.append(result_entry)
                    else:
                        # Aggregate errors per-address carry `code`, `category`,
                        # `message`, and `hint` so per-batch decomp failures
                        # match the host error-envelope contract.
                        code_val = (
                            dec_err.get("code")
                            if isinstance(dec_err, dict)
                            else MCPError.DECOMPILER_FAILED
                        )
                        entry: dict = {
                            "addr": addr,
                            "code": code_val,
                            "category": (
                                dec_err.get("category")
                                if isinstance(dec_err, dict)
                                else "runtime"
                            ),
                            "message": (
                                dec_err.get("message", "Decompilation failed")
                                if isinstance(dec_err, dict)
                                else "Decompilation failed"
                            ),
                        }
                        if isinstance(dec_err, dict):
                            if dec_err.get("hint"):
                                entry["hint"] = dec_err["hint"]
                            if dec_err.get("details"):
                                entry["details"] = dec_err["details"]
                        else:
                            entry["hint"] = ERROR_HINTS.get(MCPError.DECOMPILER_FAILED)
                        results.append(entry)
                except Exception as e:
                    entry = {
                        "addr": addr,
                        "code": MCPError.DECOMPILER_FAILED,
                        "category": "runtime",
                        "message": f"Decompilation exception: {e}",
                        "hint": ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                    }
                    results.append(entry)

            elif action == "decompile_chain":
                func = idaapi.get_func(ea)
                if not func:
                    prev_func = _get_prev_func(ea)
                    next_func = _get_next_func(ea)
                    suggestion = ""
                    if prev_func:
                        suggestion = f" Try {hex_ea(prev_func.start_ea)} ({ida_funcs.get_func_name(prev_func.start_ea) or 'unnamed'})"
                    elif next_func:
                        suggestion = f" Try {hex_ea(next_func.start_ea)} ({ida_funcs.get_func_name(next_func.start_ea) or 'unnamed'})"
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}.{suggestion}", details={"addr": addr}))
                    continue
                chain_depth = max(1, min(max_depth, 3))  # hard cap at 3
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    main_pseudo = str(cfunc) if cfunc else ""
                    main_proto = get_prototype(func)
                    # Collect callers (compact: name + first 5 lines of pseudocode)
                    callers_ctx = []
                    caller_addrs = set()
                    for i, xref in enumerate(idautils.CodeRefsTo(func.start_ea, 0)):
                        if i >= 20:  # scan at most 20 xrefs
                            break
                        caller_fn = ida_funcs.get_func(xref)
                        if caller_fn and caller_fn.start_ea not in caller_addrs:
                            caller_addrs.add(caller_fn.start_ea)
                            ccfunc, _ = _decompile_with_diagnostics(caller_fn.start_ea)
                            if ccfunc:
                                pseudo_lines = str(ccfunc).splitlines()
                                callers_ctx.append({
                                    "addr": hex_ea(caller_fn.start_ea),
                                    "name": ida_funcs.get_func_name(caller_fn.start_ea),
                                    # First 8 lines only — enough for call context
                                    "pseudocode_head": "\n".join(pseudo_lines[:8]),
                                    "total_lines": len(pseudo_lines),
                                })
                            if len(callers_ctx) >= chain_depth:
                                break
                    # Collect callees (compact)
                    callees_ctx = []
                    callee_addrs = set()
                    for item in idautils.FuncItems(func.start_ea):
                        for ref in idautils.CodeRefsFrom(item, 0):
                            callee_fn = ida_funcs.get_func(ref)
                            if callee_fn and callee_fn.start_ea not in callee_addrs:
                                callee_addrs.add(callee_fn.start_ea)
                                ccfunc, _ = _decompile_with_diagnostics(callee_fn.start_ea)
                                if ccfunc:
                                    pseudo_lines = str(ccfunc).splitlines()
                                    callees_ctx.append({
                                        "addr": hex_ea(callee_fn.start_ea),
                                        "name": ida_funcs.get_func_name(callee_fn.start_ea),
                                        "pseudocode_head": "\n".join(pseudo_lines[:8]),
                                        "total_lines": len(pseudo_lines),
                                    })
                                if len(callees_ctx) >= chain_depth:
                                    break
                        if len(callees_ctx) >= chain_depth:
                            break
                    results.append({
                        "ok": True,
                        "addr": hex_ea(func.start_ea),
                        "name": ida_funcs.get_func_name(func.start_ea),
                        "prototype": main_proto,
                        "pseudocode": main_pseudo,
                        "callers_context": callers_ctx,
                        "callees_context": callees_ctx,
                        "caller_count": len(caller_addrs),
                        "callee_count": len(callee_addrs),
                        "note": "callers/callees show first 8 lines only. Use code(action='decompile') for full pseudocode.",
                    })
                except Exception as e:
                    results.append(
                        make_error(
                            MCPError.IDA_ERROR,
                            f"callgraph collection failed at {addr}: {type(e).__name__}: {e}",
                            details={"addr": addr, "exception_type": type(e).__name__},
                        )
                    )

            elif action == "disasm":
                func = idaapi.get_func(ea)
                end_ea = None
                if end:
                    end_ea, end_err = validate_addr(end)
                    if end_err:
                        results.append({"addr": addr, **end_err})
                        continue
                    if end_ea <= ea:
                        results.append({"addr": addr, **make_error(MCPError.INVALID_ARGS, "end must be greater than start address")})
                        continue
                # window=N: capture ±N instructions around the start address,
                # centered on `ea`. Wins over function-bounded extraction so
                # that a caller with a known hot address gets exactly the slice
                # they asked for without paging through the rest of the body.
                if window is not None:
                    try:
                        radius = int(window)
                    except (TypeError, ValueError):
                        results.append(make_error(
                            MCPError.INVALID_ARGS,
                            "window must be a non-negative integer",
                            details={"got": str(window), "type": type(window).__name__},
                        ))
                        continue
                    if radius < 0:
                        results.append(make_error(
                            MCPError.INVALID_ARGS,
                            "window must be non-negative",
                            details={"got": radius},
                        ))
                        continue
                    lines = _disasm_window(
                        ea,
                        radius=radius,
                        max_items=max_items,
                        style=disasm_style,
                        include_bytes=include_bytes,
                    )
                    fname = ida_funcs.get_func_name(func.start_ea) if func else ""
                    first_addr = lines[0].split(":", 1)[0] if lines else hex_ea(ea)
                    last_addr = lines[-1].split(":", 1)[0] if lines else hex_ea(ea)
                    entry = {
                        "ok": True,
                        "addr": hex_ea(ea),
                        "name": fname,
                        "disasm": "\n".join(lines),
                        "count": len(lines),
                        "style": disasm_style,
                        "range": f"{first_addr}-{last_addr}",
                        "window": radius,
                    }
                    if not func:
                        entry["warning"] = "Address is not within a defined function. Showing raw disassembly."
                    results.append(entry)
                    continue
                if not func:
                    # Disassemble raw bytes even without function
                    lines = _disasm_range(
                        ea,
                        end_ea if end_ea is not None else (ea + 0x1000),
                        max_items=max_items,
                        style=disasm_style,
                        include_bytes=include_bytes,
                    )
                    results.append({
                        "addr": addr,
                        "warning": "Address is not within a defined function. Showing raw disassembly.",
                        "disasm": "\n".join(lines),
                        "count": len(lines),
                        "style": disasm_style,
                        "range": f"{hex_ea(ea)}-{hex_ea(end_ea if end_ea is not None else (ea + 0x1000))}",
                    })
                    continue
                disasm_start = ea if end_ea is not None else func.start_ea
                disasm_end = end_ea if end_ea is not None else func.end_ea
                lines = _disasm_range(
                    disasm_start,
                    disasm_end,
                    max_items=max_items,
                    style=disasm_style,
                    include_bytes=include_bytes,
                )
                fname = ida_funcs.get_func_name(func.start_ea)
                results.append({
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "disasm": "\n".join(lines),
                    "count": len(lines),
                    "style": disasm_style,
                    "range": f"{hex_ea(disasm_start)}-{hex_ea(disasm_end)}",
                })

            elif action == "xrefs_to":
                xref_lines = []
                for x in idautils.XrefsTo(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    fn = idaapi.get_func(x.frm)
                    fn_name = ida_funcs.get_func_name(fn.start_ea) if fn else ""
                    xref_lines.append(f"{hex_ea(x.frm)}  {kind}  {fn_name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})

            elif action == "xrefs_from":
                xref_lines = []
                for x in idautils.XrefsFrom(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    name = ida_name.get_name(x.to) or ""
                    xref_lines.append(f"{hex_ea(x.to)}  {kind}  {name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})

            elif action == "callees":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}", "Use 'funcs.create' to define a function here first"))
                    continue
                callees = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.iscode:
                            target_func = idaapi.get_func(xref.to)
                            if target_func and target_func.start_ea != func.start_ea:
                                callees.add((hex_ea(target_func.start_ea),
                                            ida_funcs.get_func_name(target_func.start_ea)))
                callee_lines = [f"{a}  {n}" for a, n in sorted(callees)]
                results.append({"ok": True, "addr": addr, "callees": "\n".join(callee_lines), "count": len(callee_lines)})

            elif action == "callers":
                func = idaapi.get_func(ea)
                start = func.start_ea if func else ea
                callers = set()
                for xref in idautils.XrefsTo(start, 0):
                    if xref.iscode:
                        caller_func = idaapi.get_func(xref.frm)
                        if caller_func:
                            callers.add((hex_ea(caller_func.start_ea),
                                        ida_funcs.get_func_name(caller_func.start_ea)))
                caller_lines = [f"{a}  {n}" for a, n in sorted(callers)]
                results.append({"ok": True, "addr": addr, "callers": "\n".join(caller_lines), "count": len(caller_lines)})

            elif action == "blocks":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                fc = idaapi.FlowChart(func)
                block_lines = []
                block_count = 0
                for block in fc:
                    succs = ",".join(hex_ea(s.start_ea) for s in block.succs())
                    preds = ",".join(hex_ea(p.start_ea) for p in block.preds())
                    block_lines.append(f"{hex_ea(block.start_ea)}-{hex_ea(block.end_ea)}  succs=[{succs}]  preds=[{preds}]")
                    block_count += 1
                    if block_count >= max_items:
                        break
                results.append({"ok": True, "addr": addr, "blocks": "\n".join(block_lines), "count": block_count})

            elif action == "callgraph":
                # BFS for call graph
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                visited = {func.start_ea: 0}
                queue = [(func.start_ea, 0)]
                edge_set = set()

                while queue and len(edge_set) < max_items:
                    curr_ea, dist = queue.pop(0)
                    if dist >= max_depth:
                        continue

                    for item_ea in idautils.FuncItems(curr_ea):
                        for xref in idautils.XrefsFrom(item_ea, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != curr_ea:
                                    target_ea = tf.start_ea
                                    edge_set.add((curr_ea, target_ea))
                                    if target_ea not in visited:
                                        visited[target_ea] = dist + 1
                                        queue.append((target_ea, dist + 1))

                # Compact: nodes with depth, then edges
                node_lines = [f"{hex_ea(k)}  depth={v}  {ida_funcs.get_func_name(k)}" for k, v in sorted(visited.items(), key=lambda x: x[1])]
                edge_lines = [f"{hex_ea(c)} -> {hex_ea(t)}" for c, t in sorted(edge_set)]
                results.append({"ok": True, "addr": hex_ea(func.start_ea), "nodes": "\n".join(node_lines), "edges": "\n".join(edge_lines)})

            elif action == "export":
                # Export function info
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                name = ida_funcs.get_func_name(func.start_ea)
                proto = get_prototype(func)

                if format == "c_header":
                    results.append({"addr": addr, "header": f"{proto};"})
                elif format == "prototypes":
                    results.append({"addr": addr, "prototype": proto})
                else:
                    results.append({"addr": addr, "name": name, "prototype": proto,
                                   "start": hex_ea(func.start_ea), "end": hex_ea(func.end_ea)})

            elif action == "xrefs_to_field":
                # Find code that accesses a specific struct field by offset
                if not field_name:
                    results.append(make_error(MCPError.INVALID_ARGS, "field_name required"))
                    continue

                struct_name = None
                actual_field = field_name
                if "." in field_name:
                    struct_name, actual_field = field_name.rsplit(".", 1)

                try:
                    til = ida_typeinf.get_idati()
                    qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)

                    # Step 1: Find the field offset in the struct
                    field_offset = None
                    field_type_str = None
                    found_struct = None
                    if struct_name:
                        tinfo = ida_typeinf.tinfo_t()
                        if tinfo.get_named_type(til, struct_name):
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            field_offset = member.offset
                                            field_type_str = str(member.type)
                                            found_struct = struct_name
                                            break
                    else:
                        for ordinal in range(1, qty_func(til) + 1):
                            tinfo = ida_typeinf.tinfo_t()
                            if not tinfo.get_numbered_type(til, ordinal):
                                continue
                            type_name = tinfo.get_type_name()
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            field_offset = member.offset  # bytes in IDA 9
                                            field_type_str = str(member.type)
                                            found_struct = type_name
                                            break
                            if field_offset is not None:
                                break

                    if field_offset is None:
                        results.append({"addr": addr, "field": field_name, "xrefs": [],
                                        "note": f"Field '{actual_field}' not found in any struct"})
                        continue

                    # Step 2: Find code that accesses this offset
                    # Strategy: scan decompiled functions for offset access patterns
                    # and scan disassembly for load/store at [reg+offset]
                    code_refs = []
                    offset_hex = hex(field_offset)
                    offset_dec = str(field_offset)

                    # Scan all functions for references to this offset
                    for func_ea in idautils.Functions():
                        func = idaapi.get_func(func_ea)
                        if not func:
                            continue
                        # Quick disasm scan for [reg+offset] patterns
                        found_in_func = False
                        for item_ea in idautils.FuncItems(func_ea):
                            disasm = idc.generate_disasm_line(item_ea, 0) or ""
                            disasm_clean = ida_lines.tag_remove(disasm)
                            # Match [reg+offset] or [reg-offset] patterns
                            if (f"+{offset_hex}" in disasm_clean.lower() or
                                f"+{offset_dec}]" in disasm_clean or
                                f"+0x{field_offset:x}]" in disasm_clean.lower()):
                                fn_name = ida_funcs.get_func_name(func_ea)
                                code_refs.append({
                                    "ea": hex_ea(item_ea),
                                    "func": hex_ea(func_ea),
                                    "func_name": fn_name,
                                    "disasm": disasm_clean[:80],
                                })
                                found_in_func = True
                                if len(code_refs) >= max_items:
                                    break
                        if found_in_func and len(code_refs) >= max_items:
                            break

                    results.append({
                        "ok": True,
                        "field": field_name,
                        "struct": found_struct,
                        "offset": field_offset,
                        "offset_hex": hex(field_offset),
                        "field_type": field_type_str,
                        "xrefs": code_refs,
                        "count": len(code_refs),
                        "note": f"Found {len(code_refs)} code references to {found_struct}.{actual_field} (offset {hex(field_offset)})",
                    })
                except Exception as e:
                    results.append(make_error(MCPError.IDA_ERROR, f"Error searching for field: {str(e)}", details={"addr": addr}))
                continue

            elif action == "find_paths":
                # Find path(s) from addr to target
                if not target:
                    results.append(make_error(MCPError.INVALID_ARGS, "target required"))
                    continue

                target_ea, error = validate_addr(target)
                if error:
                    results.append({"addr": addr, **error})
                    continue

                # Simple BFS
                queue = [(ea, [hex(ea)])]
                visited = {ea}
                paths = []

                while queue and len(paths) < max_items:
                    curr, path = queue.pop(0)
                    if curr == target_ea:
                        paths.append(path)
                        continue

                    if len(path) >= max_depth:
                        continue

                    # Get succs
                    succs = []
                    func = idaapi.get_func(curr) # if callgraph
                    if func:
                        # Intra-procedural flow? Or callgraph? Let's do callgraph for now as it's more useful typically
                        for item in idautils.FuncItems(func.start_ea):
                            for xref in idautils.XrefsFrom(item, 0):
                                if xref.iscode:
                                    tf = idaapi.get_func(xref.to)
                                    if tf and tf.start_ea != func.start_ea:
                                        succs.append(tf.start_ea)

                    for s in succs:
                        if s not in visited:
                            visited.add(s)
                            queue.append((s, path + [hex(s)]))

                results.append({"from": addr, "to": target, "paths": paths})

            elif action == "strings_in_func":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                str_lines = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                if isinstance(s, bytes):
                                    s = s.decode("utf-8", errors="replace")
                                str_lines.append(f"{hex_ea(xref.to)}  {s}")
                results.append({"ok": True, "addr": addr, "strings": "\n".join(str_lines), "count": len(str_lines)})

            elif action == "diff_functions":
                # Compare two functions' decompilation
                addr_list = normalize_list_input(addrs)
                if len(addr_list) != 2:
                    return make_error(MCPError.INVALID_ARGS, "diff_functions requires exactly 2 addresses",
                                    hint='Use addrs=["0x401000", "0x402000"]')
                ea_a, err = validate_addr(addr_list[0], require_func=True)
                if err: return err
                ea_b, err = validate_addr(addr_list[1], require_func=True)
                if err: return err

                import difflib
                cfunc_a, err_a = _decompile_with_diagnostics(ea_a)
                cfunc_b, err_b = _decompile_with_diagnostics(ea_b)
                if err_a or err_b:
                    return make_error(
                        MCPError.DECOMPILER_FAILED,
                        "Decompilation failed for one or both functions",
                        hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                        details={
                            "func_a": {"addr": hex(ea_a), "error": err_a} if err_a else {"addr": hex(ea_a)},
                            "func_b": {"addr": hex(ea_b), "error": err_b} if err_b else {"addr": hex(ea_b)},
                        },
                    )

                code_a = str(cfunc_a) if cfunc_a else ""
                code_b = str(cfunc_b) if cfunc_b else ""
                name_a = idc.get_func_name(ea_a) or hex(ea_a)
                name_b = idc.get_func_name(ea_b) or hex(ea_b)

                diff = difflib.unified_diff(
                    code_a.splitlines(), code_b.splitlines(),
                    fromfile=name_a, tofile=name_b, lineterm=""
                )
                diff_text = "\n".join(diff)

                # Compute similarity ratio
                ratio = difflib.SequenceMatcher(None, code_a, code_b).ratio()

                return {
                    "ok": True,
                    "func_a": {"addr": hex(ea_a), "name": name_a, "lines": len(code_a.splitlines())},
                    "func_b": {"addr": hex(ea_b), "name": name_b, "lines": len(code_b.splitlines())},
                    "diff": diff_text if diff_text else "(identical)",
                    "similarity": round(ratio, 4),
                }

            elif action == "semantic_decompile":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    err_entry: dict = {
                        "addr": addr,
                        "code": (
                            dec_err.get("code")
                            if isinstance(dec_err, dict)
                            else MCPError.DECOMPILER_FAILED
                        ),
                        "category": (
                            dec_err.get("category")
                            if isinstance(dec_err, dict)
                            else "runtime"
                        ),
                        "message": (
                            dec_err.get("message", "Decompilation failed")
                            if isinstance(dec_err, dict)
                            else "Decompilation failed"
                        ),
                    }
                    if isinstance(dec_err, dict):
                        if dec_err.get("hint"):
                            err_entry["hint"] = dec_err["hint"]
                        if dec_err.get("details"):
                            err_entry["details"] = dec_err["details"]
                    else:
                        err_entry["hint"] = ERROR_HINTS.get(MCPError.DECOMPILER_FAILED)
                    results.append(err_entry)
                    continue
                pseudo = str(cfunc)
                cfg_semantics = _compute_cfg_semantics(func)
                dataflow = _build_decompiler_dataflow(cfunc, max_items=max(200, min(1600, int(max_items))))
                results.append(
                    {
                        "ok": True,
                        "addr": hex_ea(func.start_ea),
                        "function": ida_funcs.get_func_name(func.start_ea),
                        "prototype": get_prototype(func),
                        "pseudocode": pseudo,
                        "semantic_summary": _semantic_pseudocode_summary(pseudo),
                        "cfg_semantics": cfg_semantics,
                        "decomp_dataflow": dataflow,
                    }
                )

            elif action == "decomp_dataflow":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    err_entry = {
                        "addr": addr,
                        "code": (
                            dec_err.get("code")
                            if isinstance(dec_err, dict)
                            else MCPError.DECOMPILER_FAILED
                        ),
                        "category": (
                            dec_err.get("category")
                            if isinstance(dec_err, dict)
                            else "runtime"
                        ),
                        "message": (
                            dec_err.get("message", "Decompilation failed")
                            if isinstance(dec_err, dict)
                            else "Decompilation failed"
                        ),
                    }
                    if isinstance(dec_err, dict):
                        if dec_err.get("hint"):
                            err_entry["hint"] = dec_err["hint"]
                        if dec_err.get("details"):
                            err_entry["details"] = dec_err["details"]
                    else:
                        err_entry["hint"] = ERROR_HINTS.get(MCPError.DECOMPILER_FAILED)
                    results.append(err_entry)
                    continue
                flow = _build_decompiler_dataflow(cfunc, max_items=max(200, min(1600, int(max_items))))
                edge_lines = [
                    f"{e['from']} -> {e['to']}  {e['kind']}  {e.get('ea') or ''}".rstrip()
                    for e in flow.get("edges", [])[: max(1, min(400, int(max_items)))]
                ]
                results.append(
                    {
                        "ok": True,
                        "addr": hex_ea(func.start_ea),
                        "function": ida_funcs.get_func_name(func.start_ea),
                        "dataflow": flow,
                        "edges": "\n".join(edge_lines),
                        "count": len(flow.get("edges", [])),
                    }
                )

            elif action == "smart_decompile":
                # Best single call for understanding a function.
                # Returns pseudocode + behavior_tags + api_calls + crypto_hints +
                # dangerous_patterns + var_rename_hints + callers + callees +
                # strings + blackboard_context + complexity + suggested_next_actions.
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    results.append({
                        "addr": addr,
                        "error": dec_err.get("message", "Decompilation failed") if isinstance(dec_err, dict) else "Decompilation failed",
                    })
                    continue

                pseudo = str(cfunc)
                fname = ida_funcs.get_func_name(func.start_ea)
                enrichment = _build_decompile_enrichment(
                    func.start_ea,
                    cfunc,
                    pseudo,
                    detailed_dangerous=True,
                    include_switch_cases=True,
                    api_limit=15,
                )
                found_apis = enrichment["api_calls"]
                crypto_hints = enrichment["crypto_hints"]
                dangerous = enrichment["dangerous_patterns"]
                var_hints = enrichment["var_rename_hints"]
                bb_ctx = enrichment["blackboard_context"]
                complexity = enrichment["complexity"]

                callers_compact = _collect_compact_callers(func.start_ea)
                callees_compact = _collect_compact_callees(func.start_ea)
                str_refs = _collect_function_strings(func.start_ea)

                behavior_tags = list(set(
                    crypto_hints
                    + (["network"] if any(a in found_apis for a in ["recv","send","socket","connect"]) else [])
                    + (["file_io"] if any(a in found_apis for a in ["fopen","fread","fwrite","CreateFile","open","read","write"]) else [])
                    + (["memory_alloc"] if "malloc" in found_apis or "VirtualAlloc" in found_apis else [])
                    + (["process_exec"] if any(a in found_apis for a in ["system","exec","CreateProcess"]) else [])
                    + (["dangerous"] if dangerous else [])
                ))

                suggested = []
                if dangerous:
                    # Actual taint trace when network input is present
                    _TAINT_SOURCES = {"recv","recvfrom","read","fread","fgets","gets","getenv","scanf"}
                    active_sources = [a for a in found_apis if a in _TAINT_SOURCES]
                    if active_sources:
                        try:
                            from taint import taint as _taint  # type: ignore
                            taint_result = _taint(
                                action="trace",
                                addr=hex_ea(func.start_ea),
                                source=active_sources[0],
                                max_depth=4,
                            )
                            taint_paths = taint_result.get("paths", [])
                            taint_vulns = taint_result.get("vulns", [])
                            if taint_paths or taint_vulns:
                                suggested.append({
                                    "action": "taint(trace) — COMPLETED",
                                    "addr": hex_ea(func.start_ea),
                                    "source": active_sources[0],
                                    "paths_found": len(taint_paths),
                                    "vulns_found": len(taint_vulns),
                                    "top_path": taint_paths[0] if taint_paths else None,
                                    "top_vuln": taint_vulns[0] if taint_vulns else None,
                                })
                            else:
                                suggested.append({
                                    "action": "taint(trace)",
                                    "addr": hex_ea(func.start_ea),
                                    "reason": f"Network input ({active_sources[0]}) present — no direct sink path found at depth 4, try taint(action='paths') for deeper search",
                                })
                        except Exception:
                            suggested.append({
                                "action": "taint(trace)",
                                "addr": hex_ea(func.start_ea),
                                "reason": f"Network input ({', '.join(active_sources)}) reaches dangerous patterns — trace data flow",
                            })
                    else:
                        suggested.append({"action": "taint(trace)", "reason": "Dangerous patterns — trace data flow"})
                if crypto_hints:
                    suggested.append({"action": "crypto_id(identify)", "addr": hex_ea(func.start_ea),
                                      "reason": f"Crypto signals: {', '.join(crypto_hints[:3])}"})
                if not bb_ctx:
                    suggested.append({"action": "blackboard(write, category=hypothesis)",
                                      "addr": hex_ea(func.start_ea),
                                      "reason": "No blackboard entry — record findings now"})
                if var_hints:
                    suggested.append({"action": "modify(rename) or funcs(suggest_names)",
                                      "reason": f"{len(var_hints)} variables could be renamed: "
                                                 + ", ".join(f"{h['var']}→{h['suggested']}" for h in var_hints[:3])})
                if len(callers_compact) == 0:
                    suggested.append({"action": "blackboard(write, category=dead_end) or check entry points",
                                      "reason": "No callers found — may be an entry point, callback, or dead code"})
                elif len(callers_compact) >= 5:
                    suggested.append({"action": "code(xrefs_to)",
                                      "addr": hex_ea(func.start_ea),
                                      "reason": f"Many callers ({len(callers_compact)}+) — this is a hot function, understand all call sites"})

                results.append({
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "prototype": get_prototype(func),
                    "pseudocode": pseudo,
                    "behavior_tags": behavior_tags,
                    "api_calls": found_apis[:15],
                    "crypto_hints": crypto_hints,
                    "dangerous_patterns": dangerous,
                    "var_rename_hints": var_hints,
                    "strings": str_refs,
                    "callers": callers_compact,
                    "callees": callees_compact,
                    "blackboard_context": bb_ctx,
                    "complexity": complexity,
                    "suggested_next_actions": suggested[:4],
                })

            elif action == "explain":
                # Plain-English explanation of what a function does.
                # Decompiles, extracts signals, and synthesizes a structured summary
                # without requiring the LLM to read raw pseudocode.
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    err_entry = {
                        "addr": addr,
                        "code": MCPError.DECOMPILER_FAILED,
                        "category": "runtime",
                        "message": "Decompilation failed — cannot explain",
                    }
                    if isinstance(dec_err, dict):
                        if dec_err.get("hint"):
                            err_entry["hint"] = dec_err["hint"]
                        if dec_err.get("details"):
                            err_entry["details"] = dec_err["details"]
                    else:
                        err_entry["hint"] = ERROR_HINTS.get(MCPError.DECOMPILER_FAILED)
                    results.append(err_entry)
                    continue

                pseudo = str(cfunc)
                fname = ida_funcs.get_func_name(func.start_ea)
                proto = get_prototype(func)

                # Collect signals
                _KNOWN_APIS = [
                    "malloc","free","memcpy","memset","strcpy","strncpy","sprintf","snprintf",
                    "recv","send","socket","connect","bind","listen","accept","recvfrom","sendto",
                    "fopen","fread","fwrite","fclose","fgets","fputs",
                    "system","exec","execve","popen","fork",
                    "CreateFile","ReadFile","WriteFile","VirtualAlloc","CreateProcess",
                    "RegSetValue","RegOpenKey","CryptEncrypt","CryptDecrypt","BCryptEncrypt",
                    "AES_encrypt","AES_decrypt","SHA256_Update","MD5_Update","HMAC",
                    "memcmp","strcmp","strstr","sscanf","gets","scanf","vsprintf",
                    "mmap","munmap","ioctl","open","read","write","close",
                ]
                found_apis = [a for a in _KNOWN_APIS if a in pseudo]
                pseudo.lower()

                # Callers/callees count
                n_callers = sum(1 for x in idautils.XrefsTo(func.start_ea, 0) if x.iscode)
                callees_set = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xr in idautils.XrefsFrom(item, 0):
                        if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                            callees_set.add(idc.get_name(xr.to) or hex(xr.to))

                # Strings referenced
                str_refs = []
                for item in idautils.FuncItems(func.start_ea):
                    for xr in idautils.XrefsFrom(item, 0):
                        s = idc.get_strlit_contents(xr.to)
                        if s:
                            with contextlib.suppress(Exception):
                                str_refs.append(s.decode("utf-8", errors="replace")[:80])
                str_refs = list(dict.fromkeys(str_refs))[:6]

                # Complexity
                n_blocks = sum(1 for _ in idaapi.FlowChart(func))
                n_lines = len(pseudo.splitlines())

                # Build plain-English summary
                purpose_parts = []
                if any(a in found_apis for a in ["recv","recvfrom","socket","connect","bind","listen","accept"]):
                    purpose_parts.append("handles network I/O")
                if any(a in found_apis for a in ["fopen","fread","fwrite","CreateFile","open","read","write"]):
                    purpose_parts.append("performs file I/O")
                if any(a in found_apis for a in ["malloc","VirtualAlloc","mmap"]):
                    purpose_parts.append("allocates memory")
                if any(a in found_apis for a in ["system","exec","execve","popen","CreateProcess"]):
                    purpose_parts.append("executes external commands")
                if any(a in found_apis for a in ["CryptEncrypt","CryptDecrypt","BCryptEncrypt","AES_encrypt","AES_decrypt"]):
                    purpose_parts.append("performs cryptographic operations")
                if any(a in found_apis for a in ["SHA256_Update","MD5_Update","HMAC"]):
                    purpose_parts.append("computes a hash or MAC")
                if any(a in found_apis for a in ["RegSetValue","RegOpenKey"]):
                    purpose_parts.append("accesses the Windows registry")
                if any(a in found_apis for a in ["memcpy","memset","strcpy","strncpy","sprintf","snprintf"]):
                    purpose_parts.append("manipulates buffers/strings")
                if any(a in found_apis for a in ["gets","scanf","sscanf","vsprintf"]):
                    purpose_parts.append("reads user/external input (potentially unsafe)")
                if not purpose_parts:
                    purpose_parts.append("performs internal computation")

                # Danger signals
                _DANGEROUS = {"gets","strcpy","sprintf","system","exec","execve","popen","memcpy","strncpy"}
                dangerous_calls = [a for a in found_apis if a in _DANGEROUS]

                summary_lines = [
                    f"Function: {fname}",
                    f"Prototype: {proto}" if proto else "",
                    f"Purpose: This function {', '.join(purpose_parts)}.",
                ]
                if str_refs:
                    summary_lines.append(f"Key strings: {', '.join(repr(s) for s in str_refs[:4])}")
                if found_apis:
                    summary_lines.append(f"API calls: {', '.join(found_apis[:10])}")
                if dangerous_calls:
                    summary_lines.append(f"⚠ Dangerous calls: {', '.join(dangerous_calls)} — review for buffer overflows / injection")
                summary_lines.append(f"Complexity: {n_blocks} basic blocks, {n_lines} pseudocode lines")
                summary_lines.append(f"Called by: {n_callers} function(s)")
                if callees_set:
                    summary_lines.append(f"Calls: {', '.join(sorted(callees_set)[:8])}")

                results.append({
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "summary": "\n".join(l for l in summary_lines if l),
                    "purpose": purpose_parts,
                    "api_calls": found_apis[:15],
                    "dangerous_calls": dangerous_calls,
                    "strings": str_refs,
                    "complexity": {"blocks": n_blocks, "pseudocode_lines": n_lines},
                    "callers": n_callers,
                    "callees": sorted(callees_set)[:12],
                })

            elif action == "trace_argument_origin":
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                arg_index = int(kwargs.get("arg_index", 0))
                max_depth = int(kwargs.get("max_depth", 4))
                max_callers = int(kwargs.get("max_callers_per_level", 10))
                results.append(_trace_argument_origin(func, arg_index, max_depth, max_callers))

            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        return results[0] if len(results) == 1 else results
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================


# ---------------------------------------------------------------------------
# Argument origin tracer — backward BFS through callers
# ---------------------------------------------------------------------------


