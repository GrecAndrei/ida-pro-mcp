
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

DISASM_MAX_LINES = 10_000


def _collect_expr_rows_from_cfunc(cfunc, max_items=2000):
    rows = []

    class ExprVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.count = 0

        def visit_expr(self, e):
            if self.count >= max_items:
                return 1
            self.count += 1
            try:
                text = ida_lines.tag_remove(e.print1(None)) or ""
            except Exception:
                text = ""
            rows.append((int(getattr(e, "ea", idaapi.BADADDR)), text))
            return 0

    try:
        v = ExprVisitor()
        v.apply_to(cfunc.body, None)
    except Exception:
        pass
    return rows


def _compute_cfg_semantics(func):
    """Compute richer CFG semantics and complexity metrics for a function."""
    try:
        fc = idaapi.FlowChart(func)
    except Exception:
        return {
            "nodes": 0,
            "edges": 0,
            "entry_blocks": 0,
            "exit_blocks": 0,
            "back_edges": 0,
            "cyclomatic_complexity": 1,
            "loop_density": 0.0,
        }

    nodes = []
    edges = set()
    incoming = {}
    outgoing = {}
    for b in fc:
        nodes.append(int(b.start_ea))
        outgoing.setdefault(int(b.start_ea), 0)
        incoming.setdefault(int(b.start_ea), 0)
        for s in b.succs():
            bea = int(b.start_ea)
            sea = int(s.start_ea)
            edges.add((bea, sea))
            outgoing[bea] = outgoing.get(bea, 0) + 1
            incoming[sea] = incoming.get(sea, 0) + 1

    back_edges = sum(1 for a, b in edges if b <= a)
    node_count = len(nodes)
    edge_count = len(edges)
    entry_blocks = sum(1 for n in nodes if incoming.get(n, 0) == 0)
    exit_blocks = sum(1 for n in nodes if outgoing.get(n, 0) == 0)
    cyclomatic = max(1, edge_count - node_count + 2)
    loop_density = round(back_edges / max(1, edge_count), 4)
    return {
        "nodes": node_count,
        "edges": edge_count,
        "entry_blocks": entry_blocks,
        "exit_blocks": exit_blocks,
        "back_edges": back_edges,
        "cyclomatic_complexity": cyclomatic,
        "loop_density": loop_density,
    }


def _build_decompiler_dataflow(cfunc, max_items=800):
    """
    Build variable dependency graph from decompiler expressions.
    Uses ctree expression text + lvar vocabulary for robust cross-version behavior.
    """
    import re

    lvars = []
    try:
        lvars = list(getattr(cfunc, "lvars", []) or [])
    except Exception:
        lvars = []
    var_names = []
    arg_names = set()
    for v in lvars:
        name = str(getattr(v, "name", "") or "").strip()
        if not name:
            continue
        var_names.append(name)
        if bool(getattr(v, "is_arg_var", False)):
            arg_names.add(name)
    vocab = sorted(set(var_names), key=len, reverse=True)
    if not vocab:
        return {
            "nodes": [],
            "edges": [],
            "assignment_edges": 0,
            "call_edges": 0,
            "argument_variables": [],
            "top_hubs": [],
        }
    word_re = re.compile(r"[A-Za-z_]\w*")
    rows = _collect_expr_rows_from_cfunc(cfunc, max_items=max_items * 4)
    edge_seen = set()
    nodes = set(vocab)
    edges = []
    assign_edges = 0
    call_edges = 0

    def _extract_vars(text):
        toks = set(word_re.findall(text or ""))
        return [t for t in toks if t in nodes]

    for ea, expr in rows:
        text = (expr or "").strip()
        if not text:
            continue
        # Assignment dependency: rhs vars influence lhs var.
        if "=" in text and "==" not in text and "<=" not in text and ">=" not in text and "!=" not in text:
            lhs, rhs = text.split("=", 1)
            lhs_vars = _extract_vars(lhs)
            rhs_vars = _extract_vars(rhs)
            if lhs_vars:
                dst = sorted(lhs_vars, key=len, reverse=True)[0]
                for src in rhs_vars:
                    if src == dst:
                        continue
                    key = (src, dst, "assign")
                    if key in edge_seen:
                        continue
                    edge_seen.add(key)
                    edges.append(
                        {
                            "from": src,
                            "to": dst,
                            "kind": "assign",
                            "ea": hex_ea(ea) if ea != idaapi.BADADDR else None,
                        }
                    )
                    assign_edges += 1
        # Call dependency: vars flow into call sites.
        if "(" in text and ")" in text and "=" not in text:
            callee = text.split("(", 1)[0].strip()
            if callee:
                call_node = f"call:{callee}"
                nodes.add(call_node)
                for src in _extract_vars(text):
                    key = (src, call_node, "arg_flow")
                    if key in edge_seen:
                        continue
                    edge_seen.add(key)
                    edges.append(
                        {
                            "from": src,
                            "to": call_node,
                            "kind": "arg_flow",
                            "ea": hex_ea(ea) if ea != idaapi.BADADDR else None,
                        }
                    )
                    call_edges += 1
        if len(edges) >= max_items:
            break

    # Hub ranking by incident edges.
    degree = {}
    for e in edges:
        degree[e["from"]] = degree.get(e["from"], 0) + 1
        degree[e["to"]] = degree.get(e["to"], 0) + 1
    hubs = sorted(degree.items(), key=lambda kv: kv[1], reverse=True)[:12]

    return {
        "nodes": sorted(nodes),
        "edges": edges,
        "assignment_edges": assign_edges,
        "call_edges": call_edges,
        "argument_variables": sorted(arg_names),
        "top_hubs": [{"node": n, "degree": d} for n, d in hubs],
    }


def _semantic_pseudocode_summary(pseudocode):
    import re

    src = pseudocode or ""
    return {
        "line_count": len(src.splitlines()),
        "call_count": len(re.findall(r"\w+\s*\(", src)),
        "if_count": len(re.findall(r"\bif\s*\(", src)),
        "loop_count": len(re.findall(r"\b(for|while|do)\b", src)),
        "switch_count": len(re.findall(r"\bswitch\s*\(", src)),
        "return_count": len(re.findall(r"\breturn\b", src)),
        "pointer_deref_count": src.count("->") + src.count("*"),
    }


def _get_prev_func(ea: int):
    getter = getattr(ida_funcs, "get_prev_func", None) or getattr(idaapi, "get_prev_func", None)
    return getter(ea) if getter else None


def _get_next_func(ea: int):
    getter = getattr(ida_funcs, "get_next_func", None) or getattr(idaapi, "get_next_func", None)
    return getter(ea) if getter else None


def _decompile_with_diagnostics(func_ea: int):
    """
    Decompile with structured diagnostics.
    Returns (cfunc, err_dict_or_none).
    """
    try:
        if not hasattr(ida_hexrays, "init_hexrays_plugin") or not ida_hexrays.init_hexrays_plugin():
            return None, make_error(
                MCPError.DECOMPILER_UNAVAILABLE,
                "Hex-Rays decompiler not available",
                hint=ERROR_HINTS.get(MCPError.DECOMPILER_UNAVAILABLE),
            )
    except Exception as e:
        return None, make_error(
            MCPError.DECOMPILER_UNAVAILABLE,
            f"Decompiler initialization failed: {e}",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_UNAVAILABLE),
        )

    try:
        if hasattr(ida_hexrays, "decompile_func") and hasattr(ida_hexrays, "hexrays_failure_t"):
            failure = ida_hexrays.hexrays_failure_t()
            flags = getattr(ida_hexrays, "DECOMP_WARNINGS", 0)
            cfunc = ida_hexrays.decompile_func(func_ea, failure, flags)
            if cfunc:
                return cfunc, None
            details = {"addr": hex(func_ea)}
            code = getattr(failure, "code", None)
            if code is not None:
                details["failure_code"] = code
            errea = getattr(failure, "errea", idaapi.BADADDR)
            if errea != idaapi.BADADDR:
                details["failure_ea"] = hex(errea)
            fmsg = getattr(failure, "str", None)
            msg = "Decompilation failed"
            if fmsg:
                msg = f"{msg}: {fmsg}"
            return None, make_error(
                MCPError.DECOMPILER_FAILED,
                msg,
                hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                details=details,
            )

        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            return cfunc, None
        return None, make_error(
            MCPError.DECOMPILER_FAILED,
            "Decompilation failed",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
            details={"addr": hex(func_ea)},
        )
    except Exception as e:
        return None, make_error(
            MCPError.DECOMPILER_FAILED,
            f"Decompilation exception: {e}",
            hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
            details={"addr": hex(func_ea)},
        )


def _format_disasm_line(
    ea: int,
    *,
    style: str = "csmini",
    include_bytes: bool = False,
    mark_all: bool = True,
) -> str:
    raw = idc.generate_disasm_line(ea, 0) or ""
    text = ida_lines.tag_remove(raw) if raw else "<data>"
    prefix = "*" if mark_all else ""
    if style == "classic":
        line = f"{hex_ea(ea)}  {text}"
    elif style == "annotated":
        line = f"{prefix}{hex_ea(ea)}: {text}"
    else:
        line = f"{prefix}{hex_ea(ea)}:{text}"
    if include_bytes:
        size = int(idc.get_item_size(ea) or 0)
        if size > 0:
            insn_bytes = " ".join(f"{ida_bytes.get_byte(ea + i):02x}" for i in range(min(size, 16)))
            line = f"{line} ; bytes={insn_bytes}"
    return line


def _disasm_range(
    start_ea: int,
    stop_ea: int,
    *,
    max_items: int,
    style: str,
    include_bytes: bool,
) -> list[str]:
    lines = []
    curr = start_ea
    count = 0
    hard_end = max(stop_ea, start_ea + 1)
    while curr < hard_end and count < max_items:
        lines.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes))
        next_ea = idc.next_head(curr, hard_end)
        if next_ea == idaapi.BADADDR or next_ea <= curr:
            break
        curr = next_ea
        count += 1
    return lines


# ============================================================================
# 2. CODE - Decompilation & Disassembly
# ============================================================================

@tool
@idaread
def code(
    action: Annotated[Literal[
        "decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field",
        "callees", "callers", "blocks", "analyze", "callgraph", "export",
        "find_paths", "strings_in_func", "diff_functions", "semantic_decompile", "decomp_dataflow",
        "decompile_chain"
    ], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es) - hex string or name"] = None,
    addr: Annotated[Optional[str], "Single address (alias for addrs)"] = None,  # Alias for compatibility
    max_items: Annotated[int, "Max items to return"] = 1000,
    max_depth: Annotated[int, "Max depth for callgraph/find_paths"] = 5,
    format: Annotated[Literal["json", "c_header", "prototypes"], "Export format"] = "json",
    disasm_style: Annotated[Literal["csmini", "classic", "annotated"], "Disassembly line style"] = "csmini",
    include_bytes: Annotated[bool, "Include instruction bytes in disassembly output"] = False,
    end: Annotated[Optional[str], "Optional end address for disasm range"] = None,
    limit: Annotated[Optional[int], "Alias for max_items (especially useful with disasm)"] = None,
    field_name: Annotated[Optional[str], "Struct field name (for xrefs_to_field)"] = None,
    target: Annotated[Optional[str], "Target address (for find_paths)"] = None,
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
        Params: addrs (REQUIRED), optional end, disasm_style (csmini|classic|annotated), include_bytes, limit
        Returns: [{addr, name, disasm: "*addr:instr\\n*addr:instr\\n...", count, style, range}]
        Example: code(action="disasm", addrs="0x401000")
        Example: code(action="disasm", addrs="0x125b0", end="0x12640", limit=160, disasm_style="csmini")
        
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
        
    find_paths - Find control flow paths between two addresses
        Params: addrs (REQUIRED), target (REQUIRED)
        Returns: [{addr, paths: [[addr1, addr2, ...], ...]}]
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
    """
    try:
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
                    
                    results.append({"addr": addr, "error": f"No function at {hex_ea(ea)}.{suggestion}"})
                    continue
                
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    if cfunc:
                        results.append({
                            "ok": True,
                            "addr": hex_ea(func.start_ea),
                            "code": str(cfunc),
                            "prototype": get_prototype(func)
                        })
                    else:
                        results.append({
                            "addr": addr,
                            "error": dec_err.get("message", "Decompilation failed") if isinstance(dec_err, dict) else "Decompilation failed",
                            "error_code": dec_err.get("code") if isinstance(dec_err, dict) else MCPError.DECOMPILER_FAILED,
                            "hint": dec_err.get("hint") if isinstance(dec_err, dict) else None,
                            "details": dec_err.get("details") if isinstance(dec_err, dict) else None,
                        })
                except Exception as e:
                    results.append({"addr": addr, "error": str(e)})

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
                    results.append({"addr": addr, "error": f"No function at {hex_ea(ea)}.{suggestion}"})
                    continue
                chain_depth = max(1, min(max_depth, 5))
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    main_pseudo = str(cfunc) if cfunc else ""
                    main_proto = get_prototype(func)
                    # Collect callers (limit xref scan to avoid hanging on heavily-referenced funcs)
                    callers_ctx = []
                    caller_addrs = set()
                    max_xrefs = chain_depth * 20
                    for i, xref in enumerate(idautils.CodeRefsTo(func.start_ea, 0)):
                        if i >= max_xrefs:
                            break
                        caller_fn = ida_funcs.get_func(xref)
                        if caller_fn and caller_fn.start_ea not in caller_addrs:
                            caller_addrs.add(caller_fn.start_ea)
                            ccfunc, _ = _decompile_with_diagnostics(caller_fn.start_ea)
                            if ccfunc:
                                callers_ctx.append({
                                    "addr": hex_ea(caller_fn.start_ea),
                                    "name": ida_funcs.get_func_name(caller_fn.start_ea),
                                    "pseudocode": str(ccfunc),
                                })
                            if len(callers_ctx) >= chain_depth:
                                break
                    # Collect callees
                    callees_ctx = []
                    callee_addrs = set()
                    for item in idautils.FuncItems(func.start_ea):
                        for ref in idautils.CodeRefsFrom(item, 0):
                            callee_fn = ida_funcs.get_func(ref)
                            if callee_fn and callee_fn.start_ea not in callee_addrs:
                                callee_addrs.add(callee_fn.start_ea)
                                ccfunc, _ = _decompile_with_diagnostics(callee_fn.start_ea)
                                if ccfunc:
                                    callees_ctx.append({
                                        "addr": hex_ea(callee_fn.start_ea),
                                        "name": ida_funcs.get_func_name(callee_fn.start_ea),
                                        "pseudocode": str(ccfunc),
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
                    })
                except Exception as e:
                    results.append({"addr": addr, "error": str(e)})

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
                        "range": f"{hex_ea(ea)}-{hex_ea((end_ea if end_ea is not None else (ea + 0x1000)))}",
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
            
            elif action == "analyze":
                # Comprehensive function analysis
                func = idaapi.get_func(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                
                fname = ida_funcs.get_func_name(func.start_ea)
                info = {"ok": True, "addr": hex_ea(func.start_ea), "name": fname, "size": hex_size(func.end_ea - func.start_ea)}
                
                # Decompile
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    info["pseudocode"] = str(cfunc) if cfunc else None
                    if dec_err:
                        info["decompiler_error"] = {
                            "code": dec_err.get("code"),
                            "message": dec_err.get("message"),
                            "hint": dec_err.get("hint"),
                        }
                except Exception:
                    info["pseudocode"] = None
                
                # Prototype
                try:
                    info["prototype"] = get_prototype(func)
                except Exception:
                    info["prototype"] = None
                
                # Callees
                try:
                    callees = set()
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if xref.iscode:
                                tf = idaapi.get_func(xref.to)
                                if tf and tf.start_ea != func.start_ea:
                                    callees.add((hex_ea(tf.start_ea), ida_funcs.get_func_name(tf.start_ea)))
                    info["callees"] = "\n".join(f"{a}  {n}" for a, n in sorted(list(callees))[:50])
                except Exception:
                    info["callees"] = ""
                
                # Callers
                try:
                    callers = set()
                    for xref in idautils.XrefsTo(func.start_ea, 0):
                        if xref.iscode:
                            cf = idaapi.get_func(xref.frm)
                            if cf:
                                callers.add((hex_ea(cf.start_ea), ida_funcs.get_func_name(cf.start_ea)))
                    info["callers"] = "\n".join(f"{a}  {n}" for a, n in sorted(list(callers))[:50])
                except Exception:
                    info["callers"] = ""
                
                # Strings
                try:
                    strings = []
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.XrefsFrom(item, 0):
                            if not xref.iscode:
                                s = idc.get_strlit_contents(xref.to)
                                if s:
                                    if isinstance(s, bytes):
                                        s = s.decode("utf-8", errors="replace")
                                    strings.append(f"{hex_ea(xref.to)}  {s}")
                    info["strings"] = "\n".join(strings[:25])
                except Exception:
                    info["strings"] = ""
                
                # Stack vars
                try:
                    info["stack_vars"] = get_stack_frame_variables_internal(func.start_ea, False)
                except Exception:
                    info["stack_vars"] = []
                
                results.append(info)
            
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
                # Find xrefs to a struct field
                if not field_name:
                    results.append(make_error(MCPError.INVALID_ARGS, "field_name required"))
                    continue
                
                # Parse field_name in format "struct_name.field_name" or just "field_name"
                struct_name = None
                actual_field = field_name
                if "." in field_name:
                    struct_name, actual_field = field_name.rsplit(".", 1)
                
                xrefs_found = []
                try:
                    # Get type info library
                    til = ida_typeinf.get_idati()
                    
                    # Search through all local types for matching fields
                    qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
                    for ordinal in range(1, qty_func(til) + 1):
                        tinfo = ida_typeinf.tinfo_t()
                        if tinfo.get_numbered_type(til, ordinal):
                            type_name = tinfo.get_type_name()
                            
                            # Filter by struct name if specified
                            if struct_name and type_name != struct_name:
                                continue
                            
                            # Check if it's a struct/union
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            # Found the field, now find xrefs to addresses using this struct
                                            # member.offset is already in bytes in IDA 9
                                            xrefs_found.append({
                                                "struct": type_name,
                                                "field": actual_field,
                                                "offset": member.offset,
                                                "field_type": str(member.type)
                                            })
                    
                    if not xrefs_found:
                        results.append({"addr": addr, "field": field_name, "xrefs": [], "note": "Field not found in any struct"})
                    else:
                        results.append({"addr": addr, "field": field_name, "struct_info": xrefs_found})
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
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}"))
                    continue
                
                str_lines = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            # Check if string
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                if isinstance(s, bytes):
                                    s = s.decode("utf-8", errors="replace")
                                str_lines.append(f"{hex(xref.to)}  {s}")
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
                    results.append(
                        {
                            "addr": addr,
                            "error": dec_err.get("message", "Decompilation failed") if isinstance(dec_err, dict) else "Decompilation failed",
                            "error_code": dec_err.get("code") if isinstance(dec_err, dict) else MCPError.DECOMPILER_FAILED,
                            "hint": dec_err.get("hint") if isinstance(dec_err, dict) else None,
                            "details": dec_err.get("details") if isinstance(dec_err, dict) else None,
                        }
                    )
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
                    results.append(
                        {
                            "addr": addr,
                            "error": dec_err.get("message", "Decompilation failed") if isinstance(dec_err, dict) else "Decompilation failed",
                            "error_code": dec_err.get("code") if isinstance(dec_err, dict) else MCPError.DECOMPILER_FAILED,
                            "hint": dec_err.get("hint") if isinstance(dec_err, dict) else None,
                            "details": dec_err.get("details") if isinstance(dec_err, dict) else None,
                        }
                    )
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

            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
        
        return results[0] if len(results) == 1 else results
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================
