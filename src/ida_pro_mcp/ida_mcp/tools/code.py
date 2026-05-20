
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


def _extract_var_rename_hints(cfunc) -> list:
    """
    Suggest better names for decompiler-generated variables (v1, v2, a1, etc.).

    Priority:
    1. IDA type info — if IDA knows the type, use it (wifi_frame_t* → frame)
    2. Usage patterns in pseudocode — recv/malloc/key/sock etc.
    3. Argument position heuristics — a1 in network function → likely fd or buf
    """
    import re
    hints = []
    try:
        pseudo = str(cfunc)
        lvars = list(getattr(cfunc, "lvars", []) or [])
        for v in lvars:
            name = str(getattr(v, "name", "") or "").strip()
            if not name or not re.match(r'^[va]\d+$', name):
                continue

            suggestion = None
            reason = ""

            # 1. IDA type info — highest confidence
            try:
                tinfo = getattr(v, "type", None)
                if tinfo is not None:
                    type_str = str(tinfo).lower().strip("* ")
                    # Strip pointer/array decorators for name inference
                    base = re.sub(r'[\*\[\]0-9]', '', type_str).strip()
                    if base and base not in ("void", "int", "char", "byte", "word", "dword",
                                             "qword", "bool", "unsigned", "signed", "__int"):
                        # Use last component of type name (e.g. wifi_frame_t → frame)
                        parts = re.split(r'[_\s]', base)
                        parts = [p for p in parts if len(p) > 2 and p not in ("type", "ptr", "ref")]
                        if parts:
                            suggestion = parts[-1].rstrip("t").rstrip("_") or parts[-1]
                            reason = f"type={tinfo}"
            except Exception:
                pass

            # 2. Usage patterns in pseudocode
            if not suggestion:
                patterns = re.findall(rf'\b{re.escape(name)}\b[^;{{}}\n]*', pseudo)
                for pat in patterns[:6]:
                    pl = pat.lower()
                    if any(x in pl for x in ["recv(", "recvfrom(", "read("]):
                        suggestion, reason = "recv_buf", pat[:50]
                    elif any(x in pl for x in ["send(", "write(", "fwrite("]):
                        suggestion, reason = "send_buf", pat[:50]
                    elif any(x in pl for x in ["socket(", "accept(", "connect("]):
                        suggestion, reason = "sock_fd", pat[:50]
                    elif any(x in pl for x in ["malloc(", "calloc(", "alloc("]):
                        suggestion, reason = "heap_buf", pat[:50]
                    elif any(x in pl for x in ["aes", "key", "cipher", "encrypt", "decrypt"]):
                        suggestion, reason = "key_buf", pat[:50]
                    elif any(x in pl for x in ["packet", "frame", "pkt", "hdr"]):
                        suggestion, reason = "pkt_buf", pat[:50]
                    elif any(x in pl for x in ["strlen(", "strcpy(", "strcat("]):
                        suggestion, reason = "str_buf", pat[:50]
                    elif any(x in pl for x in ["->next", "->prev", "->list"]):
                        suggestion, reason = "node", pat[:50]
                    elif any(x in pl for x in ["->size", "->len", "->count"]):
                        suggestion, reason = "size", pat[:50]
                    elif any(x in pl for x in ["fopen(", "fread(", "fwrite("]):
                        suggestion, reason = "fp", pat[:50]
                    elif any(x in pl for x in ["ioctl(", "mmap("]):
                        suggestion, reason = "fd", pat[:50]
                    elif re.search(rf'\b{re.escape(name)}\s*=\s*0\b', pat) and name.startswith("v"):
                        suggestion, reason = "result", pat[:50]
                    if suggestion:
                        break

            # 3. Argument position heuristic for a1/a2/a3
            if not suggestion and name.startswith("a"):
                try:
                    idx = int(name[1:]) - 1
                    proto = str(getattr(cfunc, "type", "") or "")
                    proto_lower = proto.lower()
                    if idx == 0:
                        if "socket" in proto_lower or "fd" in proto_lower:
                            suggestion, reason = "fd", "arg0 in socket-like function"
                        elif "buf" in proto_lower or "data" in proto_lower:
                            suggestion, reason = "buf", "arg0 is buffer"
                    elif idx == 1 and "size" in proto_lower:
                        suggestion, reason = "size", "arg1 is size"
                except Exception:
                    pass

            if suggestion and suggestion != name:
                hints.append({"var": name, "suggested": suggestion, "reason": reason[:80]})

    except Exception:
        pass
    return hints[:10]


def _get_blackboard_context_for_addr(addr_hex: str) -> list:
    """
    Get relevant blackboard entries for this address without IDA deps.
    Returns compact list of {title, category, confidence}.
    """
    try:
        import importlib.util, os as _os
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                             "..", "..", "host", "knowledge_graph.py")
        # Use blackboard directly
        from blackboard import BlackboardStore  # type: ignore
        store = BlackboardStore()
        entries = store.list(addr=addr_hex, limit=5, include_resolved=False)
        return [{"title": e["title"], "category": e["category"],
                 "confidence": e.get("confidence", 0.5),
                 "source_type": e.get("source_type", "manual")}
                for e in entries]
    except Exception:
        return []


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
            # On newly created functions, Hex-Rays may fail because the CFG
            # isn't fully analyzed yet (e.g. opcode error 50735). Nudge
            # auto-analysis and retry once.
            failure_code = getattr(failure, "code", None)
            if failure_code is not None:
                try:
                    fn = ida_funcs.get_func(func_ea)
                    if fn:
                        import ida_auto as _ida_auto
                        if hasattr(_ida_auto, "plan_range"):
                            _ida_auto.plan_range(fn.start_ea, fn.end_ea)
                        elif hasattr(_ida_auto, "auto_mark_range"):
                            _ida_auto.auto_mark_range(fn.start_ea, fn.end_ea, _ida_auto.AU_FINAL)
                        time.sleep(0.5)
                        failure2 = ida_hexrays.hexrays_failure_t()
                        cfunc = ida_hexrays.decompile_func(func_ea, failure2, flags)
                        if cfunc:
                            return cfunc, None
                        code2 = getattr(failure2, "code", None)
                        if code2 is not None:
                            failure = failure2
                            failure_code = code2
                except Exception:
                    pass
            details = {"addr": hex(func_ea)}
            if failure_code is not None:
                details["failure_code"] = failure_code
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
            item_size = int(idc.get_item_size(curr) or 1)
            if item_size < 1:
                item_size = 1
            curr = curr + item_size
        else:
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
        "find_paths", "strings_in_func", "diff_functions", "semantic_decompile",
        "decomp_dataflow", "decompile_chain", "smart_decompile", "annotate", "explain"
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
                        pseudo = str(cfunc)
                        result_entry = {
                            "ok": True,
                            "addr": hex_ea(func.start_ea),
                            "code": pseudo,
                            "prototype": get_prototype(func),
                        }
                        # Inline enrichment: API calls, behavior hints, var rename hints,
                        # blackboard context — all in one response so LLM doesn't need extra calls
                        try:
                            import re as _re
                            # Quick API extraction from pseudocode
                            _KNOWN_APIS = [
                                "malloc","free","memcpy","memset","strcpy","strncpy","sprintf",
                                "recv","send","socket","connect","bind","listen","accept",
                                "fopen","fread","fwrite","fclose","system","exec","popen",
                                "CreateFile","ReadFile","WriteFile","VirtualAlloc","CreateProcess",
                                "RegSetValue","RegOpenKey","CryptEncrypt","CryptDecrypt",
                                "AES_encrypt","SHA256","MD5","HMAC","pbkdf2",
                                "memcmp","strcmp","strstr","sscanf","gets","scanf",
                            ]
                            found_apis = [a for a in _KNOWN_APIS if a in pseudo]
                            if found_apis:
                                result_entry["api_calls"] = found_apis[:12]

                            # Crypto constant detection
                            _CRYPTO_PATTERNS = {
                                "AES": ["0x63636363", "0x7c777c77", "AES_KEY", "aes_"],
                                "SHA256": ["0x6a09e667", "0xbb67ae85", "sha256"],
                                "MD5": ["0x67452301", "0xefcdab89", "md5_"],
                                "RC4": ["rc4_", "KSA", "PRGA"],
                                "XOR_cipher": [],  # detected by xor_count below
                            }
                            crypto_hints = []
                            pseudo_lower = pseudo.lower()
                            for algo, patterns in _CRYPTO_PATTERNS.items():
                                if any(p.lower() in pseudo_lower for p in patterns):
                                    crypto_hints.append(algo)
                            # Count XOR operations as crypto signal
                            xor_count = pseudo.count(" ^ ") + pseudo.count("^=")
                            if xor_count >= 4:
                                crypto_hints.append(f"XOR_heavy({xor_count})")
                            if crypto_hints:
                                result_entry["crypto_hints"] = crypto_hints

                            # Dangerous patterns
                            dangerous = []
                            if any(a in found_apis for a in ["strcpy","sprintf","gets","scanf"]):
                                dangerous.append("unsafe_string_ops")
                            if "memcpy" in found_apis and "size" not in pseudo_lower:
                                dangerous.append("memcpy_no_size_check")
                            if any(a in found_apis for a in ["system","exec","popen"]):
                                dangerous.append("command_execution")
                            if dangerous:
                                result_entry["dangerous_patterns"] = dangerous

                            # Variable rename hints
                            var_hints = _extract_var_rename_hints(cfunc)
                            if var_hints:
                                result_entry["var_rename_hints"] = var_hints

                            # Blackboard context for this address
                            bb_ctx = _get_blackboard_context_for_addr(hex_ea(func.start_ea))
                            if bb_ctx:
                                result_entry["blackboard_context"] = bb_ctx

                            # Complexity summary
                            lines = pseudo.splitlines()
                            result_entry["complexity"] = {
                                "lines": len(lines),
                                "calls": len(_re.findall(r'\w+\s*\(', pseudo)),
                                "branches": len(_re.findall(r'\bif\s*\(', pseudo)),
                                "loops": len(_re.findall(r'\b(for|while|do)\b', pseudo)),
                                "xor_ops": xor_count,
                            }
                        except Exception:
                            pass
                        results.append(result_entry)
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
                cfunc = None
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

                # Enrichment (same as smart_decompile)
                if cfunc and info.get("pseudocode"):
                    pseudo = info["pseudocode"]
                    import re as _re
                    _KNOWN_APIS = [
                        "malloc","free","memcpy","memset","strcpy","strncpy","sprintf","snprintf",
                        "recv","send","socket","connect","bind","listen","accept","recvfrom","sendto",
                        "fopen","fread","fwrite","fclose","system","exec","execve","popen",
                        "CreateFile","ReadFile","WriteFile","VirtualAlloc","CreateProcess",
                        "CryptEncrypt","CryptDecrypt","AES_encrypt","SHA256_Update","MD5_Update",
                        "memcmp","strcmp","strstr","sscanf","gets","scanf","vsprintf",
                    ]
                    found_apis = [a for a in _KNOWN_APIS if a in pseudo]
                    if found_apis:
                        info["api_calls"] = found_apis[:12]
                    xor_count = pseudo.count(" ^ ") + pseudo.count("^=")
                    crypto_hints = []
                    pseudo_lower = pseudo.lower()
                    for algo, sigs in {"AES":["0x63636363","aes_encrypt"],"SHA256":["0x6a09e667","sha256"],
                                       "MD5":["0xefcdab89","md5_"],"RC4":["rc4_"]}.items():
                        if any(s.lower() in pseudo_lower for s in sigs):
                            crypto_hints.append(algo)
                    if xor_count >= 4:
                        crypto_hints.append(f"XOR_heavy({xor_count})")
                    if crypto_hints:
                        info["crypto_hints"] = crypto_hints
                    dangerous = []
                    if any(a in found_apis for a in ["strcpy","sprintf","gets","scanf","vsprintf"]):
                        dangerous.append("unsafe_string_ops")
                    if any(a in found_apis for a in ["system","exec","execve","popen"]):
                        dangerous.append("command_execution")
                    if dangerous:
                        info["dangerous_patterns"] = dangerous
                    var_hints = _extract_var_rename_hints(cfunc)
                    if var_hints:
                        info["var_rename_hints"] = var_hints
                    info["complexity"] = {
                        "lines": len(pseudo.splitlines()),
                        "calls": len(_re.findall(r'\w+\s*\(', pseudo)),
                        "branches": len(_re.findall(r'\bif\s*\(', pseudo)),
                        "loops": len(_re.findall(r'\b(for|while|do)\b', pseudo)),
                    }
                    bb_ctx = _get_blackboard_context_for_addr(hex_ea(func.start_ea))
                    if bb_ctx:
                        info["blackboard_context"] = bb_ctx
                
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
                    for ordinal in range(1, qty_func(til) + 1):
                        tinfo = ida_typeinf.tinfo_t()
                        if not tinfo.get_numbered_type(til, ordinal):
                            continue
                        type_name = tinfo.get_type_name()
                        if struct_name and type_name != struct_name:
                            continue
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
                    import re as _re
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
                import re as _re

                _KNOWN_APIS = [
                    "malloc","free","memcpy","memset","strcpy","strncpy","sprintf","snprintf",
                    "recv","send","socket","connect","bind","listen","accept","recvfrom","sendto",
                    "fopen","fread","fwrite","fclose","fgets","fputs",
                    "system","exec","execve","popen","fork",
                    "CreateFile","ReadFile","WriteFile","VirtualAlloc","CreateProcess",
                    "RegSetValue","RegOpenKey","CryptEncrypt","CryptDecrypt","BCryptEncrypt",
                    "AES_encrypt","AES_decrypt","SHA256_Update","MD5_Update","HMAC","pbkdf2",
                    "memcmp","strcmp","strstr","sscanf","gets","scanf","vsprintf",
                    "mmap","munmap","ioctl","open","read","write","close",
                ]
                found_apis = [a for a in _KNOWN_APIS if a in pseudo]

                crypto_hints = []
                pseudo_lower = pseudo.lower()
                _CRYPTO_SIGS = {
                    "AES": ["0x63636363","0x7c777c77","aes_key","aes_encrypt","aes_decrypt"],
                    "SHA256": ["0x6a09e667","0xbb67ae85","sha256","sha_256"],
                    "SHA1": ["0x67452301","sha1","sha_1"],
                    "MD5": ["0xefcdab89","md5_","md5update"],
                    "RC4": ["rc4_"," ksa"," prga"],
                    "ChaCha20": ["chacha","0x61707865"],
                    "PBKDF2": ["pbkdf2","hmac","iterations"],
                }
                for algo, sigs in _CRYPTO_SIGS.items():
                    if any(s.lower() in pseudo_lower for s in sigs):
                        crypto_hints.append(algo)
                xor_count = pseudo.count(" ^ ") + pseudo.count("^=")
                if xor_count >= 4:
                    crypto_hints.append(f"XOR_heavy({xor_count})")

                dangerous = []
                if any(a in found_apis for a in ["strcpy","sprintf","gets","scanf","vsprintf"]):
                    dangerous.append("unsafe_string_ops — potential buffer overflow")
                if "memcpy" in found_apis and not _re.search(r'memcpy\s*\([^,]+,[^,]+,\s*sizeof', pseudo):
                    dangerous.append("memcpy — verify size is bounded")
                if any(a in found_apis for a in ["system","exec","execve","popen"]):
                    dangerous.append("command_execution — check for injection")
                if "VirtualAlloc" in found_apis and "WriteProcessMemory" in found_apis:
                    dangerous.append("process_injection pattern")
                if "recv" in found_apis or "recvfrom" in found_apis:
                    dangerous.append("network_input — trace data flow to sinks")

                var_hints = _extract_var_rename_hints(cfunc)

                callers_compact = []
                for i, xref in enumerate(idautils.CodeRefsTo(func.start_ea, 0)):
                    if i >= 30: break
                    cf = ida_funcs.get_func(xref)
                    if cf:
                        callers_compact.append({"addr": hex_ea(cf.start_ea),
                                                "name": ida_funcs.get_func_name(cf.start_ea)})
                    if len(callers_compact) >= 5: break

                callees_compact = []
                callee_seen = set()
                for item in idautils.FuncItems(func.start_ea):
                    for ref in idautils.CodeRefsFrom(item, 0):
                        cf = ida_funcs.get_func(ref)
                        if cf and cf.start_ea not in callee_seen:
                            callee_seen.add(cf.start_ea)
                            callees_compact.append({"addr": hex_ea(cf.start_ea),
                                                    "name": ida_funcs.get_func_name(cf.start_ea)})
                        if len(callees_compact) >= 8: break
                    if len(callees_compact) >= 8: break

                str_refs = []
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            s = idc.get_strlit_contents(xref.to)
                            if s:
                                if isinstance(s, bytes):
                                    s = s.decode("utf-8", errors="replace")
                                str_refs.append(s[:80])
                    if len(str_refs) >= 10: break

                bb_ctx = _get_blackboard_context_for_addr(hex_ea(func.start_ea))

                lines = pseudo.splitlines()
                complexity = {
                    "lines": len(lines),
                    "calls": len(_re.findall(r'\w+\s*\(', pseudo)),
                    "branches": len(_re.findall(r'\bif\s*\(', pseudo)),
                    "loops": len(_re.findall(r'\b(for|while|do)\b', pseudo)),
                    "xor_ops": xor_count,
                    "switch_cases": len(_re.findall(r'\bcase\b', pseudo)),
                }

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

            elif action == "annotate":
                # Add a comment to a function or address. Shortcut for modify(comment).
                if not comment:
                    results.append(make_error(MCPError.INVALID_ARGS, "comment required for annotate"))
                    continue
                try:
                    func = idaapi.get_func(ea)
                    target_ea = func.start_ea if func else ea
                    if func:
                        idc.set_func_cmt(target_ea, comment, 1)
                    else:
                        idc.set_cmt(ea, comment, 1)
                    results.append({
                        "ok": True,
                        "addr": hex_ea(target_ea),
                        "comment": comment,
                        "type": "function_comment" if func else "address_comment",
                    })
                except Exception as e:
                    results.append({"addr": addr, "error": str(e)})

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
                    results.append({"addr": addr, "error": "Decompilation failed — cannot explain"})
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
                pseudo_lower = pseudo.lower()

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
                        s = idc.get_strlit_contents(xr.to, -1, -1)
                        if s:
                            try:
                                str_refs.append(s.decode("utf-8", errors="replace")[:80])
                            except Exception:
                                pass
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

            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
        
        return results[0] if len(results) == 1 else results
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 3. DATA - Functions, Globals, Strings, Imports
# ============================================================================
