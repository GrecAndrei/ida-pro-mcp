import re

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
        match = re.search(r'(?<![<>=!])=(?!=)', text)
        if match:
            idx = match.start()
            lhs = text[:idx].strip().rstrip('+-*/%&|^<>=!')
            rhs = text[idx+1:].strip()
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
                    # tinfo's __str__ can return a hex memory address for
                    # anonymous lvars — only feed a clean printable name
                    # to the inference regex. Fall back to type name only
                    # when it's a real type string, not a memory address.
                    type_str = str(tinfo).strip()
                    if not type_str or type_str.startswith(("0x", "0X")):
                        raise ValueError("anonymous lvar (no type name)")
                    type_str = type_str.lower().strip("* ")
                    # Strip pointer/array decorators for name inference.
                    # Keep letter segments; drop pure numerics so we don't
                    # delete real identifiers (e.g. 'id0' stays 'id', 'v1'
                    # stays 'v' if it ever leaked into the type name).
                    base = re.sub(r'[\*\[\]]', '', type_str)
                    base = re.sub(r'\b\d+\b', '', base).strip()
                    if base and base not in ("void", "int", "char", "byte", "word", "dword",
                                             "qword", "bool", "unsigned", "signed", "__int"):
                        # Use last component of type name (e.g. wifi_frame_t → frame)
                        parts = re.split(r'[_\s]', base)
                        parts = [p for p in parts if len(p) > 2 and p not in ("type", "ptr", "ref")]
                        if parts:
                            suggestion = parts[-1].rstrip("t").rstrip("_") or parts[-1]
                            # Use the cleaned type name in the reason, NOT the
                            # tinfo object itself (which str()s to a hex address).
                            reason = f"type={type_str}"
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


_DECOMP_KNOWN_APIS = [
    "malloc", "free", "memcpy", "memset", "strcpy", "strncpy", "sprintf", "snprintf",
    "recv", "send", "socket", "connect", "bind", "listen", "accept", "recvfrom", "sendto",
    "fopen", "fread", "fwrite", "fclose", "fgets", "fputs",
    "system", "exec", "execve", "popen", "fork",
    "CreateFile", "ReadFile", "WriteFile", "VirtualAlloc", "WriteProcessMemory", "CreateProcess",
    "RegSetValue", "RegOpenKey", "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
    "AES_encrypt", "AES_decrypt", "SHA256", "SHA256_Update", "SHA1", "MD5", "MD5_Update", "HMAC", "pbkdf2",
    "memcmp", "strcmp", "strstr", "sscanf", "gets", "scanf", "vsprintf",
    "mmap", "munmap", "ioctl", "open", "read", "write", "close",
]

_DECOMP_CRYPTO_SIGS = {
    "AES": ["0x63636363", "0x7c777c77", "aes_key", "aes_encrypt", "aes_decrypt", "aes_"],
    "SHA256": ["0x6a09e667", "0xbb67ae85", "sha256", "sha_256"],
    "SHA1": ["0x67452301", "sha1", "sha_1"],
    "MD5": ["0xefcdab89", "0x67452301", "md5_", "md5update"],
    "RC4": ["rc4_", "ksa", "prga"],
    "ChaCha20": ["chacha", "0x61707865"],
    "PBKDF2": ["pbkdf2", "hmac", "iterations"],
}


def _detect_api_calls(pseudo: str, *, limit: int = 15) -> list[str]:
    return [api for api in _DECOMP_KNOWN_APIS if api in pseudo][:limit]


def _detect_crypto_hints(pseudo: str, *, xor_threshold: int = 4) -> tuple[list[str], int]:
    pseudo_lower = pseudo.lower()
    crypto_hints = []
    for algo, sigs in _DECOMP_CRYPTO_SIGS.items():
        if any(sig.lower() in pseudo_lower for sig in sigs):
            crypto_hints.append(algo)
    xor_count = pseudo.count(" ^ ") + pseudo.count("^=")
    if xor_count >= xor_threshold:
        crypto_hints.append(f"XOR_heavy({xor_count})")
    return crypto_hints, xor_count


def _detect_dangerous_patterns(found_apis: list[str], pseudo: str, *, detailed: bool = False) -> list[str]:
    import re as _re

    dangerous = []
    if any(api in found_apis for api in ["strcpy", "sprintf", "gets", "scanf", "vsprintf"]):
        dangerous.append(
            "unsafe_string_ops — potential buffer overflow" if detailed else "unsafe_string_ops"
        )
    memcpy_bounded = _re.search(r"memcpy\s*\([^,]+,[^,]+,\s*sizeof", pseudo)
    if "memcpy" in found_apis and not memcpy_bounded:
        dangerous.append(
            "memcpy — verify size is bounded" if detailed else "memcpy_no_size_check"
        )
    if any(api in found_apis for api in ["system", "exec", "execve", "popen"]):
        dangerous.append(
            "command_execution — check for injection" if detailed else "command_execution"
        )
    if detailed:
        if "VirtualAlloc" in found_apis and "WriteProcessMemory" in found_apis:
            dangerous.append("process_injection pattern")
        if "recv" in found_apis or "recvfrom" in found_apis:
            dangerous.append("network_input — trace data flow to sinks")
    return dangerous


def _build_pseudocode_complexity(pseudo: str, *, include_switch_cases: bool = False, xor_count: int | None = None) -> dict:
    import re as _re

    effective_xor = xor_count if xor_count is not None else pseudo.count(" ^ ") + pseudo.count("^=")
    complexity = {
        "lines": len(pseudo.splitlines()),
        "calls": len(_re.findall(r"\w+\s*\(", pseudo)),
        "branches": len(_re.findall(r"\bif\s*\(", pseudo)),
        "loops": len(_re.findall(r"\b(for|while|do)\b", pseudo)),
        "xor_ops": effective_xor,
    }
    if include_switch_cases:
        complexity["switch_cases"] = len(_re.findall(r"\bcase\b", pseudo))
    return complexity


def _collect_compact_callers(func_start_ea: int, *, scan_limit: int = 30, result_limit: int = 5) -> list[dict]:
    callers_compact = []
    seen = set()
    for i, xref in enumerate(idautils.CodeRefsTo(func_start_ea, 0)):
        if i >= scan_limit:
            break
        cf = ida_funcs.get_func(xref)
        if not cf or cf.start_ea in seen:
            continue
        seen.add(cf.start_ea)
        callers_compact.append({"addr": hex_ea(cf.start_ea), "name": ida_funcs.get_func_name(cf.start_ea)})
        if len(callers_compact) >= result_limit:
            break
    return callers_compact


def _collect_compact_callees(func_start_ea: int, *, result_limit: int = 8) -> list[dict]:
    callees_compact = []
    seen = set()
    for item in idautils.FuncItems(func_start_ea):
        for ref in idautils.CodeRefsFrom(item, 0):
            cf = ida_funcs.get_func(ref)
            if not cf or cf.start_ea in seen:
                continue
            seen.add(cf.start_ea)
            callees_compact.append({"addr": hex_ea(cf.start_ea), "name": ida_funcs.get_func_name(cf.start_ea)})
            if len(callees_compact) >= result_limit:
                break
        if len(callees_compact) >= result_limit:
            break
    return callees_compact


def _collect_function_strings(func_start_ea: int, *, result_limit: int = 10) -> list[str]:
    str_refs = []
    for item in idautils.FuncItems(func_start_ea):
        for xref in idautils.XrefsFrom(item, 0):
            if xref.iscode:
                continue
            s = idc.get_strlit_contents(xref.to)
            if not s:
                continue
            if isinstance(s, bytes):
                s = s.decode("utf-8", errors="replace")
            str_refs.append(s[:80])
        if len(str_refs) >= result_limit:
            break
    return str_refs[:result_limit]


def _build_decompile_enrichment(
    func_start_ea: int,
    cfunc,
    pseudo: str,
    *,
    detailed_dangerous: bool = False,
    include_switch_cases: bool = False,
    api_limit: int = 15,
) -> dict:
    found_apis = _detect_api_calls(pseudo, limit=api_limit)
    crypto_hints, xor_count = _detect_crypto_hints(pseudo)
    dangerous = _detect_dangerous_patterns(found_apis, pseudo, detailed=detailed_dangerous)
    var_hints = _extract_var_rename_hints(cfunc)
    return {
        "api_calls": found_apis,
        "crypto_hints": crypto_hints,
        "dangerous_patterns": dangerous,
        "var_rename_hints": var_hints,
        "blackboard_context": _get_blackboard_context_for_addr(hex_ea(func_start_ea)),
        "complexity": _build_pseudocode_complexity(
            pseudo,
            include_switch_cases=include_switch_cases,
            xor_count=xor_count,
        ),
    }


def _get_blackboard_context_for_addr(addr_hex: str) -> list:
    """
    Get relevant blackboard entries for this address without IDA deps.
    Returns compact list of {title, category, confidence}.
    """
    try:
        import os as _os
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
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
            item_size = max(item_size, 1)
            curr = curr + item_size
        else:
            curr = next_ea
        count += 1
    return lines


def _disasm_window(
    center_ea: int,
    *,
    radius: int,
    max_items: int,
    style: str,
    include_bytes: bool,
) -> list[str]:
    """Disassemble up to ``radius`` instructions on each side of
    ``center_ea``. Output order is: [oldest ... center-1, center, center+1 ... newest]
    so the natural reading flow is preserved around the focus address.

    ``radius`` is clamped to ``max_items // 2`` so we never blow the
    parent budget, and the final line count never exceeds ``max_items``.
    The walk stops early if IDA stops emitting valid head bytes
    (function/data boundaries, unmapped segments, etc.).
    """
    radius = max(radius, 0)
    max_items = max(max_items, 1)
    radius = min(radius, max_items // 2 if max_items >= 2 else 0)

    before: list[str] = []
    curr = center_ea
    # Walk backwards collecting "radius" instructions whose start_ea is
    # strictly less than center_ea. PrevHead returns BADADDR when we
    # cross the function/binary boundary.
    steps_back = 0
    while steps_back < radius:
        prev = idc.prev_head(curr, 0)
        if prev == idaapi.BADADDR or prev >= curr:
            break
        before.append(_format_disasm_line(prev, style=style, include_bytes=include_bytes))
        curr = prev
        steps_back += 1
    before.reverse()

    after: list[str] = []
    curr = center_ea
    steps_fwd = 0
    while steps_fwd < radius:
        next_ea = idc.next_head(curr, idaapi.BADADDR)
        if next_ea == idaapi.BADADDR or next_ea <= curr:
            # Non-head aligned; fall through one byte at a time until
            # we find a valid head or hit the budget.
            item_size = int(idc.get_item_size(curr) or 1)
            item_size = max(item_size, 1)
            curr = curr + item_size
            if curr <= center_ea:
                continue
            steps_fwd += 1
            after.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes))
            continue
        # Even when next_ea == center_ea exactly we still want to move.
        curr = next_ea
        if curr <= center_ea:
            continue
        steps_fwd += 1
        after.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes))

    # center line itself (if it points at a head).
    center_line = _format_disasm_line(
        center_ea, style=style, include_bytes=include_bytes
    )
    lines = before + [center_line] + after
    if len(lines) > max_items:
        # Keep the central slice — drop the head of `before` so the focus
        # address is preserved if the budget is tight.
        keep = max_items
        tail_budget = keep - 1 - len(after)
        tail_budget = max(tail_budget, 0)
        before = before[-tail_budget:] if tail_budget else []
        lines = before + [center_line] + after
        if len(lines) > max_items:
            lines = lines[:max_items]
    return lines


# ============================================================================
# 2. CODE - Decompilation & Disassembly
# ============================================================================


def _extract_arg_from_decompiled(caller_pseudo, target_name, arg_index):
    """Extract the argument expression at a call site from decompiled text.

    Looks for `target_name(...)` in the decompiled text and returns the
    arg_index-th argument expression as a string. Returns None if parsing
    fails (multi-line, unusual formatting, etc.).
    """
    # Find all occurrences of `target_name (` in the decompiled text
    pattern = re.compile(r'\b' + re.escape(target_name) + r'\s*\(', re.IGNORECASE)
    for m in pattern.finditer(caller_pseudo):
        start = m.end()
        depth = 1
        i = start
        arg_start = start
        arg_idx = 0
        args = []
        while i < len(caller_pseudo) and depth > 0:
            c = caller_pseudo[i]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    if arg_idx == arg_index:
                        return caller_pseudo[arg_start:i].strip()
                    args.append(caller_pseudo[arg_start:i].strip())
            elif c == ',' and depth == 1:
                if arg_idx == arg_index:
                    return caller_pseudo[arg_start:i].strip()
                args.append(caller_pseudo[arg_start:i].strip())
                arg_idx += 1
                arg_start = i + 1
            i += 1
    return None


def _trace_argument_origin(func, arg_index, max_depth, max_callers_per_level):
    """Trace a function argument backward through callers.

    Returns a tree structure showing each caller and the argument expression
    they pass for the specified argument index.
    """
    target_addr = func.start_ea
    fname = ida_funcs.get_func_name(target_addr) or hex(target_addr)

    # Get argument names from prototype if available
    arg_names = []
    proto = idc.get_type(target_addr)
    if proto:
        try:
            func_type = idc.parse_decl(proto, idc.PT_SILENT)
            if func_type:
                _, _, _, args = idc.get_type(target_addr) or ("", "", "", [])
        except Exception:
            pass
    if not arg_names:
        arg_names = [f"arg{i}" for i in range(arg_index + 1)]
    if arg_index >= len(arg_names):
        return {
            "ok": True,
            "target": hex(target_addr),
            "target_name": fname,
            "arg_index": arg_index,
            "argument_name": f"arg{arg_index}",
            "prototype": proto or "unknown",
            "trace_tree": [],
            "note": f"Argument index {arg_index} exceeds known arguments; showing callers without argument extraction.",
        }

    arg_name = arg_names[arg_index]

    # BFS through callers
    trace_tree = []
    visited = {target_addr}
    current_level = [target_addr]

    for depth in range(max_depth + 1):
        next_level = []
        for func_ea in current_level:
            callers = []
            for xr in idautils.XrefsTo(func_ea, 0):
                if not xr.iscode:
                    continue
                caller_func = idaapi.get_func(xr.frm)
                if not caller_func:
                    continue
                caller_ea = caller_func.start_ea
                caller_name = ida_funcs.get_func_name(caller_ea) or hex(caller_ea)
                call_site = hex(xr.frm)

                # Get the decompiled line at the call site
                caller_pseudo = ""
                arg_source = ""
                arg_type = "unknown"
                try:
                    cfunc = ida_hexrays.decompile(caller_ea)
                    if cfunc:
                        caller_pseudo = str(cfunc)
                        extracted = _extract_arg_from_decompiled(caller_pseudo, fname, arg_index)
                        if not extracted:
                            # Try matching by demangled name or partial name
                            extracted = _extract_arg_from_decompiled(caller_pseudo, fname.split("::")[-1], arg_index)
                        if extracted:
                            arg_source = extracted
                            # Classify the argument
                            if extracted.startswith(('"', "'")):
                                arg_type = "string_literal"
                            elif extracted.startswith("0x") or extracted.isdigit():
                                arg_type = "constant"
                            elif "(" in extracted and ")" in extracted:
                                arg_type = "function_call"
                            elif extracted.startswith("&"):
                                arg_type = "address_of"
                            elif arg_type == "unknown":
                                arg_type = "variable"
                        else:
                            arg_source = ""
                            arg_type = "parse_failed"
                except Exception as e:
                    arg_source = ""
                    arg_type = f"decompile_error: {e}"

                call_entry = {
                    "depth": depth,
                    "caller_addr": hex(caller_ea),
                    "caller_name": caller_name,
                    "call_site": call_site,
                    "call_line": arg_source,
                    "arg_source": arg_source,
                    "arg_type": arg_type,
                }
                callers.append(call_entry)

                if caller_ea not in visited and len(next_level) < max_callers_per_level:
                    visited.add(caller_ea)
                    next_level.append(caller_ea)

            trace_tree.extend(callers[:max_callers_per_level])
        current_level = next_level
        if not current_level:
            break

    return {
        "ok": True,
        "action": "trace_argument_origin",
        "target": hex(target_addr),
        "target_name": fname,
        "arg_index": arg_index,
        "argument_name": arg_name,
        "prototype": proto or "unknown",
        "trace_tree": trace_tree,
        "note": f"Backward trace of argument {arg_index} ({arg_name}) up to {max_depth} levels deep. arg_type: string_literal, constant, function_call, address_of, variable, or parse_failed.",
    }
