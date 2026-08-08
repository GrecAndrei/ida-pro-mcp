import re
import time

from ida_pro_mcp.ida_mcp.support.crypto_registry import DECOMP_CRYPTO_SIGS as _DECOMP_CRYPTO_SIGS

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


def _build_function_structure_summary(func, cfunc=None, max_items=12, details=False):
    """Return compact CFG/ctree evidence suitable for normal LLM responses.

    This deliberately does not export a raw graph or an AST dump.  Those are
    available through ``graph`` and ``ctree`` when an investigation needs
    them.  The common path instead gets deterministic, bounded facts that can
    be read beside disassembly or pseudocode without drowning out the code.
    ``cfunc`` is optional so disassembly can benefit without starting Hex-Rays.
    ``details=True`` adds dataflow top_hubs and edge counts (opt-in — verbose).
    """
    summary: dict[str, Any] = {"cfg": _compute_cfg_semantics(func)}
    call_targets: list[str] = []
    try:
        for item_ea in idautils.FuncItems(func.start_ea):
            for target in idautils.CodeRefsFrom(item_ea, 0):
                target_func = ida_funcs.get_func(target)
                if target_func and target_func.start_ea != func.start_ea:
                    name = ida_funcs.get_func_name(target_func.start_ea) or hex_ea(target_func.start_ea)
                    if name not in call_targets:
                        call_targets.append(name)
                        if len(call_targets) >= max_items:
                            break
            if len(call_targets) >= max_items:
                break
    except Exception:
        pass
    if call_targets:
        summary["call_targets"] = call_targets

    if cfunc is not None:
        control_points: list[dict[str, str]] = []

        class ControlVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

            def visit_insn(self, insn):
                if len(control_points) >= max_items:
                    return 1
                kinds = {
                    ida_hexrays.cit_if: ("if", "cif", "expr"),
                    ida_hexrays.cit_while: ("while", "cwhile", "expr"),
                    ida_hexrays.cit_for: ("for", "cfor", "cond"),
                    ida_hexrays.cit_switch: ("switch", "cswitch", "expr"),
                }
                detail = kinds.get(insn.op)
                if not detail:
                    return 0
                kind, container, field = detail
                condition = ""
                try:
                    expr = getattr(getattr(insn, container), field)
                    condition = ida_lines.tag_remove(expr.print1(None)) if expr else ""
                except Exception:
                    pass
                control_points.append({
                    "kind": kind,
                    "ea": hex_ea(insn.ea) if insn.ea != idaapi.BADADDR else "",
                    "condition": condition[:160],
                })
                return 0

        try:
            ControlVisitor().apply_to(cfunc.body, None)
        except Exception:
            pass
        if control_points:
            summary["control_points"] = control_points
        try:
            dataflow = _build_decompiler_dataflow(cfunc, max_items=min(160, max_items * 16))
            df: dict = {
                "argument_variables": dataflow.get("argument_variables", [])[:max_items],
            }
            if details:
                df["top_hubs"] = dataflow.get("top_hubs", [])[:max_items]
                df["assignment_edges"] = dataflow.get("assignment_edges", 0)
                df["call_edges"] = dataflow.get("call_edges", 0)
            summary["dataflow"] = df
        except Exception:
            pass

    evidence: list[str] = []
    cfg = summary["cfg"]
    evidence.append(
        "cfg: {nodes} blocks, {edges} edges, complexity {cyclomatic_complexity}, "
        "back_edges {back_edges}".format(**cfg)
    )
    if call_targets:
        evidence.append("calls: " + ", ".join(call_targets[:max_items]))
    if summary.get("control_points"):
        rendered = [
            f"{point['kind']}({point['condition']})" if point.get("condition") else point["kind"]
            for point in summary["control_points"][:max_items]
        ]
        evidence.append("control: " + "; ".join(rendered))
    dataflow = summary.get("dataflow")
    if isinstance(dataflow, dict) and dataflow.get("argument_variables"):
        evidence.append("args: " + ", ".join(dataflow["argument_variables"]))
    summary["evidence"] = " | ".join(evidence)
    return summary


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
                tinfo_attr = getattr(v, "type", None)
                # lvar_t.type is a bound method in SWIG bindings — call it to get
                # the tinfo_t object, then stringify that. Accessing it as a
                # property gives a method repr like "<bound method lvar_t.type...>"
                if callable(tinfo_attr):
                    try:
                        tinfo = tinfo_attr()
                    except Exception:
                        tinfo = None
                else:
                    tinfo = tinfo_attr
                if tinfo is not None:
                    # Prefer tinfo_t.dstr() when available (clean type string);
                    # fall back to str() which can still return a hex address for
                    # anonymous lvars.
                    if hasattr(tinfo, "dstr"):
                        type_str = tinfo.dstr().strip()
                    else:
                        type_str = str(tinfo).strip()
                    if not type_str or type_str.startswith(("0x", "0X", "<")):
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


def _scan_ctree_vulns(cfunc) -> list[dict]:
    """Scan decompiled ctree (AST) for vulnerability patterns using IDA's Hex-Rays API.

    Uses ctree_visitor_t to traverse the actual AST nodes — not regex on text.
    Uses ida_typeinf for prototype analysis, ida_xref for inter-procedural taint,
    ida_segment for writable segment detection, ida_bytes for memory content inspection,
    ida_struct for sensitive field detection, FlowChart for CFG reachability.
    """
    findings = []
    if not cfunc:
        return findings

    # Collect lvar info for type/size analysis
    lvar_map = {}
    try:
        for v in (cfunc.lvars or []):
            name = str(getattr(v, "name", "") or "")
            if name:
                typ = str(getattr(v, "type", "") or "")
                lvar_map[name] = {
                    "type": typ,
                    "is_arg": bool(getattr(v, "is_arg_var", False)),
                    "width": int(getattr(v, "width", 0) or 0),
                }
    except Exception:
        pass

    # Dangerous API sets
    UNBOUNDED_COPY = {"strcpy", "lstrcpy", "strcat", "lstrcat", "gets", "vsprintf"}
    SIZED_COPY = {"memcpy", "memmove", "strncpy", "CopyMemory", "memmove_s"}
    FORMAT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "dprintf", "syslog", "vprintf", "vfprintf", "vsprintf", "vsnprintf"}
    COMMAND_EXEC = {"system", "popen", "exec", "execve", "execl", "execlp", "execvp", "ShellExecute", "CreateProcessA", "CreateProcessW"}
    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "VirtualAlloc", "HeapAlloc", "mmap", "LocalAlloc", "GlobalAlloc", "CoTaskMemAlloc"}
    NETWORK_SOURCES = {"recv", "recvfrom", "recvmsg", "WSARecv", "read", "fread", "recv_s", "gets"}
    FREE_FUNCS = {"free", "VirtualFree", "HeapFree", "munmap", "LocalFree", "GlobalFree", "CoTaskMemFree"}
    # Track freed variables for UAF detection
    freed_vars = {}  # var_name -> (ea, line_text)
    # Track allocation return values for unchecked-malloc detection
    alloc_calls = {}  # ea -> callee_name
    # Track all call EAs for return value checking
    call_eas = []  # (ea, callee_name, result_var)

    # Get function start EA for xref analysis
    func_ea = int(cfunc.entry_ea) if hasattr(cfunc, 'entry_ea') else 0

    # --- Prototype analysis: get function signature and parameter types ---
    func_params = []
    try:
        tinfo = cfunc.type
        if tinfo:
            # Extract parameter types from prototype
            func_data = ida_typeinf.func_type_data_t()
            if tinfo.get_func_details(func_data):
                for i in range(func_data.size()):
                    pi = func_data[i]
                    param_name = str(getattr(pi, "name", "") or f"arg{i}")
                    param_type = str(getattr(pi, "type", "") or "")
                    func_params.append({"name": param_name, "type": param_type, "idx": i})
    except Exception:
        pass

    class VulnVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            try:
                if expr.op == ida_hexrays.cot_call:
                    self._check_call(expr)
                elif expr.op == ida_hexrays.cot_asg:
                    self._check_assignment(expr)
            except Exception:
                pass
            return 0

        def _get_call_info(self, expr):
            callee = expr.x
            callee_name = ""
            callee_ea = 0
            if callee:
                if callee.op == ida_hexrays.cot_obj:
                    callee_ea = int(callee.obj_ea)
                    callee_name = idc.get_name(callee_ea) or hex_ea(callee_ea)
                elif callee.op == ida_hexrays.cot_var:
                    try:
                        lv = cfunc.lvars[callee.v.idx]
                        callee_name = str(getattr(lv, "name", "") or f"var_{callee.v.idx}")
                    except Exception:
                        callee_name = f"var_{callee.v.idx}"
                else:
                    try:
                        callee_name = ida_lines.tag_remove(callee.print1(None)) or ""
                    except Exception:
                        callee_name = ""
            args = []
            if expr.a:
                for i in range(expr.a.size()):
                    arg = expr.a.at(i)
                    arg_text = ""
                    try:
                        arg_text = ida_lines.tag_remove(arg.print1(None)) or ""
                    except Exception:
                        pass
                    args.append((arg, arg_text))
            return callee_name, callee_ea, args

        def _is_string_literal(self, arg_expr) -> bool:
            try:
                if arg_expr.op == ida_hexrays.cot_str:
                    return True
                if arg_expr.op == ida_hexrays.cot_ref and arg_expr.x:
                    if arg_expr.x.op == ida_hexrays.cot_obj:
                        ea = arg_expr.x.obj_ea
                        return idc.get_str_type(ea) is not None
            except Exception:
                pass
            return False

        def _get_string_content(self, arg_expr) -> str | None:
            """Extract actual string content from a string literal expression."""
            try:
                if arg_expr.op == ida_hexrays.cot_str:
                    return str(getattr(arg_expr, "string", "") or "")
                if arg_expr.op == ida_hexrays.cot_ref and arg_expr.x:
                    if arg_expr.x.op == ida_hexrays.cot_obj:
                        ea = arg_expr.x.obj_ea
                        s = idc.get_strlit_contents(ea, -1, 0)
                        if s:
                            return s.decode("utf-8", errors="replace")
            except Exception:
                pass
            return None

        def _is_constant(self, arg_expr) -> bool:
            try:
                if arg_expr.op in (ida_hexrays.cot_num, ida_hexrays.cot_float):
                    return True
                if arg_expr.op == ida_hexrays.cot_sizeof:
                    return True
                text = ida_lines.tag_remove(arg_expr.print1(None)) or ""
                if "sizeof" in text:
                    return True
            except Exception:
                pass
            return False

        def _get_numeric_value(self, arg_expr) -> int | None:
            """Extract numeric value from a constant expression."""
            try:
                if arg_expr.op == ida_hexrays.cot_num:
                    return int(arg_expr.n.value(0))
            except Exception:
                pass
            return None

        def _is_var_user_tainted(self, arg_expr) -> bool:
            try:
                if arg_expr.op == ida_hexrays.cot_var:
                    idx = arg_expr.v.idx
                    if idx < len(cfunc.lvars or []):
                        name = str(getattr(cfunc.lvars[idx], "name", "") or "")
                        typ = str(getattr(cfunc.lvars[idx], "type", "") or "")
                        is_arg = bool(getattr(cfunc.lvars[idx], "is_arg_var", False))
                        if is_arg and any(kw in typ.lower() for kw in ("char", "byte", "uint8", "void")):
                            return True
                        if any(kw in name.lower() for kw in ("recv", "read", "input", "buf", "data", "payload", "pkt", "msg")):
                            return True
                if arg_expr.op == ida_hexrays.cot_call:
                    callee, _, _ = self._get_call_info(arg_expr)
                    if any(src in callee for src in NETWORK_SOURCES):
                        return True
                # Check if it's a dereference of a tainted pointer
                if arg_expr.op == ida_hexrays.cot_ptr and arg_expr.x:
                    return self._is_var_user_tainted(arg_expr.x)
            except Exception:
                pass
            return False

        def _get_arg_size_hint(self, arg_expr) -> str | None:
            try:
                if self._is_constant(arg_expr):
                    return "constant"
                if arg_expr.op == ida_hexrays.cot_sizeof:
                    return "sizeof"
                text = ida_lines.tag_remove(arg_expr.print1(None)) or ""
                if "sizeof" in text or "strlen" in text:
                    return "computed"
                if arg_expr.op == ida_hexrays.cot_var:
                    idx = arg_expr.v.idx
                    if idx < len(cfunc.lvars or []):
                        name = str(getattr(cfunc.lvars[idx], "name", "") or "")
                        if any(kw in name.lower() for kw in ("size", "len", "length", "count", "sz")):
                            return "named_size_var"
            except Exception:
                pass
            return None

        def _check_format_specifiers(self, fmt_text: str, arg_count: int, ea: int):
            """Verify format string specifiers match argument count."""
            import re as _re
            # Count format specifiers (excluding %%)
            specifiers = _re.findall(r'%(?:(\d+)\$)?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?(?:hh?|ll?|[Lqjzt])?[diouxXeEfFgGaAcspn%]', fmt_text)
            # Remove %% (literal percent)
            real_specs = [s for s in specifiers if s != '%']
            n_specs = len(real_specs)
            # Account for format string itself being arg 0 for printf
            actual_args = arg_count  # args after format string
            if n_specs > 0 and actual_args < n_specs:
                findings.append({"severity": "high", "pattern": "format_arg_mismatch",
                                 "evidence": f"format has {n_specs} specifiers but {actual_args} args at {hex_ea(ea)}",
                                 "detail": "Fewer arguments than format specifiers — potential info leak or crash"})
            if '%n' in fmt_text:
                findings.append({"severity": "critical", "pattern": "format_string_write",
                                 "evidence": f"format string contains %n at {hex_ea(ea)}",
                                 "detail": "%n allows arbitrary write — format string exploitation"})

        def _check_call(self, expr):
            callee_name, callee_ea, args = self._get_call_info(expr)
            if not callee_name:
                return
            func = callee_name.split("::")[-1] if "::" in callee_name else callee_name
            func = func.split("(")[0].strip()
            ea = int(getattr(expr, "ea", idaapi.BADADDR))

            # Track all calls for return value checking
            call_eas.append((ea, func, expr))

            # --- Prototype check: does callee expect specific types? ---
            callee_tinfo = None
            callee_params = []
            if callee_ea and callee_ea != idaapi.BADADDR:
                try:
                    callee_tinfo = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(callee_tinfo, callee_ea):
                        func_data = ida_typeinf.func_type_data_t()
                        if callee_tinfo.get_func_details(func_data):
                            for i in range(func_data.size()):
                                pi = func_data[i]
                                callee_params.append({"name": str(getattr(pi, "name", "") or ""), "type": str(getattr(pi, "type", "") or "")})
                except Exception:
                    pass

            # --- Unbounded copy ---
            if func in UNBOUNDED_COPY:
                if func == "gets":
                    findings.append({"severity": "critical", "pattern": "gets_always_overflow",
                                     "evidence": f"{callee_name} at {hex_ea(ea)}",
                                     "detail": "gets() has no length limit — always exploitable"})
                elif func in ("strcpy", "lstrcpy"):
                    if args and self._is_user_tainted(args[0][0]):
                        findings.append({"severity": "critical", "pattern": "strcpy_user_input",
                                         "evidence": f"{callee_name}({args[0][1]}) at {hex_ea(ea)}",
                                         "detail": "strcpy from user-controlled source — buffer overflow"})
                    else:
                        findings.append({"severity": "high", "pattern": "strcpy_unbounded",
                                         "evidence": f"{callee_name} at {hex_ea(ea)}",
                                         "detail": "strcpy without length check — use strncpy/strlcpy"})
                elif func in ("strcat", "lstrcat"):
                    findings.append({"severity": "high", "pattern": "strcat_unbounded",
                                     "evidence": f"{callee_name} at {hex_ea(ea)}",
                                     "detail": "strcat appends without bounds — use strncat"})

            # --- Sized copy with unchecked size ---
            elif func in SIZED_COPY:
                if len(args) >= 3:
                    size_expr = args[2][0]
                    if not self._is_constant(size_expr) and not self._get_arg_size_hint(size_expr):
                        if self._is_user_tainted(size_expr):
                            findings.append({"severity": "critical", "pattern": "user_controlled_copy_size",
                                             "evidence": f"{callee_name} size: {args[2][1]} at {hex_ea(ea)}",
                                             "detail": "Copy size from user input — overflow via crafted size"})
                        else:
                            findings.append({"severity": "medium", "pattern": "unbounded_copy_size",
                                             "evidence": f"{callee_name} size: {args[2][1]} at {hex_ea(ea)}",
                                             "detail": "Size argument is not a constant or sizeof — verify bounds"})
                    # Type mismatch: check if dest/src types suggest different buffer sizes
                    if callee_params and len(callee_params) >= 2:
                        dest_type = callee_params[0].get("type", "").lower()
                        src_type = callee_params[1].get("type", "").lower()
                        if "char" in dest_type and "char" not in src_type and "void" not in src_type:
                            findings.append({"severity": "medium", "pattern": "type_mismatch_copy",
                                             "evidence": f"{callee_name} dest={dest_type} src={src_type} at {hex_ea(ea)}",
                                             "detail": "Source and destination have different types — size mismatch risk"})

            # --- Format string ---
            elif func in FORMAT_FUNCS:
                if func in ("printf", "fprintf", "dprintf", "syslog"):
                    if args:
                        fmt_arg = args[0][0]
                        if not self._is_string_literal(fmt_arg):
                            findings.append({"severity": "high", "pattern": "format_string_injection",
                                             "evidence": f"{callee_name} format: {args[0][1]} at {hex_ea(ea)}",
                                             "detail": "Format string is a variable — potential format string attack"})
                        else:
                            # Check actual format string content
                            fmt_content = self._get_string_content(fmt_arg)
                            if fmt_content:
                                self._check_format_specifiers(fmt_content, len(args) - 1, ea)
                if func == "sprintf":
                    findings.append({"severity": "high", "pattern": "sprintf_unbounded",
                                     "evidence": f"{callee_name} at {hex_ea(ea)}",
                                     "detail": "sprintf without size limit — use snprintf"})
                if func == "snprintf" and len(args) >= 2:
                    size_val = self._get_numeric_value(args[0][0])
                    if size_val is not None and size_val <= 0:
                        findings.append({"severity": "high", "pattern": "snprintf_zero_size",
                                         "evidence": f"snprintf size={size_val} at {hex_ea(ea)}",
                                         "detail": "snprintf with zero/negative size — undefined behavior"})

            # --- Command injection ---
            elif func in COMMAND_EXEC:
                if args:
                    cmd_arg = args[0][0]
                    if not self._is_string_literal(cmd_arg):
                        findings.append({"severity": "critical", "pattern": "command_injection",
                                         "evidence": f"{callee_name} cmd: {args[0][1]} at {hex_ea(ea)}",
                                         "detail": "Command string is a variable — potential command injection"})

            # --- Allocation with user-controlled size ---
            elif func in ALLOC_FUNCS:
                if args:
                    size_arg = args[0][0]
                    alloc_calls[ea] = func
                    if self._is_user_tainted(size_arg):
                        findings.append({"severity": "high", "pattern": "user_controlled_alloc_size",
                                         "evidence": f"{callee_name} size: {args[0][1]} at {hex_ea(ea)}",
                                         "detail": "Allocation size from user input — integer overflow or huge alloc DoS"})
                    elif not self._is_constant(size_arg):
                        text = ida_lines.tag_remove(size_arg.print1(None)) or ""
                        if "*" in text or "mul" in text.lower():
                            findings.append({"severity": "high", "pattern": "integer_overflow_alloc",
                                             "evidence": f"{callee_name} size: {text} at {hex_ea(ea)}",
                                             "detail": "Size computed by multiplication — check for integer overflow"})
                    # Check for zero-size allocation
                    size_val = self._get_numeric_value(size_arg)
                    if size_val is not None and size_val == 0:
                        findings.append({"severity": "medium", "pattern": "zero_alloc",
                                         "evidence": f"{callee_name} size=0 at {hex_ea(ea)}",
                                         "detail": "Zero-size allocation — implementation-defined behavior"})

            # --- Free: track for UAF ---
            elif func in FREE_FUNCS:
                if args:
                    free_arg = args[0][0]
                    try:
                        text = ida_lines.tag_remove(free_arg.print1(None)) or ""
                        freed_vars[text] = (ea, callee_name)
                    except Exception:
                        pass

            # --- Dangerous Windows combos ---
            if func == "WriteProcessMemory":
                findings.append({"severity": "high", "pattern": "process_injection_write",
                                 "evidence": f"{callee_name} at {hex_ea(ea)}",
                                 "detail": "WriteProcessMemory — process injection if targeting remote process"})
            if func in ("CreateRemoteThread", "NtCreateThreadEx"):
                findings.append({"severity": "critical", "pattern": "remote_thread_injection",
                                 "evidence": f"{callee_name} at {hex_ea(ea)}",
                                 "detail": "Remote thread creation — likely code injection"})

            # --- Prototype type mismatch: check if call args match expected types ---
            if callee_params and args:
                for i, (arg_expr, _arg_text) in enumerate(args[:len(callee_params)]):
                    expected_type = callee_params[i].get("type", "").lower()
                    if not expected_type:
                        continue
                    # Check: passing int where pointer expected
                    if "ptr" in expected_type or "*" in expected_type or "char" in expected_type:
                        if arg_expr.op == ida_hexrays.cot_num:
                            val = self._get_numeric_value(arg_expr)
                            if val is not None and val != 0 and val < 0x10000:
                                findings.append({"severity": "medium", "pattern": "int_as_pointer",
                                                 "evidence": f"{callee_name} arg[{i}]={val} expected {expected_type} at {hex_ea(ea)}",
                                                 "detail": "Small integer passed where pointer expected — likely bug"})

        def _is_user_tainted(self, arg_expr) -> bool:
            return self._is_var_user_tainted(arg_expr)

        def _check_assignment(self, expr):
            try:
                lhs = expr.x
                rhs = expr.y
                if lhs and lhs.op == ida_hexrays.cot_var:
                    idx = lhs.v.idx
                    if idx < len(cfunc.lvars or []):
                        name = str(getattr(cfunc.lvars[idx], "name", "") or "")
                        if rhs and rhs.op == ida_hexrays.cot_num and rhs.n.value(0) == 0:
                            freed_vars[name] = (int(getattr(expr, "ea", 0)), "assigned NULL")
            except Exception:
                pass

    try:
        v = VulnVisitor()
        v.apply_to(cfunc.body, None)
    except Exception:
        pass

    # --- UAF second pass ---
    class UAFChecker(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.found = []

        def visit_expr(self, expr):
            try:
                if expr.op == ida_hexrays.cot_var:
                    idx = expr.v.idx
                    if idx < len(cfunc.lvars or []):
                        name = str(getattr(cfunc.lvars[idx], "name", "") or "")
                        if name in freed_vars:
                            ea = int(getattr(expr, "ea", idaapi.BADADDR))
                            free_ea, free_name = freed_vars[name]
                            if ea != free_ea:
                                self.found.append({
                                    "severity": "critical", "pattern": "use_after_free",
                                    "evidence": f"var '{name}' used at {hex_ea(ea)} after {free_name} at {hex_ea(free_ea)}",
                                    "detail": f"Variable '{name}' was freed/NULL'd then used — use-after-free"
                                })
            except Exception:
                pass
            return 0

    if freed_vars:
        try:
            checker = UAFChecker()
            checker.apply_to(cfunc.body, None)
            findings.extend(checker.found[:3])
        except Exception:
            pass

    # --- Unchecked malloc: allocation result used without NULL check ---
    class UncheckedAllocChecker(ida_hexrays.ctree_visitor_t):
        """Detect alloc calls whose return value is never compared to NULL."""
        def __init__(self, alloc_eas):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.alloc_eas = set(alloc_eas)
            self.checked_eas = set()

        def visit_expr(self, expr):
            try:
                # Check for comparisons with NULL/0 that involve alloc results
                if expr.op in (ida_hexrays.cot_eq, ida_hexrays.cot_ne, ida_hexrays.cot_ule, ida_hexrays.cot_sle):
                    for side in (expr.x, expr.y):
                        if side and side.op == ida_hexrays.cot_call:
                            ea = int(getattr(side, "ea", 0))
                            if ea in self.alloc_eas:
                                self.checked_eas.add(ea)
            except Exception:
                pass
            return 0

    if alloc_calls:
        try:
            checker = UncheckedAllocChecker(alloc_calls.keys())
            checker.apply_to(cfunc.body, None)
            for ea, callee_name in alloc_calls.items():
                if ea not in checker.checked_eas:
                    findings.append({"severity": "high", "pattern": "unchecked_malloc",
                                     "evidence": f"{callee_name} at {hex_ea(ea)} return value not checked",
                                     "detail": "Allocation result not compared to NULL — NULL deref on OOM"})
        except Exception:
            pass

    # --- Inter-procedural analysis: check callers of this function ---
    if func_ea and func_ea != idaapi.BADADDR:
        try:
            # Check if function is called from network-facing code
            caller_funcs = set()
            for ref_ea in idautils.CodeRefsTo(func_ea, 0):
                caller_func = ida_funcs.get_func(ref_ea)
                if caller_func:
                    caller_name = ida_funcs.get_func_name(caller_func.start_ea) or ""
                    caller_funcs.add(caller_name)
            # If callers include network/socket functions, flag as network-reachable
            network_callers = [c for c in caller_funcs if any(kw in c.lower() for kw in ("recv", "socket", "handle", "dispatch", "process", "parse", "http", "tcp", "udp", "server"))]
            if network_callers and any(f["severity"] == "critical" for f in findings):
                findings.append({"severity": "critical", "pattern": "network_reachable_vuln",
                                 "evidence": f"function called from: {network_callers[:3]}",
                                 "detail": "Critical vuln is reachable from network-facing callers — high exploitability"})

            # Check if function is exported (external linkage)
            func_flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
            if func_flags is not None and func_flags & idaapi.FUNC_LIB:
                if any(f["severity"] in ("critical", "high") for f in findings):
                    findings.append({"severity": "high", "pattern": "library_func_with_vuln",
                                     "evidence": "function is a library/import function",
                                     "detail": "Vulnerability in library function — affects all callers across the binary"})
        except Exception:
            pass

    # --- Segment analysis: writable segments with executable permissions ---
    try:
        seg = ida_segment.getseg(func_ea)
        if seg:
            perms = int(getattr(seg, "perm", 0) or 0)
            # Check if code is in a writable segment (shellcode/ROP)
            if perms & idaapi.SEGPERM_WRITE and perms & idaapi.SEGPERM_EXEC:
                seg_name = ida_segment.get_segm_name(seg) or ""
                findings.append({"severity": "high", "pattern": "writable_executable_segment",
                                 "evidence": f"function in segment '{seg_name}' with W+X permissions",
                                 "detail": "Code in writable+executable segment — shellcode injection risk"})
    except Exception:
        pass

    # --- Check referenced strings for suspicious content ---
    try:
        class StringRefChecker(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.suspicious = []

            def visit_expr(self, expr):
                try:
                    if expr.op == ida_hexrays.cot_str:
                        s = str(getattr(expr, "string", "") or "")
                        self._check_string(s, int(getattr(expr, "ea", 0)))
                    elif expr.op == ida_hexrays.cot_ref and expr.x and expr.x.op == ida_hexrays.cot_obj:
                        ea = expr.x.obj_ea
                        s = idc.get_strlit_contents(ea, -1, 0)
                        if s:
                            self._check_string(s.decode("utf-8", errors="replace"), ea)
                except Exception:
                    pass
                return 0

            def _check_string(self, s, ea):
                sl = s.lower()
                # Hardcoded URLs/C2
                if any(proto in sl for proto in ("http://", "https://", "ftp://", "tcp://")):
                    self.suspicious.append({"severity": "medium", "pattern": "hardcoded_url",
                                            "evidence": f"'{s[:80]}' at {hex_ea(ea)}",
                                            "detail": "Hardcoded URL — potential C2 or data exfil endpoint"})
                # Hardcoded IPs
                import re as _re
                if _re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
                    self.suspicious.append({"severity": "medium", "pattern": "hardcoded_ip",
                                            "evidence": f"'{s[:80]}' at {hex_ea(ea)}",
                                            "detail": "Hardcoded IP address — potential C2 endpoint"})
                # Shell commands in strings
                if any(cmd in sl for cmd in ("/bin/sh", "cmd.exe", "powershell", "bash", "wget ", "curl ")):
                    self.suspicious.append({"severity": "high", "pattern": "shell_command_string",
                                            "evidence": f"'{s[:80]}' at {hex_ea(ea)}",
                                            "detail": "String contains shell command — potential command injection payload"})

        src = StringRefChecker()
        src.apply_to(cfunc.body, None)
        findings.extend(src.suspicious[:5])
    except Exception:
        pass

    # --- CFG path reachability: find all paths from entry to dangerous calls ---
    try:
        danger_eas = set()
        for f in findings:
            # Extract EA from evidence string
            import re as _re
            ea_match = _re.search(r'at (0x[0-9a-fA-F]+)', f.get("evidence", ""))
            if ea_match:
                try:
                    danger_eas.add(int(ea_match.group(1), 16))
                except ValueError:
                    pass
        if danger_eas and func_ea:
            # Build basic block map
            func = ida_funcs.get_func(func_ea)
            if func:
                fc = idaapi.FlowChart(func)
                bb_map = {}
                for _bb in fc:
                    bb_map[int(bb.start_ea)] = bb
                # Find which BBs contain dangerous calls
                danger_bbs = []
                for bb in fc:
                    for danger_ea in danger_eas:
                        if bb.start_ea <= danger_ea < bb.end_ea:
                            danger_bbs.append(bb)
                            break
                # Check if dangerous BBs are in loops (back-edge targets)
                for bb in danger_bbs:
                    for succ_bb in bb.succs():
                        if int(succ_bb.start_ea) <= int(bb.start_ea):
                            # Back edge → this BB is in a loop
                            findings.append({"severity": "high", "pattern": "danger_in_loop",
                                             "evidence": f"dangerous call at {hex_ea(int(bb.start_ea))} is in a loop body",
                                             "detail": "Vulnerable call is inside a loop — repeated exploitation possible, amplifies impact"})
                            break
                # Check if function has many BBs (complex → harder to audit)
                bb_count = len(list(fc))
                if bb_count > 20:
                    has_critical = any(f.get("severity") == "critical" for f in findings)
                    if has_critical:
                        findings.append({"severity": "medium", "pattern": "complex_func_with_vuln",
                                         "evidence": f"function has {bb_count} basic blocks with critical vulns",
                                         "detail": "Complex function with many branches — difficult to audit all paths, manual review recommended"})
    except Exception:
        pass

    # --- Stack frame analysis: large buffers, canary, frame pointer ---
    try:
        func_obj = ida_funcs.get_func(func_ea)
        if func_obj:
            frame = ida_funcs.get_frame(func_obj)
            if frame:
                frame_size = int(getattr(frame, "memqty", 0) or 0)
                # Check for large stack allocations
                for i in range(frame_size):
                    member = frame.get_member(i)
                    if member:
                        mname = ida_struct.get_member_name(member.id) or ""
                        msize = ida_struct.get_member_size(member)
                        # Large stack buffer
                        if msize > 256 and any(kw in mname.lower() for kw in ("buf", "buffer", "data", "tmp", "temp", "stack", "local")):
                            findings.append({"severity": "high", "pattern": "large_stack_buffer",
                                             "evidence": f"'{mname}' ({msize} bytes) in stack frame at {hex_ea(func_ea)}",
                                             "detail": f"Large stack buffer ({msize} bytes) — high risk of stack overflow if used with unbounded input"})
                        # Stack canary detection
                        if "canary" in mname.lower() or "cookie" in mname.lower() or "__stack_chk" in mname.lower():
                            findings.append({"severity": "low", "pattern": "stack_canary_present",
                                             "evidence": f"canary '{mname}' in stack frame at {hex_ea(func_ea)}",
                                             "detail": "Stack canary detected — overflow will be caught before return (if not bypassed)"})
                        # Sensitive field names in stack vars
                        if any(kw in mname.lower() for kw in ("password", "passwd", "secret", "key", "token", "credential")):
                            findings.append({"severity": "medium", "pattern": "sensitive_stack_var",
                                             "evidence": f"'{mname}' in stack frame at {hex_ea(func_ea)}",
                                             "detail": "Sensitive data in stack variable — may leak on stack overflow or memory dump"})
    except Exception:
        pass

    # --- Instruction-level analysis: check operand types at dangerous call sites ---
    try:
        import ida_ua
        danger_eas_for_insn = set()
        for f in findings:
            import re as _re
            ea_match = _re.search(r'at (0x[0-9a-fA-F]+)', f.get("evidence", ""))
            if ea_match:
                try:
                    danger_eas_for_insn.add(int(ea_match.group(1), 16))
                except ValueError:
                    pass
        for dea in list(danger_eas_for_insn)[:10]:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, dea):
                # Check if any operand references a stack variable directly
                for i in range(6):  # IDA supports up to 6 operands
                    op_type = idc.get_operand_type(dea, i)
                    if op_type is None or op_type == 0:
                        break
                    # o_displ = stack variable reference (e.g., [ebp-0x10])
                    if op_type == ida_ua.o_displ:
                        op_text = idc.print_operand(dea, i)
                        if op_text and ("ebp" in op_text or "rbp" in op_text or "sp" in op_text):
                            # This is a stack variable used in a dangerous call
                            pass  # Already caught by frame analysis
                    # o_mem = direct memory reference (global variable)
                    elif op_type == ida_ua.o_mem:
                        mem_ea = idc.get_operand_value(dea, i)
                        if mem_ea and mem_ea != idaapi.BADADDR:
                            # Check if global is writable
                            seg = ida_segment.getseg(mem_ea)
                            if seg and int(getattr(seg, "perm", 0) or 0) & idaapi.SEGPERM_WRITE:
                                seg_name = ida_segment.get_segm_name(seg) or ""
                                findings.append({"severity": "medium", "pattern": "global_writable_ref",
                                                 "evidence": f"operand references writable global at {hex_ea(mem_ea)} (seg '{seg_name}') from {hex_ea(dea)}",
                                                 "detail": "Dangerous call references writable global — TOCTOU or race condition risk"})
    except Exception:
        pass

    # --- ida_bytes: check actual bytes at function entry for known shellcode patterns ---
    try:
        func_bytes = ida_bytes.get_bytes(func_ea, 16)
        if func_bytes:
            # NOP sled detection
            if func_bytes[:4] == b'\x90\x90\x90\x90':
                findings.append({"severity": "critical", "pattern": "nop_sled",
                                 "evidence": f"function at {hex_ea(func_ea)} starts with NOP sled",
                                 "detail": "NOP sled at function entry — shellcode injection indicator"})
            # INT3 padding (debug trap / shellcode marker)
            if func_bytes[:4] == b'\xcc\xcc\xcc\xcc':
                findings.append({"severity": "medium", "pattern": "int3_padding",
                                 "evidence": f"function at {hex_ea(func_ea)} starts with INT3 padding",
                                 "detail": "INT3 padding at function entry — debug trap or shellcode marker"})
            # Common shellcode prologues
            shellcode_prologues = [
                (b"\x31\xc0", "xor eax, eax"),  # x86
                (b"\x48\x31\xc0", "xor rax, rax"),  # x64
                (b"\xfc", "cld"),  # x86 shellcode cld
                (b"\x6a\x00", "push 0"),  # x86 push null
            ]
            for pattern_bytes, desc in shellcode_prologues:
                if func_bytes[:len(pattern_bytes)] == pattern_bytes:
                    # Check if this is in a non-code section
                    seg = ida_segment.getseg(func_ea)
                    seg_name = ida_segment.get_segm_name(seg) if seg else ""
                    if seg_name and seg_name.lower() not in (".text", ".code", "CODE", "text"):
                        findings.append({"severity": "high", "pattern": "shellcode_in_data_seg",
                                         "evidence": f"function at {hex_ea(func_ea)} in segment '{seg_name}' starts with {desc}",
                                         "detail": "Shellcode-like prologue in non-code segment — likely injected code"})
    except Exception:
        pass

    # --- ida_xref: string xref analysis — find functions that reference suspicious strings ---
    try:
        # Collect all string EAs referenced by this function
        str_ref_eas = set()
        class StrRefCollector(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            def visit_expr(self, expr):
                try:
                    if expr.op == ida_hexrays.cot_ref and expr.x and expr.x.op == ida_hexrays.cot_obj:
                        ea = expr.x.obj_ea
                        if idc.get_str_type(ea) is not None:
                            str_ref_eas.add(ea)
                except Exception:
                    pass
                return 0
        collector = StrRefCollector()
        collector.apply_to(cfunc.body, None)
        # Check if suspicious strings are also referenced by other functions
        # (shared C2 infrastructure, shared exploit strings)
        for str_ea in list(str_ref_eas)[:5]:
            ref_count = 0
            ref_funcs = set()
            for xref_ea in idautils.XrefsTo(str_ea):
                xref_func = ida_funcs.get_func(xref_ea.frm)
                if xref_func and int(xref_func.start_ea) != func_ea:
                    ref_count += 1
                    ref_name = ida_funcs.get_func_name(xref_func.start_ea) or hex_ea(xref_func.start_ea)
                    ref_funcs.add(ref_name)
                    if ref_count >= 5:
                        break
            if ref_count > 0:
                s = idc.get_strlit_contents(str_ea, -1, 0)
                if s:
                    s_text = s.decode("utf-8", errors="replace")[:40]
                    # Check if it's a suspicious string
                    if any(kw in s_text.lower() for kw in ("http", "cmd", "shell", "exec", "admin", "root", "password", "key")):
                        findings.append({"severity": "medium", "pattern": "shared_suspicious_string",
                                         "evidence": f"string '{s_text}' at {hex_ea(str_ea)} referenced by {ref_count} other funcs: {list(ref_funcs)[:3]}",
                                         "detail": "Suspicious string shared across multiple functions — coordinated attack infrastructure"})
    except Exception:
        pass

    # --- Processor-specific checks ---
    try:
        proc_name = idaapi.get_inf_attr(idaapi.INF_PROCNAME) if hasattr(idaapi, 'get_inf_attr') else ""
        if not proc_name:
            proc_name = str(getattr(idaapi.inf, 'procname', '') or '')
        proc_lower = proc_name.lower()

        if "arm" in proc_lower or "thumb" in proc_lower:
            # ARM: check for interworking calls (BLX to data)
            # Check if function has BX LR (standard return) vs BX R14 (interworking)
            func_obj = ida_funcs.get_func(func_ea)
            if func_obj:
                fc = idaapi.FlowChart(func_obj)
                for bb in fc:
                    # Check last instruction of each BB
                    last_ea = int(bb.end_ea) - 4  # ARM instructions are 4 bytes (or 2 for Thumb)
                    if last_ea > int(bb.start_ea):
                        mnem = idc.print_insn_mnem(last_ea) or ""
                        if mnem in ("BLX", "BX"):
                            target = idc.get_operand_value(last_ea, 0)
                            if target and target != idaapi.BADADDR:
                                # Check if target is in a writable segment
                                seg = ida_segment.getseg(target)
                                if seg and int(getattr(seg, "perm", 0) or 0) & idaapi.SEGPERM_WRITE:
                                    findings.append({"severity": "high", "pattern": "arm_branch_to_writable",
                                                     "evidence": f"{mnem} to {hex_ea(target)} (writable) at {hex_ea(last_ea)}",
                                                     "detail": "ARM branch to writable memory — code execution hijack via buffer overflow"})

        elif "mips" in proc_lower:
            # MIPS: check for delay slot hazards
            func_obj = ida_funcs.get_func(func_ea)
            if func_obj:
                fc = idaapi.FlowChart(func_obj)
                for _bb in fc:
                    # Check if branch delay slot contains a dangerous instruction
                    for item_ea in idautils.FuncItems(func_ea):
                        mnem = idc.print_insn_mnem(item_ea) or ""
                        if mnem in ("JAL", "JALR", "JR"):
                            # Check next instruction (delay slot)
                            next_ea = idc.next_head(item_ea, idaapi.BADADDR)
                            if next_ea and next_ea != idaapi.BADADDR:
                                delay_mnem = idc.print_insn_mnem(next_ea) or ""
                                if delay_mnem in ("LW", "SW", "LB", "SB"):
                                    # Load/store in delay slot — can be exploited
                                    pass  # Too noisy to flag all of these
                                    break

        elif "x86" in proc_lower or "metapc" in proc_lower:
            # x86: check for segment override in dangerous calls
            func_obj = ida_funcs.get_func(func_ea)
            if func_obj:
                # Check if function uses FS/GS segment (SEH, TEB access)
                uses_seh = False
                for item_ea in idautils.FuncItems(func_ea):
                    mnem = idc.print_insn_mnem(item_ea) or ""
                    op0 = idc.print_operand(item_ea, 0) or ""
                    if "fs:" in op0 or "gs:" in op0:
                        uses_seh = True
                        break
                if uses_seh and any(f.get("severity") == "critical" for f in findings):
                    findings.append({"severity": "high", "pattern": "seh_with_vuln",
                                     "evidence": f"function uses FS/GS segment access at {hex_ea(func_ea)}",
                                     "detail": "Function uses SEH/TEB access and has critical vulns — SEH overwrite exploitation likely"})
    except Exception:
        pass

    # --- ida_name: demangle and check for known vulnerable patterns in names ---
    try:
        func_name = idc.get_func_name(func_ea) or ""
        demangled = ida_name.demangle_name(func_name, 0) if func_name else ""
        name_to_check = (demangled or func_name).lower()
        # Known vulnerable function families
        vuln_families = {
            "strcpy": "Use strncpy/strlcpy instead",
            "sprintf": "Use snprintf instead",
            "gets": "Never use gets() — always exploitable",
            "scanf": "Use fgets + sscanf with width limits",
            "vsprintf": "Use vsnprintf instead",
            "strcat": "Use strncat instead",
        }
        for vuln_name, advice in vuln_families.items():
            if vuln_name in name_to_check:
                # This function IS the vulnerable function (not calling it)
                findings.append({"severity": "high", "pattern": "vulnerable_function_name",
                                 "evidence": f"function name '{func_name}' contains '{vuln_name}' at {hex_ea(func_ea)}",
                                 "detail": f"Function is a known-vulnerable variant — {advice}"})
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["pattern"], f["evidence"][:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 99))
    return unique


def _detect_dangerous_patterns(found_apis: list[str], pseudo: str, *, detailed: bool = False, cfunc=None) -> list[dict]:
    """Detect vulnerability patterns using ctree AST analysis when available, text heuristics as fallback.

    Args:
        found_apis: List of API names found in the function.
        pseudo: Decompiled pseudocode text.
        detailed: If True, return structured dicts; if False, return flat strings.
        cfunc: IDA cfunc_t for AST-level analysis (preferred).
    """

    # Try ctree-based analysis first (uses IDA's actual AST)
    if cfunc is not None:
        ctree_findings = _scan_ctree_vulns(cfunc)
        if ctree_findings:
            if not detailed:
                return [f"{f['pattern']} — {f['detail'][:60]}" for f in ctree_findings]
            return ctree_findings

    # Fallback: text-based heuristics (when no cfunc available)
    import re as _re
    findings = []

    def _add(sev, pat, evidence, detail=""):
        findings.append({"severity": sev, "pattern": pat, "evidence": evidence[:120], "detail": detail})

    call_pat = _re.compile(r'(\w+)\s*\(([^)]*)\)', _re.MULTILINE)
    calls = [(m.group(1), m.group(2)) for m in call_pat.finditer(pseudo)]

    UNBOUNDED = {'strcpy', 'lstrcpy', 'strcat', 'lstrcat', 'gets', 'vsprintf'}
    COMMAND = {'system', 'popen', 'exec', 'execve', 'execl', 'execlp', 'execvp'}
    ALLOC = {'malloc', 'calloc', 'realloc', 'VirtualAlloc', 'HeapAlloc', 'mmap'}
    NETWORK = {'recv', 'recvfrom', 'recvmsg', 'read', 'fread', 'gets'}
    SINKS = {'memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf', 'system', 'exec', 'execve', 'popen'}

    for name, args in calls:
        if name in UNBOUNDED:
            sev = "critical" if name == "gets" else "high"
            _add(sev, f"{name}_unbounded", f"{name}({args})", f"{name} without bounds check")
        elif name in COMMAND and args and not args.strip().startswith('"'):
            _add("critical", "command_injection", f"{name}({args})", "Command string is a variable")
        elif name == 'sprintf':
            _add("high", "sprintf_unbounded", f"sprintf({args})", "Use snprintf instead")
        elif name in ALLOC and '*' in args:
            _add("high", "integer_overflow_alloc", f"{name}({args})", "Size involves multiplication")

    # Source-to-sink flow
    src_vars = set()
    snk_vars = set()
    for name, args in calls:
        if name in NETWORK:
            for a in args.split(','):
                a = a.strip()
                if a and not a.startswith('"'): src_vars.add(a)
        if name in SINKS:
            for a in args.split(','):
                a = a.strip()
                if a and not a.startswith('"'): snk_vars.add(a)
    shared = src_vars & snk_vars
    if shared:
        _add("critical", "source_to_sink_flow", f"vars={shared}", "Network input flows to dangerous sink")

    # TOCTOU
    if 'access' in found_apis or 'stat' in found_apis:
        if any(n in found_apis for n in ('open', 'fopen', 'CreateFile')):
            _add("medium", "toctou_race", "access/stat then open", "TOCTOU race condition")

    # Hardcoded secrets
    creds = _re.findall(r'(?:password|secret|api_key|token)\s*=\s*"([^"]+)"', pseudo, _re.IGNORECASE)
    if creds:
        _add("high", "hardcoded_secret", f"{len(creds)} credential(s)", "Hardcoded secrets in source")

    # Windows injection
    if 'VirtualAlloc' in found_apis and 'WriteProcessMemory' in found_apis:
        _add("high", "process_injection", "VirtualAlloc + WriteProcessMemory", "Classic injection pattern")
    if 'CreateRemoteThread' in found_apis:
        _add("critical", "remote_thread_injection", "CreateRemoteThread", "Remote thread creation")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 99))
    if not detailed:
        return [f"{f['pattern']} — {f['detail'][:60]}" for f in findings]
    return findings


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
    dangerous = _detect_dangerous_patterns(
        found_apis, pseudo, detailed=detailed_dangerous, cfunc=cfunc
    )
    var_hints = _extract_var_rename_hints(cfunc)
    ctx = gather_function_context(func_start_ea, max_refs=8)
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
        **ctx,
    }


def annotate_pseudocode(pseudo: str, func_ea: int, bb_context: list, dangerous: list, cfunc=None) -> str:
    """Inject inline annotations into pseudocode from BB findings, dangerous patterns, and IDA comments.

    Adds annotations as C comments above relevant lines:
    // [BB:category] title (confidence)
    // [DANGER] pattern description
    // [IDA:comment] original comment text
    """
    if not pseudo:
        return pseudo
    lines = pseudo.splitlines()
    annotated = []
    # Header annotations from BB context
    header_annos = []
    for entry in bb_context[:5]:
        cat = entry.get("category", "note")
        title = entry.get("title", "")
        conf = entry.get("confidence", 0.5)
        header_annos.append(f"  // [BB:{cat}] {title} (confidence: {conf})")
    for d in dangerous[:5]:
        if isinstance(d, dict):
            sev = d.get('severity', 'medium').upper()
            header_annos.append(f"  // [{sev}] {d.get('pattern', '')} — {d.get('detail', '')}")
        elif isinstance(d, str):
            header_annos.append(f"  // [DANGER] {d}")
    if header_annos:
        annotated.extend(header_annos)
        annotated.append("")
    # Try to get IDA comments for addresses in the function
    ida_comments = {}
    if cfunc:
        try:
            class CommentVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_insn(self, insn):
                    ea = int(getattr(insn, "ea", idaapi.BADADDR))
                    if ea and ea != idaapi.BADADDR:
                        cmt = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1) or ""
                        if cmt:
                            ida_comments[ea] = cmt
                    return 0
            v = CommentVisitor()
            v.apply_to(cfunc.body)
        except Exception:
            pass
    # Merge annotated lines
    for line in lines:
        annotated.append(line)
        # Try to find address references in the line to attach IDA comments
        addr_match = re.search(r'0x[0-9a-fA-F]+', line)
        if addr_match:
            addr_str = addr_match.group(0)
            try:
                addr_val = int(addr_str, 16)
                if addr_val in ida_comments:
                    annotated.append(f"    // [IDA] {ida_comments[addr_val]}")
            except ValueError:
                pass
    return "\n".join(annotated)


def _get_blackboard_context_for_addr(addr_hex: str) -> list:
    """
    Get relevant blackboard entries for this address without IDA deps.
    Returns compact list of {title, category, confidence}.
    """
    try:
        # Use blackboard directly (no IDA deps)
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
    include_comments: bool = False,
    annotate_branches: bool = False,
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
    # Branch/call annotation: resolve target name for flow instructions
    if annotate_branches:
        branch_anno = _annotate_branch_target(ea, text)
        if branch_anno:
            line = f"{line} ; -> {branch_anno}"
    # IDA comment overlay
    if include_comments:
        cmt = idc.get_cmt(ea, 0) or ""  # regular comment
        rcmt = idc.get_cmt(ea, 1) or ""  # repeatable comment
        comment_text = cmt or rcmt
        if comment_text:
            line = f"{line} ; // {comment_text}"
    if include_bytes:
        size = int(idc.get_item_size(ea) or 0)
        if size > 0:
            insn_bytes = " ".join(f"{ida_bytes.get_byte(ea + i):02x}" for i in range(min(size, 16)))
            line = f"{line} ; bytes={insn_bytes}"
    return line


def _annotate_branch_target(ea: int, text: str) -> str | None:
    """Resolve the target name for branch/call instructions."""
    try:
        mnem = idc.print_insn_mnem(ea) or ""
        if not mnem:
            return None
        # Only annotate flow-control instructions
        if not any(kw in mnem for kw in ("call", "jmp", "je", "jne", "jz", "jnz",
                                          "jg", "jl", "jge", "jle", "ja", "jb",
                                          "jae", "jbe", "jo", "jno", "js", "jns",
                                          "jp", "jnp", "jcxz", "jecxz", "jrcxz",
                                          "loop", "loope", "loopne", "b.", "bl", "bx",
                                          "ret", "br")):
            return None
        # Get operand value — IDA resolves the target for us
        target = idc.get_operand_value(ea, 0)
        if target in (0, idaapi.BADADDR):
            return None
        name = idc.get_name(target) or ""
        if name:
            return f"{name} ({hex_ea(target)})"
        return hex_ea(target)
    except Exception:
        return None


def _format_disasm_structured(ea: int) -> dict:
    """Return a single instruction as a structured dict."""
    raw = idc.generate_disasm_line(ea, 0) or ""
    text = ida_lines.tag_remove(raw) if raw else "<data>"
    mnem = idc.print_insn_mnem(ea) or ""
    operands = []
    for i in range(3):
        op = idc.print_operand(ea, i)
        if not op:
            break
        operands.append(op)
    result: dict[str, Any] = {
        "addr": hex_ea(ea),
        "mnem": mnem,
        "operands": operands,
        "text": text,
    }
    # Branch target
    if mnem and any(kw in mnem for kw in ("call", "jmp", "je", "jne", "jz", "jnz",
                                            "jg", "jl", "jge", "jle", "ja", "jb",
                                            "jae", "jbe", "jo", "jno", "js", "jns",
                                            "jp", "jnp", "loop", "b.", "bl", "bx", "br")):
        target = idc.get_operand_value(ea, 0)
        if target and target != idaapi.BADADDR:
            result["branch_target"] = hex_ea(target)
            name = idc.get_name(target) or ""
            if name:
                result["branch_name"] = name
    # IDA comments
    cmt = idc.get_cmt(ea, 0) or ""
    rcmt = idc.get_cmt(ea, 1) or ""
    if cmt or rcmt:
        result["comment"] = cmt or rcmt
    # Instruction bytes
    size = int(idc.get_item_size(ea) or 0)
    if size > 0:
        result["bytes"] = " ".join(f"{ida_bytes.get_byte(ea + i):02x}" for i in range(min(size, 16)))
    # Data references
    refs = []
    for i in range(idaapi.get_dref_cnt(ea)):
        dr = idaapi.get_dref(ea, i)
        if dr and dr != idaapi.BADADDR:
            name = idc.get_name(dr) or ""
            refs.append({"addr": hex_ea(dr), "name": name} if name else {"addr": hex_ea(dr)})
    if refs:
        result["data_refs"] = refs[:8]
    return result


def _disasm_range_structured(start_ea: int, stop_ea: int, max_items: int) -> list[dict]:
    """Return structured disassembly for a range."""
    items = []
    curr = start_ea
    count = 0
    hard_end = max(stop_ea, start_ea + 1)
    while curr < hard_end and count < max_items:
        items.append(_format_disasm_structured(curr))
        next_ea = idc.next_head(curr, hard_end)
        if next_ea == idaapi.BADADDR or next_ea <= curr:
            item_size = int(idc.get_item_size(curr) or 1)
            curr = curr + max(item_size, 1)
        else:
            curr = next_ea
        count += 1
    return items


def _disasm_range(
    start_ea: int,
    stop_ea: int,
    *,
    max_items: int,
    style: str,
    include_bytes: bool,
    include_comments: bool = False,
    annotate_branches: bool = False,
) -> list[str]:
    lines = []
    curr = start_ea
    count = 0
    hard_end = max(stop_ea, start_ea + 1)
    while curr < hard_end and count < max_items:
        lines.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes,
                                         include_comments=include_comments,
                                         annotate_branches=annotate_branches))
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
    include_comments: bool = False,
    annotate_branches: bool = False,
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
        before.append(_format_disasm_line(prev, style=style, include_bytes=include_bytes,
                                         include_comments=include_comments,
                                         annotate_branches=annotate_branches))
        curr = prev
        steps_back += 1
    before.reverse()

    after: list[str] = []
    curr = center_ea
    steps_fwd = 0
    while steps_fwd < radius:
        next_ea = idc.next_head(curr, idaapi.BADADDR)
        if next_ea == idaapi.BADADDR or next_ea <= curr:
            # Non-head aligned or end of address space — try advancing
            # by item size, but only format if we land on a valid head.
            item_size = int(idc.get_item_size(curr) or 1)
            item_size = max(item_size, 1)
            curr = curr + item_size
            if curr <= center_ea:
                continue
            # Verify we're on a valid instruction head before formatting
            check = idc.next_head(curr - 1, idaapi.BADADDR)
            if check != curr:
                break
            steps_fwd += 1
            after.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes,
                                             include_comments=include_comments,
                                             annotate_branches=annotate_branches))
            continue
        curr = next_ea
        if curr <= center_ea:
            continue
        steps_fwd += 1
        after.append(_format_disasm_line(curr, style=style, include_bytes=include_bytes,
                                         include_comments=include_comments,
                                         annotate_branches=annotate_branches))

    # center line itself (if it points at a head).
    center_line = _format_disasm_line(
        center_ea, style=style, include_bytes=include_bytes,
        include_comments=include_comments,
        annotate_branches=annotate_branches,
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
                func_data = ida_typeinf.func_type_data_t()
                if func_type.get_func_details(func_data):
                    arg_names = [
                        str(getattr(func_data[i], "name", "") or f"arg{i}")
                        for i in range(func_data.size())
                    ]
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
                    # depth is the number of hops from the target function:
                    # a direct caller of the target is depth 1, its callers 2, etc.
                    "depth": depth + 1,
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


def gather_function_context(func_ea: int, max_refs: int = 10) -> dict:
    """Gather compact inline context for a function: callers, callees, strings, xrefs."""
    ctx: dict[str, Any] = {}
    try:
        func = ida_funcs.get_func(func_ea)
        if not func:
            return ctx
        # Callers
        callers = []
        ref = idaapi.get_first_cref_to(func.start_ea)
        while ref and ref != idaapi.BADADDR and len(callers) < max_refs:
            caller_func = ida_funcs.get_func(ref)
            if caller_func:
                cname = ida_funcs.get_func_name(caller_func.start_ea) or hex_ea(caller_func.start_ea)
                if cname not in callers:
                    callers.append(cname)
            ref = idaapi.get_next_cref_to(func.start_ea, ref)
        if callers:
            ctx["callers"] = callers
        # Callees
        callees = []
        fii = idaapi.func_item_iterator_t(func)
        ea = fii.current()
        while ea != idaapi.BADADDR and len(callees) < max_refs:
            cref = idaapi.get_first_cref_from(ea)
            while cref and cref != idaapi.BADADDR and len(callees) < max_refs:
                callee_func = ida_funcs.get_func(cref)
                if callee_func and callee_func.start_ea != func.start_ea:
                    cname = ida_funcs.get_func_name(callee_func.start_ea) or hex_ea(callee_func.start_ea)
                    if cname not in callees:
                        callees.append(cname)
                cref = idaapi.get_next_cref_from(ea, cref)
            if not fii.next_code():
                break
            ea = fii.current()
        if callees:
            ctx["callees"] = callees
        # String references in function
        strings = []
        fii2 = idaapi.func_item_iterator_t(func)
        ea2 = fii2.current()
        while ea2 != idaapi.BADADDR and len(strings) < max_refs:
            dref = idaapi.get_first_dref_from(ea2)
            while dref and dref != idaapi.BADADDR and len(strings) < max_refs:
                s = idc.get_strlit_contents(dref, -1, 0)
                if s:
                    text = s.decode("utf-8", errors="replace")[:80]
                    if text not in strings:
                        strings.append(text)
                dref = idaapi.get_next_dref_from(ea2, dref)
            if not fii2.next_code():
                break
            ea2 = fii2.current()
        if strings:
            ctx["strings"] = strings
        # Complexity
        ctx["complexity"] = _compute_cfg_semantics(func)
    except Exception:
        pass
    return ctx


# ============================================================================
# CUSTOM DETECTOR ENGINE — LLM-defined per-session detection rules
# ============================================================================

# Session-scoped detector registry
_CUSTOM_DETECTORS: dict[str, dict] = {}


def register_detector(name: str, rule: dict) -> dict:
    """Register a custom detection rule. Returns the registered rule."""
    _CUSTOM_DETECTORS[name.lower()] = rule
    return {"ok": True, "name": name, "rule": rule}


def list_detectors() -> list[dict]:
    """List all registered custom detectors."""
    return [{"name": k, **v} for k, v in _CUSTOM_DETECTORS.items()]


def delete_detector(name: str) -> bool:
    """Delete a custom detector. Returns True if existed."""
    return _CUSTOM_DETECTORS.pop(name.lower(), None) is not None


def _run_custom_detector(kwargs: dict, max_items: int) -> dict:
    """Execute a custom detection rule defined by the LLM at runtime.

    Supported rule types:
    - api_chain: find functions calling APIs in sequence (e.g., recv then memcpy)
    - string_ref: find functions referencing a specific string
    - type_match: find functions with a parameter matching a type pattern
    - xor_threshold: find functions with XOR operations above a threshold
    - caller_of: find functions called by a specific function
    - callee_of: find functions that call a specific function
    - custom_ctree: run a ctree visitor with user-defined conditions
    """
    rule_type = str(kwargs.get("rule_type") or kwargs.get("detect") or "").strip().lower()
    rule_name = str(kwargs.get("rule_name") or kwargs.get("name") or "").strip()

    # Handle registration
    if kwargs.get("register"):
        rule = kwargs.get("rule") or kwargs
        if isinstance(rule, dict):
            return register_detector(rule_name or rule_type, rule)
        return make_error(MCPError.INVALID_ARGS, "rule must be a dict")

    # Handle list/delete
    if kwargs.get("list_detectors") or rule_type == "list":
        return {"ok": True, "detectors": list_detectors()}
    if kwargs.get("delete_detector") or rule_type == "delete":
        if not rule_name:
            return make_error(MCPError.INVALID_ARGS, "name required to delete detector")
        deleted = delete_detector(rule_name)
        return {"ok": True, "deleted": deleted, "name": rule_name}

    # Look up registered detector or use inline rule
    detector = _CUSTOM_DETECTORS.get(rule_name) if rule_name else None
    if detector and not rule_type:
        rule_type = detector.get("type", "")
        kwargs = {**detector, **kwargs}  # merge: registered defaults + call overrides

    if not rule_type:
        return make_error(MCPError.INVALID_ARGS,
                          "rule_type or detect required",
                          hint="Types: api_chain, string_ref, type_match, xor_threshold, caller_of, callee_of, custom_ctree")

    # --- api_chain: find functions calling APIs in order ---
    if rule_type == "api_chain":
        apis = kwargs.get("apis") or kwargs.get("chain") or []
        if isinstance(apis, str):
            apis = [a.strip() for a in apis.split(",")]
        if not apis:
            return make_error(MCPError.INVALID_ARGS, "apis list required (e.g., ['recv', 'memcpy'])")
        strict_order = bool(kwargs.get("strict_order", True))
        results = _detect_api_chains(apis, strict_order=strict_order, max_items=max_items)
        return {"ok": True, "rule_type": "api_chain", "apis": apis, "strict_order": strict_order,
                "matches": results, "count": len(results)}

    # --- string_ref: find functions referencing a specific string ---
    elif rule_type == "string_ref":
        pattern = str(kwargs.get("pattern") or kwargs.get("string") or "").strip()
        if not pattern:
            return make_error(MCPError.INVALID_ARGS, "pattern required")
        results = _detect_string_refs(pattern, max_items=max_items)
        return {"ok": True, "rule_type": "string_ref", "pattern": pattern,
                "matches": results, "count": len(results)}

    # --- type_match: find functions with parameter matching type ---
    elif rule_type == "type_match":
        type_pattern = str(kwargs.get("type_pattern") or kwargs.get("type") or "").strip()
        if not type_pattern:
            return make_error(MCPError.INVALID_ARGS, "type_pattern required (e.g., 'SOCKET', 'char *')")
        results = _detect_type_matches(type_pattern, max_items=max_items)
        return {"ok": True, "rule_type": "type_match", "type_pattern": type_pattern,
                "matches": results, "count": len(results)}

    # --- xor_threshold: find functions with XOR above threshold ---
    elif rule_type == "xor_threshold":
        threshold = int(kwargs.get("threshold", 4) or 4)
        results = _detect_xor_heavy(threshold=threshold, max_items=max_items)
        return {"ok": True, "rule_type": "xor_threshold", "threshold": threshold,
                "matches": results, "count": len(results)}

    # --- caller_of: find functions called by target ---
    elif rule_type == "caller_of":
        target = str(kwargs.get("target") or kwargs.get("function") or "").strip()
        if not target:
            return make_error(MCPError.INVALID_ARGS, "target function required")
        results = _detect_callers_of(target, max_items=max_items)
        return {"ok": True, "rule_type": "caller_of", "target": target,
                "matches": results, "count": len(results)}

    # --- callee_of: find functions that call target ---
    elif rule_type == "callee_of":
        target = str(kwargs.get("target") or kwargs.get("function") or "").strip()
        if not target:
            return make_error(MCPError.INVALID_ARGS, "target function required")
        results = _detect_callees_of(target, max_items=max_items)
        return {"ok": True, "rule_type": "callee_of", "target": target,
                "matches": results, "count": len(results)}

    return make_error(MCPError.INVALID_ARGS,
                      f"Unknown rule_type: {rule_type}",
                      hint="Types: api_chain, string_ref, type_match, xor_threshold, caller_of, callee_of")


def _detect_api_chains(apis: list[str], *, strict_order: bool = True, max_items: int = 100) -> list[dict]:
    """Find functions that call APIs in the given sequence using ctree traversal."""
    matches = []
    seen = set()

    class ChainCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self, chain_list):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self._chain = chain_list
        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call:
                callee = expr.x
                if callee and callee.op == ida_hexrays.cot_obj:
                    name = idc.get_name(callee.obj_ea) or ""
                    if name:
                        self._chain.append(name)
            return 0

    for func_ea in _iter_all_functions():
        if len(matches) >= max_items:
            break
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                continue
            call_chain = []
            collector = ChainCollector(call_chain)
            collector.apply_to(cfunc.body, None)

            # Check if APIs appear in order
            if strict_order:
                idx = 0
                for api in apis:
                    found = False
                    while idx < len(call_chain):
                        if api in call_chain[idx]:
                            found = True
                            idx += 1
                            break
                        idx += 1
                    if not found:
                        break
                else:
                    # All APIs found in order
                    fname = idc.get_func_name(func_ea) or hex_ea(func_ea)
                    if fname not in seen:
                        seen.add(fname)
                        matches.append({"addr": hex_ea(func_ea), "name": fname, "call_chain": call_chain[:20]})
            else:
                # Any order
                chain_set = set(call_chain)
                if all(any(api in c for c in chain_set) for api in apis):
                    fname = idc.get_func_name(func_ea) or hex_ea(func_ea)
                    if fname not in seen:
                        seen.add(fname)
                        matches.append({"addr": hex_ea(func_ea), "name": fname, "call_chain": call_chain[:20]})
        except Exception:
            continue
    return matches


def _detect_string_refs(pattern: str, *, max_items: int = 100) -> list[dict]:
    """Find functions that reference strings matching a pattern."""
    import re as _re
    matches = []
    seen = set()
    try:
        rx = _re.compile(pattern, _re.IGNORECASE)
    except _re.error:
        rx = _re.compile(_re.escape(pattern), _re.IGNORECASE)

    try:
        strings_iter = idautils.Strings()
    except Exception:
        strings_iter = None
    if strings_iter is None:
        return matches

    # Search all string literals in the binary
    for s_obj in strings_iter:
        if len(matches) >= max_items:
            break
        try:
            content = str(s_obj)
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
        except Exception:
            continue
        if not rx.search(content):
            continue
        s_ea = int(getattr(s_obj, "ea", 0) or 0)
        if not s_ea:
            continue
        # Find functions referencing this string
        for xref_ea in idautils.XrefsTo(s_ea):
            func = ida_funcs.get_func(xref_ea.frm)
            if func:
                fname = ida_funcs.get_func_name(func.start_ea) or hex_ea(func.start_ea)
                if fname in seen:
                    continue
                seen.add(fname)
                matches.append({"addr": hex_ea(func.start_ea), "name": fname,
                                "string": content[:80], "string_addr": hex_ea(s_ea)})
                if len(matches) >= max_items:
                    return matches
    return matches


def _detect_type_matches(type_pattern: str, *, max_items: int = 100) -> list[dict]:
    """Find functions with parameters matching a type pattern."""
    import re as _re
    matches = []
    try:
        rx = _re.compile(type_pattern, _re.IGNORECASE)
    except _re.error:
        rx = _re.compile(_re.escape(type_pattern), _re.IGNORECASE)

    for func_ea in _iter_all_functions():
        if len(matches) >= max_items:
            break
        try:
            tinfo = ida_typeinf.tinfo_t()
            if not ida_nalt.get_tinfo(tinfo, func_ea):
                continue
            func_data = ida_typeinf.func_type_data_t()
            if not tinfo.get_func_details(func_data):
                continue
            for i in range(func_data.size()):
                pi = func_data[i]
                param_type = str(getattr(pi, "type", "") or "")
                if rx.search(param_type):
                    fname = idc.get_func_name(func_ea) or hex_ea(func_ea)
                    matches.append({"addr": hex_ea(func_ea), "name": fname,
                                    "param_idx": i, "param_name": str(getattr(pi, "name", "") or ""),
                                    "param_type": param_type, "matched": type_pattern})
                    break
        except Exception:
            continue
    return matches


def _detect_xor_heavy(*, threshold: int = 4, max_items: int = 100) -> list[dict]:
    """Find functions with XOR operations above a threshold (crypto indicator)."""
    matches = []
    for func_ea in _iter_all_functions():
        if len(matches) >= max_items:
            break
        try:
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            xor_count = 0
            for item_ea in idautils.FuncItems(func.start_ea):
                mnem = idc.print_insn_mnem(item_ea) or ""
                if mnem.upper() in ("XOR", "EOR", "XORI"):
                    xor_count += 1
            if xor_count >= threshold:
                fname = idc.get_func_name(func_ea) or hex_ea(func_ea)
                matches.append({"addr": hex_ea(func_ea), "name": fname, "xor_count": xor_count})
        except Exception:
            continue
    return matches


def _detect_callers_of(target: str, *, max_items: int = 100) -> list[dict]:
    """Find functions called BY the target function (callees)."""
    # Resolve target to EA
    target_ea = idc.get_name_ea_simple(target)
    if target_ea == idaapi.BADADDR:
        # Try with common prefixes
        for prefix in ("_", "__", ""):
            target_ea = idc.get_name_ea_simple(prefix + target)
            if target_ea != idaapi.BADADDR:
                break
    if target_ea == idaapi.BADADDR:
        return []

    func = ida_funcs.get_func(target_ea)
    if not func:
        return []

    matches = []
    seen = set()
    for item_ea in idautils.FuncItems(func.start_ea):
        for ref_ea in idautils.CodeRefsFrom(item_ea, 0):
            callee_func = ida_funcs.get_func(ref_ea)
            if callee_func and callee_func.start_ea != func.start_ea:
                cname = idc.get_func_name(callee_func.start_ea) or hex_ea(callee_func.start_ea)
                if cname not in seen:
                    seen.add(cname)
                    matches.append({"addr": hex_ea(callee_func.start_ea), "name": cname})
                    if len(matches) >= max_items:
                        return matches
    return matches


def _detect_callees_of(target: str, *, max_items: int = 100) -> list[dict]:
    """Find functions that CALL the target function (callers)."""
    target_ea = idc.get_name_ea_simple(target)
    if target_ea == idaapi.BADADDR:
        for prefix in ("_", "__", ""):
            target_ea = idc.get_name_ea_simple(prefix + target)
            if target_ea != idaapi.BADADDR:
                break
    if target_ea == idaapi.BADADDR:
        return []

    matches = []
    seen = set()
    for ref_ea in idautils.CodeRefsTo(target_ea, 0):
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func:
            fname = idc.get_func_name(caller_func.start_ea) or hex_ea(caller_func.start_ea)
            if fname not in seen:
                seen.add(fname)
                matches.append({"addr": hex_ea(caller_func.start_ea), "name": fname})
                if len(matches) >= max_items:
                    return matches
    return matches


def _iter_all_functions():
    """Iterate over all function EAs in the binary."""
    ea = _get_next_func(0)
    while ea is not None:
        # IDA 9.x get_next_func returns an EA; older bindings may return a
        # func_t object — normalize both to an int EA.
        start = ea if isinstance(ea, int) else int(getattr(ea, "start_ea", idaapi.BADADDR))
        if start == idaapi.BADADDR:
            break
        yield start
        ea = _get_next_func(start)
