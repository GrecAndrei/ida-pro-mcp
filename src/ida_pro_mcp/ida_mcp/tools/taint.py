
import re

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 38. TAINT - Static Taint/Data Flow Analysis (Enhanced)
# ============================================================================

# --- Constants and Patterns ---
DANGEROUS_SINKS = {
    "network": ["send", "recv", "connect", "WSA", "accept", "http", "curl"],
    "exec": ["system", "exec", "popen", "ShellExecute", "CreateProcess", "eval"],
    "mem": ["VirtualAlloc", "VirtualProtect", "mmap", "mprotect", "memcpy", "strcpy", "gets"],
    "file": ["CreateFile", "ReadFile", "WriteFile", "fopen", "open"],
    "crypto": ["MD5", "SHA1", "DES", "RC4", "rand"],
}

SANITIZER_PATTERNS = {
    "length_check": ["strlen", "len", "size", "length", "count", "sizeof"],
    "bounds_check": ["<", ">", "<=", ">=", "==", "min", "max", "clamp", "range"],
    "encoding": ["encode", "decode", "escape", "urlencode", "htmlentities", "sanitize"],
    "null_term": ["strncpy", "snprintf", "strlcpy"],
    "whitelist": ["isalnum", "isdigit", "isalpha", "regex", "match", "validate"],
}

STRUCT_FIELD_PATTERN = re.compile(r'->([a-zA-Z_]\w*)|\.(\w+)')


def _is_sink_name(name: str) -> tuple:
    """Check if a function name matches a dangerous sink category."""
    if not name:
        return None
    name_lower = name.lower()
    for cat, patterns in DANGEROUS_SINKS.items():
        for p in patterns:
            if p.lower() in name_lower:
                return cat
    return None


def _is_sanitizer_call(name: str) -> tuple:
    """Check if a function name looks like a sanitizer/validator."""
    if not name:
        return None
    name_lower = name.lower()
    for cat, patterns in SANITIZER_PATTERNS.items():
        for p in patterns:
            if p.lower() in name_lower:
                return cat
    return None


def _collect_callers(func_ea, max_depth=3, max_results=50):
    """BFS up the call graph to find callers of a function."""
    visited = set()
    callers = []
    queue = [(func_ea, 0)]
    while queue and len(callers) < max_results:
        curr, d = queue.pop(0)
        if curr in visited or d >= max_depth:
            continue
        visited.add(curr)
        for xref in idautils.XrefsTo(curr):
            if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.append((xref.frm, caller_func.start_ea, d))
                    queue.append((caller_func.start_ea, d + 1))
    return callers


def _collect_callees(func_ea, max_depth=3, max_results=50):
    """BFS down the call graph to find callees from a function."""
    visited = set()
    callees = []
    queue = [(func_ea, 0)]
    while queue and len(callees) < max_results:
        curr, d = queue.pop(0)
        if curr in visited or d >= max_depth:
            continue
        visited.add(curr)
        func = ida_funcs.get_func(curr)
        if not func:
            continue
        for item in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item, 0):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                    name = idc.get_name(xref.to)
                    if name:
                        callees.append((item, xref.to, name, d))
                        if len(callees) >= max_results:
                            return callees
                    if xref.to not in visited:
                        queue.append((xref.to, d + 1))
    return callees


def _decompile_or_error(ea, action_name=""):
    """Helper to decompile a function with actionable error messages."""
    if not ida_hexrays.init_hexrays_plugin():
        hint = "Ensure Hex-Rays decompiler is installed and licensed. Try Edit -> Plugins -> Hex-Rays."
        return None, make_error(MCPError.IDA_ERROR, f"Decompiler required{f' for {action_name}' if action_name else ''}. {hint}")
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        hint = "Function may be thunk, data, or have incomplete function boundaries. Try forcing a function (Edit -> Functions -> Create function)."
        return None, make_error(MCPError.IDA_ERROR, f"Decompilation failed{f' for {action_name}' if action_name else ''}. {hint}")
    return cfunc, None


def _get_arg_by_name_or_index(cfunc, arg_num=0, arg_name=None):
    """Get argument lvar by index or name."""
    args = [v for v in cfunc.lvars if v.is_arg_var]
    if arg_name:
        for a in args:
            if a.name == arg_name:
                return a
        return None
    if arg_num >= len(args):
        return None
    return args[arg_num]


# --- CTree Visitors for Semantic Analysis ---

class TaintVisitor(ida_hexrays.ctree_visitor_t):
    """Base visitor that collects expressions matching a variable/field."""
    def __init__(self, cfunc, target_name, track_fields=False):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.target_name = target_name
        self.track_fields = track_fields
        self.matches = []
        self.calls = []
        self.assigns = []
        self.fields_accessed = set()

    def _match_expr(self, e):
        """Check if expression refers to target variable or its fields."""
        if e.op == ida_hexrays.cot_var:
            try:
                v = self.cfunc.lvars[e.v.idx]
                if v.name == self.target_name:
                    return True
            except Exception:
                pass
        elif self.track_fields and e.op in (ida_hexrays.cot_memref, ida_hexrays.cot_memptr):
            text = ida_lines.tag_remove(e.print1(None))
            if self.target_name in text:
                m = STRUCT_FIELD_PATTERN.search(text)
                if m:
                    field = m.group(1) or m.group(2)
                    if field:
                        self.fields_accessed.add(field)
                return True
        return False

    def visit_expr(self, e):
        if self._match_expr(e):
            text = ida_lines.tag_remove(e.print1(None))
            self.matches.append((e.ea, text))
        if e.op == ida_hexrays.cot_call:
            func_expr = e.x
            if func_expr.op == ida_hexrays.cot_obj:
                name = idc.get_name(func_expr.obj_ea)
            else:
                name = ida_lines.tag_remove(func_expr.print1(None))
            args_text = []
            arg = e.a
            while arg:
                a0 = arg[0]
                args_text.append(ida_lines.tag_remove(a0.print1(None)))
                arg = arg[1:]
            self.calls.append((e.ea, name, args_text))
        return 0

    def visit_insn(self, i):
        if i.op == ida_hexrays.cit_expr and i.cexpr.op == ida_hexrays.cot_asg:
            lhs = i.cexpr.x
            rhs = i.cexpr.y
            if self._match_expr(lhs):
                self.assigns.append((i.ea, "assign", ida_lines.tag_remove(rhs.print1(None))))
            elif self._match_expr(rhs):
                self.assigns.append((i.ea, "used", ida_lines.tag_remove(lhs.print1(None))))
        elif i.op == ida_hexrays.cit_if:
            cond_text = ida_lines.tag_remove(i.cif.expr.print1(None))
            if self.target_name in cond_text:
                self.assigns.append((i.ea, "branch", cond_text))
        return 0


class CrossFuncTaintVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor that finds cross-function data flow (arguments passed to callees)."""
    def __init__(self, cfunc, target_name):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.target_name = target_name
        self.arg_passes = []  # (call_ea, callee_name, arg_index, arg_text)
        self.return_flows = []  # (ea, text)

    def _matches_target(self, e):
        text = ida_lines.tag_remove(e.print1(None))
        return self.target_name in text

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            func_expr = e.x
            callee = None
            if func_expr.op == ida_hexrays.cot_obj:
                callee = idc.get_name(func_expr.obj_ea)
            args = []
            arg = e.a
            idx = 0
            while arg:
                a0 = arg[0]
                a_text = ida_lines.tag_remove(a0.print1(None))
                if self._matches_target(a0):
                    self.arg_passes.append((e.ea, callee, idx, a_text))
                args.append(a_text)
                arg = arg[1:]
                idx += 1
        elif e.op == ida_hexrays.cot_var:
            try:
                v = self.cfunc.lvars[e.v.idx]
                if v.name == self.target_name:
                    parent = self.parent_expr()
                    if parent and parent.op == ida_hexrays.cot_asg and parent.y == e:
                        self.return_flows.append((e.ea, ida_lines.tag_remove(parent.x.print1(None))))
            except Exception:
                pass
        return 0


class SanitizerVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor that detects validation/sanitization patterns on target variable."""
    def __init__(self, cfunc, target_name):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.target_name = target_name
        self.checks = []
        self.sanitizer_calls = []

    def _contains_target(self, e):
        text = ida_lines.tag_remove(e.print1(None))
        return self.target_name in text

    def visit_insn(self, i):
        if i.op == ida_hexrays.cit_if:
            cond = i.cif.expr
            if self._contains_target(cond):
                text = ida_lines.tag_remove(cond.print1(None))
                check_type = "generic"
                if any(op in text for op in ["<", ">", "<=", ">=", "==", "!="]):
                    check_type = "bounds_check"
                elif any(p in text.lower() for p in SANITIZER_PATTERNS["whitelist"]):
                    check_type = "whitelist"
                elif any(p in text.lower() for p in SANITIZER_PATTERNS["length_check"]):
                    check_type = "length_check"
                self.checks.append((i.ea, check_type, text))
        elif i.op == ida_hexrays.cit_expr and i.cexpr.op == ida_hexrays.cot_call:
            func_expr = i.cexpr.x
            name = None
            if func_expr.op == ida_hexrays.cot_obj:
                name = idc.get_name(func_expr.obj_ea)
            if name:
                san_cat = _is_sanitizer_call(name)
                if san_cat:
                    arg = i.cexpr.a
                    while arg:
                        if self._contains_target(arg[0]):
                            self.sanitizer_calls.append((i.ea, san_cat, name))
                            break
                        arg = arg[1:]
        return 0


# --- Core Helpers ---

def _find_sinks_in_function(func_ea, max_results=50):
    sinks = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return sinks
    for item in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item, 0):
            if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                name = idc.get_name(xref.to)
                cat = _is_sink_name(name)
                if cat:
                    sinks.append((item, cat, name, xref.to))
                    if len(sinks) >= max_results:
                        return sinks
    return sinks


def _trace_variable_in_function(cfunc, target_name, track_fields=False):
    """Trace a variable within a single function using ctree visitor."""
    visitor = TaintVisitor(cfunc, target_name, track_fields=track_fields)
    visitor.apply_to(cfunc.body, None)
    return visitor


def _forward_taint_bfs(start_ea, source_name, max_depth=5, max_hits=50, track_fields=False):
    """Cross-function forward taint from a source variable."""
    visited_funcs = set()
    results = []
    queue = [(start_ea, source_name, 0, [])]

    while queue and len(results) < max_hits:
        curr_ea, var_name, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        func = ida_funcs.get_func(curr_ea)
        if not func:
            continue
        if func.start_ea in visited_funcs:
            continue
        visited_funcs.add(func.start_ea)

        cfunc, err = _decompile_or_error(func.start_ea)
        if err:
            continue

        visitor = _trace_variable_in_function(cfunc, var_name, track_fields=track_fields)
        func_name = idc.get_func_name(func.start_ea)
        local_path = path + [(func_name, var_name)]

        # Record sinks in this function
        for cat, patterns in DANGEROUS_SINKS.items():
            for m in visitor.matches:
                _, text = m
                if any(p.lower() in text.lower() for p in patterns):
                    results.append({
                        "function": func_name,
                        "ea": hex(m[0]),
                        "sink_category": cat,
                        "context": text,
                        "depth": depth,
                        "path": " -> ".join(f"{p[0]}({p[1]})" for p in local_path),
                    })
                    if len(results) >= max_hits:
                        return results

        # Follow into callees where variable is passed as argument
        cross_visitor = CrossFuncTaintVisitor(cfunc, var_name)
        cross_visitor.apply_to(cfunc.body, None)
        for call_ea, callee_name, arg_idx, arg_text in cross_visitor.arg_passes:
            if callee_name:
                callee_ea = idc.get_name_ea_simple(callee_name)
                if callee_ea != idaapi.BADADDR and callee_ea not in visited_funcs:
                    # Determine param name in callee
                    callee_cfunc, _ = _decompile_or_error(callee_ea)
                    next_var = var_name
                    if callee_cfunc:
                        callee_args = [v for v in callee_cfunc.lvars if v.is_arg_var]
                        if arg_idx < len(callee_args):
                            next_var = callee_args[arg_idx].name
                    queue.append((callee_ea, next_var, depth + 1, local_path))

    return results


def _interprocedural_slice(start_ea, arg_num=0, arg_name=None, max_depth=3, max_hits=50, track_fields=False):
    """Build interprocedural slice from source to sinks across call graph."""
    cfunc, err = _decompile_or_error(start_ea, "cross_function_slice")
    if err:
        return None, err

    arg = _get_arg_by_name_or_index(cfunc, arg_num, arg_name)
    if not arg:
        hint = f"Function has {len([v for v in cfunc.lvars if v.is_arg_var])} arguments. Use arg_name=\"...\" to specify by name."
        return None, make_error(MCPError.INVALID_ARGS, f"Invalid argument index/name. {hint}")

    target_name = arg.name
    forward_results = _forward_taint_bfs(start_ea, target_name, max_depth, max_hits, track_fields)
    return forward_results, None


@tool
@idaread
def taint(
    action: Annotated[Literal[
        "find_arg_usage", "trace_return", "find_sinks", "data_flow",
        "backward_trace", "slice", "forward_trace", "cross_function_slice",
        "sanitize_check"
    ], "Action: find_arg_usage|trace_return|find_sinks|data_flow|backward_trace|slice|forward_trace|cross_function_slice|sanitize_check"],
    addr: Annotated[Optional[str], "Function or instruction address"] = None,
    arg_num: Annotated[int, "Argument number to trace (0-indexed)"] = 0,
    arg_name: Annotated[Optional[str], "Argument name to trace (alternative to arg_num)"] = None,
    depth: Annotated[int, "Analysis depth (call graph levels)"] = 5,
    max_hits: Annotated[int, "Max results for lists"] = 50,
    track_fields: Annotated[bool, "Enable field-sensitive tracking for struct/field access"] = False,
    **kwargs
) -> dict:
    """
    Enhanced static data flow and vulnerability triage utilities.

    Actions:
    - find_arg_usage: Identify how a function argument is used in pseudocode.
    - trace_return: Find where a function's return value is used by callers.
    - find_sinks: Find dangerous API calls reachable from `addr`.
    - data_flow: High-level input/output analysis for a function.
    - backward_trace: Linear backward instruction trace from `addr`.
    - slice: Heuristic argument-to-sink slice using decompiler output.
    - forward_trace: Forward cross-function taint from source to all reachable sinks.
    - cross_function_slice: Interprocedural slice across call graph from an argument.
    - sanitize_check: Find validation/sanitization functions in a call chain.
    """
    try:
        # ------------------------------------------------------------------
        # find_arg_usage
        # ------------------------------------------------------------------
        if action == "find_arg_usage":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide a function address (e.g., '0x401000' or 'main').")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            cfunc, err = _decompile_or_error(ea, "find_arg_usage")
            if err:
                return err

            arg = _get_arg_by_name_or_index(cfunc, arg_num, arg_name)
            if not arg:
                total = len([v for v in cfunc.lvars if v.is_arg_var])
                hint = f"Function has {total} arguments. Valid indices: 0-{total-1} or use arg_name."
                return make_error(MCPError.INVALID_ARGS, f"Argument not found. {hint}")

            visitor = _trace_variable_in_function(cfunc, arg.name, track_fields=track_fields)
            uses_text = "\n".join(f"{hex(ea_)}  {txt}" for ea_, txt in visitor.matches[:max_hits])

            line_matches = []
            try:
                for idx, ln in enumerate(str(cfunc).splitlines(), 1):
                    if arg.name in ln:
                        line_matches.append(f"L{idx}  {ln.strip()}")
                        if len(line_matches) >= max_hits:
                            break
            except Exception:
                pass

            calls_text = "\n".join(f"{hex(ea_)}  call {name}({', '.join(args)})" for ea_, name, args in visitor.calls[:max_hits])
            assigns_text = "\n".join(f"{hex(ea_)}  {kind}: {txt}" for ea_, kind, txt in visitor.assigns[:max_hits])

            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "arg": {"name": arg.name, "type": str(arg.type())},
                "uses": uses_text,
                "lines": "\n".join(line_matches),
                "calls": calls_text,
                "assignments": assigns_text,
                "fields_accessed": sorted(visitor.fields_accessed) if track_fields else [],
            }

        # ------------------------------------------------------------------
        # find_sinks
        # ------------------------------------------------------------------
        elif action == "find_sinks":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide a function address to start sink search.")
            ea, err = validate_addr(addr)
            if err:
                return err

            sinks = []
            visited = {ea}
            queue = [(ea, 0)]

            while queue and len(sinks) < max_hits:
                curr_ea, curr_depth = queue.pop(0)
                if curr_depth >= depth:
                    continue
                func = ida_funcs.get_func(curr_ea)
                if not func:
                    continue
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            name = idc.get_name(xref.to)
                            cat = _is_sink_name(name)
                            if cat:
                                sinks.append(f"{hex(item)}  d={curr_depth}  {cat}  {name}")
                                if len(sinks) >= max_hits:
                                    break
                            if xref.to not in visited:
                                visited.add(xref.to)
                                queue.append((xref.to, curr_depth + 1))
                            if len(sinks) >= max_hits:
                                break
                        if len(sinks) >= max_hits:
                            break

            return {"ok": True, "start": hex(ea), "sinks": "\n".join(sinks), "count": len(sinks)}

        # ------------------------------------------------------------------
        # trace_return
        # ------------------------------------------------------------------
        elif action == "trace_return":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide the function whose return value you want to trace.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            result_lines = []
            for xref in idautils.XrefsTo(ea):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                    next_ea = idc.next_head(xref.frm)
                    next_insn = ida_lines.tag_remove(idc.generate_disasm_line(next_ea, 0)) if next_ea != idaapi.BADADDR else ""
                    caller = idc.get_func_name(xref.frm)
                    result_lines.append(f"{hex(xref.frm)}  {caller}  next:{next_insn}")
                    if len(result_lines) >= max_hits:
                        break
            return {"ok": True, "function": idc.get_func_name(ea), "usages": "\n".join(result_lines)}

        # ------------------------------------------------------------------
        # data_flow
        # ------------------------------------------------------------------
        elif action == "data_flow":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide a function address for I/O analysis.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            proto = None
            try:
                proto = get_prototype(ea)
            except Exception:
                proto = None

            func = ida_funcs.get_func(ea)
            callee_lines = []
            if func:
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            name = idc.get_name(xref.to)
                            if name:
                                callee_lines.append(f"{hex(item)}  {name}  target={hex(xref.to)}")
                                if len(callee_lines) >= max_hits:
                                    break
                        if len(callee_lines) >= max_hits:
                            break

            arg_lines = []
            if ida_hexrays.init_hexrays_plugin():
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        arg_lines = [f"{v.name}  {str(v.type())}" for v in cfunc.lvars if v.is_arg_var]
                except Exception:
                    arg_lines = []

            sinks = _find_sinks_in_function(ea, max_hits)
            sink_lines = [f"{hex(item)}  {cat}  {name}  target={hex(to)}" for item, cat, name, to in sinks]

            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "prototype": proto,
                "args": "\n".join(arg_lines),
                "callees": "\n".join(callee_lines),
                "sinks": "\n".join(sink_lines),
            }

        # ------------------------------------------------------------------
        # backward_trace
        # ------------------------------------------------------------------
        elif action == "backward_trace":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide an instruction address to trace backward from.")
            ea, err = validate_addr(addr)
            if err:
                return err

            func = ida_funcs.get_func(ea)
            trace_lines = []
            curr = ea
            for _ in range(depth * 10):
                curr = idc.prev_head(curr)
                if curr == idaapi.BADADDR or (func and curr < func.start_ea):
                    break
                trace_lines.append(f"{hex(curr)}  {ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))}")
                if len(trace_lines) >= max_hits:
                    break

            return {"ok": True, "target": hex(ea), "trace": "\n".join(reversed(trace_lines))}

        # ------------------------------------------------------------------
        # slice
        # ------------------------------------------------------------------
        elif action == "slice":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide a function address and arg_num/arg_name to slice.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            cfunc, err = _decompile_or_error(ea, "slice")
            if err:
                return err

            arg = _get_arg_by_name_or_index(cfunc, arg_num, arg_name)
            if not arg:
                total = len([v for v in cfunc.lvars if v.is_arg_var])
                hint = f"Function has {total} args. Use arg_num (0-{total-1}) or arg_name."
                return make_error(MCPError.INVALID_ARGS, f"Invalid argument. {hint}")

            arg_name = arg.name
            visitor = _trace_variable_in_function(cfunc, arg_name, track_fields=track_fields)

            sinks = []
            for cat, patterns in DANGEROUS_SINKS.items():
                for m in visitor.matches:
                    _, text = m
                    if any(p.lower() in text.lower() for p in patterns):
                        sinks.append(f"{cat}  {text}")
                        if len(sinks) >= max_hits:
                            break
                if len(sinks) >= max_hits:
                    break

            # Also check assignments for sinks
            for ea_, kind, text in visitor.assigns:
                for cat, patterns in DANGEROUS_SINKS.items():
                    if any(p.lower() in text.lower() for p in patterns):
                        sinks.append(f"{cat}  {kind}: {text}")
                        if len(sinks) >= max_hits:
                            break
                if len(sinks) >= max_hits:
                    break

            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "arg": {"name": arg_name, "type": str(arg.type())},
                "sinks": "\n".join(sinks),
                "fields_accessed": sorted(visitor.fields_accessed) if track_fields else [],
                "note": "Heuristic slice based on ctree traversal. Use forward_trace or cross_function_slice for interprocedural analysis."
            }

        # ------------------------------------------------------------------
        # forward_trace
        # ------------------------------------------------------------------
        elif action == "forward_trace":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide the source function address and arg_num/arg_name to start taint.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            cfunc, err = _decompile_or_error(ea, "forward_trace")
            if err:
                return err

            arg = _get_arg_by_name_or_index(cfunc, arg_num, arg_name)
            if not arg:
                total = len([v for v in cfunc.lvars if v.is_arg_var])
                hint = f"Function has {total} args. Use arg_num (0-{total-1}) or arg_name."
                return make_error(MCPError.INVALID_ARGS, f"Invalid argument. {hint}")

            results = _forward_taint_bfs(ea, arg.name, depth, max_hits, track_fields)
            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "source": {"name": arg.name, "type": str(arg.type())},
                "sinks_found": results,
                "count": len(results),
            }

        # ------------------------------------------------------------------
        # cross_function_slice
        # ------------------------------------------------------------------
        elif action == "cross_function_slice":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide the starting function address for interprocedural slice.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            results, err = _interprocedural_slice(ea, arg_num, arg_name, depth, max_hits, track_fields)
            if err:
                return err

            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "arg_num": arg_num,
                "arg_name": arg_name,
                "slices": results,
                "count": len(results),
                "note": "Interprocedural slice follows call graph via argument passing. Depth limit may truncate paths."
            }

        # ------------------------------------------------------------------
        # sanitize_check
        # ------------------------------------------------------------------
        elif action == "sanitize_check":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required. Hint: Provide a function address to check for sanitizers in its call chain.")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            cfunc, err = _decompile_or_error(ea, "sanitize_check")
            if err:
                return err

            arg = _get_arg_by_name_or_index(cfunc, arg_num, arg_name)
            if not arg:
                total = len([v for v in cfunc.lvars if v.is_arg_var])
                hint = f"Function has {total} args. Use arg_num (0-{total-1}) or arg_name."
                return make_error(MCPError.INVALID_ARGS, f"Invalid argument. {hint}")

            target_name = arg.name

            # Check sanitizers in current function
            san_visitor = SanitizerVisitor(cfunc, target_name)
            san_visitor.apply_to(cfunc.body, None)

            local_checks = [{"ea": hex(ea_), "type": t, "context": ctx} for ea_, t, ctx in san_visitor.checks]
            local_calls = [{"ea": hex(ea_), "category": cat, "function": name} for ea_, cat, name in san_visitor.sanitizer_calls]

            # Check down the call chain
            chain_checks = []
            chain_calls = []
            visited = set()
            queue = [(ea, 0)]
            while queue and len(chain_calls) < max_hits:
                curr_ea, d = queue.pop(0)
                if d >= depth or curr_ea in visited:
                    continue
                visited.add(curr_ea)
                func = ida_funcs.get_func(curr_ea)
                if not func:
                    continue
                curr_cfunc, _ = _decompile_or_error(func.start_ea)
                if not curr_cfunc:
                    continue
                sv = SanitizerVisitor(curr_cfunc, target_name)
                sv.apply_to(curr_cfunc.body, None)
                for ea_, t, ctx in sv.checks:
                    chain_checks.append({"ea": hex(ea_), "type": t, "context": ctx, "function": idc.get_func_name(curr_ea), "depth": d})
                for ea_, cat, name in sv.sanitizer_calls:
                    chain_calls.append({"ea": hex(ea_), "category": cat, "function": name, "caller": idc.get_func_name(curr_ea), "depth": d})
                # Follow callees
                for item in idautils.FuncItems(func.start_ea):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            if xref.to not in visited:
                                queue.append((xref.to, d + 1))

            return {
                "ok": True,
                "function": idc.get_func_name(ea),
                "target": {"name": target_name, "type": str(arg.type())},
                "local_checks": local_checks,
                "local_sanitizer_calls": local_calls,
                "chain_checks": chain_checks,
                "chain_sanitizer_calls": chain_calls,
                "sanitized": bool(local_checks or local_calls or chain_checks or chain_calls),
            }

        else:
            valid_actions = [
                "find_arg_usage", "trace_return", "find_sinks", "data_flow",
                "backward_trace", "slice", "forward_trace", "cross_function_slice",
                "sanitize_check"
            ]
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}. Valid actions: {', '.join(valid_actions)}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 39. COVERAGE - Code Coverage Import and Analysis
# ============================================================================
