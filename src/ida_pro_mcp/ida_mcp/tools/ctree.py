
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_segment
import ida_funcs
import ida_kernwin
import ida_frame
import ida_lines

# Infrastructure discovery
try:
    # Package mode
    from ..rpc import tool, unsafe
    from ..sync import idaread, idawrite, IDAError
    from ..utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size,
        compile_smart_pattern,
    )
    from ..error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
        
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size,
        compile_smart_pattern,
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 21. CTREE - Hex-Rays AST/CTree Access for Deep Decompiler Analysis
# ============================================================================


def _ctree_collect_expr_rows(cfunc, max_items=2500):
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


def _ctree_build_var_dependency_graph(cfunc, max_edges=1200):
    import re

    lvars = list(getattr(cfunc, "lvars", []) or [])
    names = []
    arg_vars = set()
    for v in lvars:
        n = str(getattr(v, "name", "") or "").strip()
        if not n:
            continue
        names.append(n)
        if bool(getattr(v, "is_arg_var", False)):
            arg_vars.add(n)
    vocab = set(names)
    if not vocab:
        return {
            "nodes": [],
            "edges": [],
            "arg_vars": [],
            "edge_count": 0,
            "assignment_edges": 0,
            "phi_like_merges": [],
        }

    word_re = re.compile(r"[A-Za-z_]\w*")

    def _vars(text):
        return [t for t in set(word_re.findall(text or "")) if t in vocab]

    rows = _ctree_collect_expr_rows(cfunc, max_items=max_edges * 4)
    edges = []
    edge_seen = set()
    assigns = 0

    # Track potential merge targets where same var receives multiple unique sources.
    merge_sources = {}

    for ea, expr in rows:
        text = (expr or "").strip()
        if not text:
            continue
        if "=" in text and "==" not in text and "<=" not in text and ">=" not in text and "!=" not in text:
            lhs, rhs = text.split("=", 1)
            lhs_vars = _vars(lhs)
            rhs_vars = _vars(rhs)
            if lhs_vars:
                dst = sorted(lhs_vars, key=len, reverse=True)[0]
                merge_sources.setdefault(dst, set())
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
                            "ea": hex(ea) if ea != idaapi.BADADDR else None,
                        }
                    )
                    merge_sources[dst].add(src)
                    assigns += 1
        if len(edges) >= max_edges:
            break

    phi_like = sorted(
        (
            {"var": var, "incoming_sources": sorted(srcs), "source_count": len(srcs)}
            for var, srcs in merge_sources.items()
            if len(srcs) >= 2
        ),
        key=lambda it: it["source_count"],
        reverse=True,
    )[:32]

    return {
        "nodes": sorted(vocab),
        "edges": edges,
        "arg_vars": sorted(arg_vars),
        "edge_count": len(edges),
        "assignment_edges": assigns,
        "phi_like_merges": phi_like,
    }


def _ctree_build_dominance_map(cfunc, max_nodes=600):
    """
    Build an approximate condition-dominance map using ctree depth/order.
    This is a decompiler-structure approximation suitable for LLM triage.
    """
    conditions = []

    class CondVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.count = 0

        def visit_insn(self, i):
            if self.count >= max_nodes:
                return 1
            if i.op in [ida_hexrays.cit_if, ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do, ida_hexrays.cit_switch]:
                self.count += 1
                expr = "complex"
                try:
                    if i.op == ida_hexrays.cit_if and i.cif.expr:
                        expr = ida_lines.tag_remove(i.cif.expr.print1(None))
                    elif i.op == ida_hexrays.cit_while and i.cwhile.expr:
                        expr = ida_lines.tag_remove(i.cwhile.expr.print1(None))
                    elif i.op == ida_hexrays.cit_for and i.cfor.cond:
                        expr = ida_lines.tag_remove(i.cfor.cond.print1(None))
                    elif i.op == ida_hexrays.cit_do and i.cdo.expr:
                        expr = ida_lines.tag_remove(i.cdo.expr.print1(None))
                except Exception:
                    pass
                conditions.append(
                    {
                        "id": f"cond_{len(conditions)}",
                        "ea": hex(int(getattr(i, "ea", idaapi.BADADDR))),
                        "depth": int(getattr(self, "level", 0)),
                        "op": ida_hexrays.get_ctype_name(i.op),
                        "expr": expr,
                    }
                )
            return 0

    try:
        v = CondVisitor()
        v.apply_to(cfunc.body, None)
    except Exception:
        pass

    edges = []
    for i, node in enumerate(conditions):
        # Dominator approximation: nearest earlier condition with lower depth.
        dom = None
        for j in range(i - 1, -1, -1):
            cand = conditions[j]
            if cand["depth"] < node["depth"]:
                dom = cand
                break
        if dom:
            edges.append({"from": dom["id"], "to": node["id"], "relation": "dominates"})

    return {
        "conditions": conditions,
        "dominance_edges": edges,
        "condition_count": len(conditions),
        "edge_count": len(edges),
    }


def _ctree_build_logic_graph(cfunc, max_nodes=1200):
    """Build token-efficient logic graph with typed edges for RE workflows."""
    nodes = []
    edges = []
    edge_seen = set()
    node_ids = set()

    def _add_node(ea, kind, text, depth):
        nid = f"n_{len(nodes)}"
        node = {
            "id": nid,
            "ea": hex(int(ea)) if ea is not None and ea != idaapi.BADADDR else None,
            "kind": kind,
            "text": (text or "").strip(),
            "depth": int(depth),
        }
        nodes.append(node)
        node_ids.add(nid)
        return nid

    def _add_edge(src, dst, rel):
        if not src or not dst or src == dst:
            return
        key = (src, dst, rel)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({"from": src, "to": dst, "relation": rel})

    class LogicGraphVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.count = 0
            self.control_stack = []

        def _control_parent(self):
            return self.control_stack[-1] if self.control_stack else None

        def visit_insn(self, i):
            if self.count >= max_nodes:
                return 1
            op = i.op
            depth = int(getattr(self, "level", 0))

            if op == ida_hexrays.cit_if:
                cond = "complex_expression"
                try:
                    if i.cif.expr:
                        cond = ida_lines.tag_remove(i.cif.expr.print1(None))
                except Exception:
                    pass
                nid = _add_node(getattr(i, "ea", idaapi.BADADDR), "if", cond, depth)
                _add_edge(self._control_parent(), nid, "controls")
                self.control_stack.append(nid)
                self.count += 1
                return 0

            if op in [ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do]:
                cond = "loop"
                try:
                    if op == ida_hexrays.cit_while and i.cwhile.expr:
                        cond = ida_lines.tag_remove(i.cwhile.expr.print1(None))
                    elif op == ida_hexrays.cit_for and i.cfor.cond:
                        cond = ida_lines.tag_remove(i.cfor.cond.print1(None))
                    elif op == ida_hexrays.cit_do and i.cdo.expr:
                        cond = ida_lines.tag_remove(i.cdo.expr.print1(None))
                except Exception:
                    pass
                nid = _add_node(getattr(i, "ea", idaapi.BADADDR), "loop", cond, depth)
                _add_edge(self._control_parent(), nid, "controls")
                self.control_stack.append(nid)
                self.count += 1
                return 0

            if op == ida_hexrays.cit_return:
                nid = _add_node(getattr(i, "ea", idaapi.BADADDR), "return", "return", depth)
                _add_edge(self._control_parent(), nid, "exits")
                self.count += 1
                return 0
            return 0

        def leave_insn(self, i):
            if i.op in [ida_hexrays.cit_if, ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do]:
                if self.control_stack:
                    self.control_stack.pop()
            return 0

        def visit_expr(self, e):
            if self.count >= max_nodes:
                return 1
            if e.op == ida_hexrays.cot_call:
                depth = int(getattr(self, "level", 0))
                txt = "call"
                try:
                    txt = ida_lines.tag_remove(e.print1(None))
                except Exception:
                    pass
                nid = _add_node(getattr(e, "ea", idaapi.BADADDR), "call", txt, depth)
                _add_edge(self._control_parent(), nid, "contains_call")
                self.count += 1
            return 0

    try:
        v = LogicGraphVisitor()
        v.apply_to(cfunc.body, None)
    except Exception:
        pass

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


@tool
@idaread
def ctree(
    action: Annotated[Literal["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow", "dominance_map", "var_dependency_graph"],
                      "Action: get|traverse|find_calls|find_vars|find_strings|find_conditions|get_logic_flow|dominance_map|var_dependency_graph"],
    addr: Annotated[str, "Address of function to analyze"],
    query: Annotated[Optional[str], "Filter pattern (regex/glob/substring/semantic auto-detected; for find_* actions)"] = None,
    depth: Annotated[int, "Max traversal depth"] = 10,
) -> dict:
    """
    Hex-Rays AST (CTree) analysis utilities.

    Actions:
    - get: List all AST nodes with their C-like text representation.
    - traverse: Recursive tree dump starting from `addr`.
    - find_calls: List all function calls including arguments.
    - find_vars: List all local variable and parameter usage.
    - find_strings: Find string literal references in the pseudocode.
    - find_conditions: Extract logic for if/while/for statements.
    - get_logic_flow: Simplified Logic Flow (SLF) for token-efficient reasoning.
    - dominance_map: Approximate condition-dominance hierarchy from decompiler structure.
    - var_dependency_graph: Build variable dependency graph + phi-like merge candidates.
    """
    try:
        ea, err = validate_addr(addr, require_func=True)
        if err: return err

        try:
            if not ida_hexrays.init_hexrays_plugin():
                return make_error(MCPError.IDA_ERROR, "Decompiler required for CTree")
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc: return make_error(MCPError.IDA_ERROR, "Decompilation failed")
        except Exception:
            return make_error(MCPError.IDA_ERROR, "Decompiler required for CTree")

        func_name = idc.get_func_name(ea)
        filter_matcher = compile_smart_pattern(query, case_sensitive=False) if query else None

        def match_filter(text):
            if not filter_matcher:
                return True
            return filter_matcher((text or ""))

        if action == "get_logic_flow":
            graph = _ctree_build_logic_graph(cfunc, max_nodes=max(200, min(5000, int(depth) * 180)))
            nodes = graph.get("nodes", [])
            if filter_matcher:
                nodes = [n for n in nodes if match_filter(n.get("text", "")) or match_filter(n.get("kind", ""))]
                allowed = {n.get("id") for n in nodes}
                edges = [e for e in graph.get("edges", []) if e.get("from") in allowed and e.get("to") in allowed]
            else:
                edges = graph.get("edges", [])

            lines = [
                f"{n.get('ea') or 'None'}  {n.get('kind')}  depth={n.get('depth')}  {n.get('text', '')}"
                for n in nodes[:1200]
            ]
            edge_lines = [
                f"{e.get('from')} -> {e.get('to')}  {e.get('relation')}"
                for e in edges[:1200]
            ]
            return {
                "ok": True,
                "function": func_name,
                "logic_flow": "\n".join(lines),
                "edges": "\n".join(edge_lines),
                "logic_graph": {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)},
                "count": len(nodes),
            }

        if action == "get":
            node_lines = []
            class NodeVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.count = 0
                def visit_expr(self, e):
                    if self.count > 200: return 1
                    self.count += 1
                    node_lines.append(f"{hex(e.ea)}  {ida_hexrays.get_ctype_name(e.op)}  {ida_lines.tag_remove(e.print1(None))}")
                    return 0
                def visit_insn(self, i):
                    if self.count > 200: return 1
                    self.count += 1
                    node_lines.append(f"{hex(i.ea)}  {ida_hexrays.get_ctype_name(i.op)}")
                    return 0

            visitor = NodeVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "nodes": "\n".join(node_lines), "total": len(node_lines)}

        elif action == "find_calls":
            call_lines = []
            class CallVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_call:
                        callee = ""
                        try:
                            callee = ida_lines.tag_remove(e.x.print1(None))
                        except Exception:
                            pass
                        args = []
                        try:
                            for a in getattr(e, "a", []):
                                args.append(ida_lines.tag_remove(a.print1(None)))
                        except Exception:
                            pass
                        text = ida_lines.tag_remove(e.print1(None))
                        if match_filter(text) or match_filter(callee) or any(match_filter(a) for a in args):
                            args_str = ", ".join(args) if args else ""
                            call_lines.append(f"{hex(e.ea)}  {callee}({args_str})")
                    return 0

            visitor = CallVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "calls": "\n".join(call_lines), "count": len(call_lines)}

        elif action == "find_vars":
            var_lines = [f"{v.name}  {str(v.type())}  {'arg' if v.is_arg_var else 'local'}" for v in cfunc.lvars]
            use_lines = []
            class VarUseVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_var:
                        try:
                            v = cfunc.lvars[e.v.idx]
                            name = v.name
                            text = ida_lines.tag_remove(e.print1(None))
                            if match_filter(name) or match_filter(text):
                                use_lines.append(f"{hex(e.ea)}  {name}  {text}")
                        except Exception:
                            pass
                    return 0
            visitor = VarUseVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "variables": "\n".join(var_lines), "uses": "\n".join(use_lines), "count": len(use_lines)}

        elif action == "find_conditions":
            cond_lines = []
            class CondVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_insn(self, i):
                    if i.op in [ida_hexrays.cit_if, ida_hexrays.cit_while, ida_hexrays.cit_for]:
                        expr_text = "unknown"
                        if i.op == ida_hexrays.cit_if and i.cif.expr:
                            expr_text = ida_lines.tag_remove(i.cif.expr.print1(None))
                        elif i.op == ida_hexrays.cit_while and i.cwhile.expr:
                            expr_text = ida_lines.tag_remove(i.cwhile.expr.print1(None))
                        elif i.op == ida_hexrays.cit_for and i.cfor.cond:
                            expr_text = ida_lines.tag_remove(i.cfor.cond.print1(None))
                        if match_filter(expr_text):
                            cond_lines.append(f"{hex(i.ea)}  {ida_hexrays.get_ctype_name(i.op)}  {expr_text}")
                    return 0

            visitor = CondVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "logic_points": "\n".join(cond_lines), "count": len(cond_lines)}

        elif action == "find_strings":
            str_lines = []
            class StringVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_str:
                        text = ""
                        try:
                            text = ida_lines.tag_remove(e.print1(None))
                        except Exception:
                            pass
                        if match_filter(text):
                            str_lines.append(f"{hex(e.ea)}  {text}")
                    elif e.op == ida_hexrays.cot_obj:
                        obj_ea = getattr(e, "obj_ea", idaapi.BADADDR)
                        if obj_ea != idaapi.BADADDR:
                            s = idc.get_strlit_contents(obj_ea)
                            if s:
                                text = s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s)
                                if match_filter(text):
                                    str_lines.append(f"{hex(obj_ea)}  xref@{hex(e.ea)}  {text}")
                    return 0
            visitor = StringVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "strings": "\n".join(str_lines), "count": len(str_lines)}

        elif action == "traverse":
            node_lines = []
            class TraverseVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, max_depth):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.max_depth = max_depth
                def visit_expr(self, e):
                    if self.level > self.max_depth:
                        return 1
                    text = ""
                    try:
                        text = ida_lines.tag_remove(e.print1(None))
                    except Exception:
                        pass
                    if match_filter(text):
                        indent = "  " * self.level
                        node_lines.append(f"{indent}{hex(e.ea)}  {ida_hexrays.get_ctype_name(e.op)}  {text}")
                    return 0
            visitor = TraverseVisitor(depth)
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "nodes": "\n".join(node_lines), "count": len(node_lines)}

        elif action == "dominance_map":
            dom = _ctree_build_dominance_map(cfunc, max_nodes=max(100, min(2000, int(depth) * 120)))
            edge_lines = [
                f"{e['from']} -> {e['to']}  {e['relation']}"
                for e in dom.get("dominance_edges", [])[:500]
            ]
            return {
                "ok": True,
                "function": func_name,
                "dominance_map": dom,
                "edges": "\n".join(edge_lines),
                "count": dom.get("edge_count", 0),
            }

        elif action == "var_dependency_graph":
            dep = _ctree_build_var_dependency_graph(cfunc, max_edges=max(200, min(2400, int(depth) * 180)))
            edge_lines = [
                f"{e['from']} -> {e['to']}  {e['kind']}  {e.get('ea') or ''}".rstrip()
                for e in dep.get("edges", [])[:500]
            ]
            return {
                "ok": True,
                "function": func_name,
                "var_dependency_graph": dep,
                "edges": "\n".join(edge_lines),
                "count": dep.get("edge_count", 0),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# 22. DIFF - Binary Comparison and Diffing
# ============================================================================
