
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
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
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
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 21. CTREE - Hex-Rays AST/CTree Access for Deep Decompiler Analysis
# ============================================================================

@tool
@idaread
def ctree(
    action: Annotated[Literal["get", "traverse", "find_calls", "find_vars", "find_strings", "find_conditions", "get_logic_flow"],
                      "Action: get|traverse|find_calls|find_vars|find_strings|find_conditions|get_logic_flow"],
    addr: Annotated[str, "Address of function to analyze"],
    query: Annotated[Optional[str], "Filter pattern (for find_* actions)"] = None,
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
        filter_text = (query or "").lower()

        def match_filter(text):
            if not filter_text:
                return True
            return filter_text in (text or "").lower()

        if action == "get_logic_flow":
            flow = []
            class LogicVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.count = 0
                def visit_expr(self, e):
                    if self.count > 500: return 1 # Limit
                    if e.op == ida_hexrays.cot_call:
                        self.count += 1
                        text = ida_lines.tag_remove(e.print1(None))
                        flow.append(f"{hex(e.ea)}  call  {text}")
                    return 0
                def visit_insn(self, i):
                    if self.count > 500: return 1
                    if i.op == ida_hexrays.cit_if:
                        self.count += 1
                        cond = "complex_expression"
                        try:
                            if i.cif.expr: cond = ida_lines.tag_remove(i.cif.expr.print1(None))
                        except Exception:
                            pass
                        flow.append(f"{hex(i.ea)}  if  {cond}")
                    elif i.op == ida_hexrays.cit_return:
                        flow.append(f"{hex(i.ea)}  return")
                    elif i.op in [ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do]:
                        flow.append(f"{hex(i.ea)}  loop")
                    return 0

            visitor = LogicVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "logic_flow": "\n".join(flow), "count": len(flow)}

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
                                text = s.decode("utf-8", "replace")
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# 22. DIFF - Binary Comparison and Diffing
# ============================================================================
