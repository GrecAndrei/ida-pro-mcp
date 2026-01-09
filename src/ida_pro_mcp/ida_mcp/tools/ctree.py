
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
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc: return make_error(MCPError.IDA_ERROR, "Decompilation failed")
        except: return make_error(MCPError.IDA_ERROR, "Decompiler required for CTree")
        
        func_name = idc.get_func_name(ea)
        
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
                        # Use print1() instead of str() for better performance
                        text = ida_lines.tag_remove(e.print1(None))
                        flow.append({"type": "call", "ea": hex(e.ea), "text": text})
                    return 0
                def visit_insn(self, i):
                    if self.count > 500: return 1
                    if i.op == ida_hexrays.cit_if:
                        self.count += 1
                        cond = "complex_expression"
                        try: 
                            if i.cif.expr: cond = ida_lines.tag_remove(i.cif.expr.print1(None))
                        except: pass
                        flow.append({"type": "if", "ea": hex(i.ea), "cond": cond})
                    elif i.op == ida_hexrays.cit_return:
                        flow.append({"type": "return", "ea": hex(i.ea)})
                    elif i.op in [ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do]:
                        flow.append({"type": "loop", "ea": hex(i.ea)})
                    return 0
            
            visitor = LogicVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "logic_flow": flow}

        if action == "get":
            nodes = []
            class NodeVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.count = 0
                def visit_expr(self, e):
                    if self.count > 200: return 1
                    self.count += 1
                    nodes.append({"op": ida_hexrays.get_ctype_name(e.op), "ea": hex(e.ea), "text": ida_lines.tag_remove(e.print1(None))})
                    return 0
                def visit_insn(self, i):
                    if self.count > 200: return 1
                    self.count += 1
                    nodes.append({"op": ida_hexrays.get_ctype_name(i.op), "ea": hex(i.ea)})
                    return 0
            
            visitor = NodeVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "nodes": nodes, "total": len(nodes)}
        
        elif action == "find_calls":
            calls = []
            class CallVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_call:
                        calls.append({"addr": hex(e.ea), "text": ida_lines.tag_remove(str(e))})
                    return 0
            
            visitor = CallVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "calls": calls}

        elif action == "find_vars":
            vars = [{"name": v.name, "type": str(v.type()), "is_arg": v.is_arg_var} for v in cfunc.lvars]
            return {"ok": True, "function": func_name, "variables": vars}

        elif action == "find_conditions":
            conds = []
            class CondVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                def visit_insn(self, i):
                    if i.op in [ida_hexrays.cit_if, ida_hexrays.cit_while, ida_hexrays.cit_for]:
                        # Extract the expression part
                        expr_text = "unknown"
                        if i.op == ida_hexrays.cit_if and i.cif.expr: expr_text = ida_lines.tag_remove(str(i.cif.expr))
                        conds.append({"type": ida_hexrays.get_ctype_name(i.op), "addr": hex(i.ea), "expr": expr_text})
                    return 0
            
            visitor = CondVisitor()
            visitor.apply_to(cfunc.body, None)
            return {"ok": True, "function": func_name, "logic_points": conds}

        else:
            return make_error(MCPError.NOT_IMPLEMENTED, f"Action {action} is not yet fully optimized.")
            
    except Exception as e:
        return handle_error(e)
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 22. DIFF - Binary Comparison and Diffing
# ============================================================================
