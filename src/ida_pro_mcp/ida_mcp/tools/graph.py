
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
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ida_mcp.error_handling import (
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
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================

@tool
@idaread
def graph(
    action: Annotated[Literal["callgraph", "cfg", "xref_graph"],
                      "Action: callgraph|cfg|xref_graph"],
    addr: Annotated[Optional[str], "Starting address (function or location)"] = None,
    depth: Annotated[int, "Max traversal depth"] = 3,
    direction: Annotated[Literal["down", "up", "both"], "Direction: down (callees), up (callers), both"] = "down",
    format: Annotated[Literal["json", "dot", "mermaid"], "Output format: json, dot (Graphviz), or mermaid"] = "json",
    **kwargs
) -> dict:
    """
    Export graphs for visualization and analysis.
    
    Actions:
    - callgraph: Generate function call graph starting from addr
    - cfg: Generate control flow graph for function at addr
    - xref_graph: Generate cross-reference graph
    
    Output formats:
    - json: Structured JSON with nodes and edges
    - dot: Graphviz DOT format for visualization
    - mermaid: Mermaid.js flowchart syntax (best for LLMs and rendering)
    """
    try:
        if action == "callgraph":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            nodes, edges, visited = {}, [], set()
            def add_node(f_ea):
                if f_ea not in nodes:
                    nodes[f_ea] = {"id": hex(f_ea), "name": idc.get_func_name(f_ea) or f"sub_{f_ea:x}"}
            
            def traverse(f_ea, d):
                if d > depth or f_ea in visited: return
                visited.add(f_ea)
                add_node(f_ea)
                for item in idautils.FuncItems(f_ea):
                    for xref in idautils.CodeRefsFrom(item, 0):
                        target = ida_funcs.get_func(xref)
                        if target and target.start_ea != f_ea:
                            add_node(target.start_ea)
                            edge = {"from": hex(f_ea), "to": hex(target.start_ea)}
                            if edge not in edges: edges.append(edge)
                            traverse(target.start_ea, d + 1)
            
            traverse(ea, 0)
            
            if format == "mermaid":
                mm = ["graph TD"]
                for edge in edges:
                    u_name = nodes[int(edge["from"], 16)]["name"]
                    v_name = nodes[int(edge["to"], 16)]["name"]
                    mm.append(f'  {u_name}["{u_name}"] --> {v_name}["{v_name}"]')
                return {"ok": True, "mermaid": "\n".join(mm)}
                
            return {"ok": True, "nodes": list(nodes.values()), "edges": edges}
        
        elif action == "cfg":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            import ida_gdl
            func = ida_funcs.get_func(ea)
            nodes, edges = [], []
            for block in ida_gdl.FlowChart(func):
                b_id = hex(block.start_ea)
                nodes.append({"id": b_id, "start": b_id, "end": hex(block.end_ea)})
                for succ in block.succs():
                    edges.append({"from": b_id, "to": hex(succ.start_ea)})
            
            if format == "mermaid":
                mm = ["graph TD"]
                for edge in edges:
                    mm.append(f'  {edge["from"]} --> {edge["to"]}')
                return {"ok": True, "mermaid": "\n".join(mm)}
                
            return {"ok": True, "function": idc.get_func_name(ea), "nodes": nodes, "edges": edges}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================
