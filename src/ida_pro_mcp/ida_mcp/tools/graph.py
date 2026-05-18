
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================

@tool
@idaread
def graph(
    action: Annotated[Literal["callgraph", "cfg", "xref_graph"],
                      "Action: callgraph|cfg|xref_graph"],
    addr: Annotated[Optional[str], "Starting address (function or location)"] = None,
    depth: Annotated[int, "Max traversal depth"] = 5,
    direction: Annotated[Literal["down", "up", "both"], "Direction: down (callees), up (callers), both"] = "down",
    format: Annotated[Literal["json", "dot", "mermaid"], "Output format: json, dot (Graphviz), or mermaid"] = "json",
    max_items: Annotated[int, "Max nodes/edges to collect (prevents hangs on large binaries)"] = 500,
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
        # Normalize: if action is a format/direction alias, remap to callgraph with that format/direction
        _FORMAT_ALIASES = {"mermaid", "dot", "json"}
        _DIR_ALIASES = {"down", "up", "both"}
        if action in _FORMAT_ALIASES:
            format = action
            action = "callgraph"
        elif action in _DIR_ALIASES:
            direction = action
            action = "callgraph"

        if action == "callgraph":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            depth = max(0, int(depth))
            max_items = min(max(1, int(max_items)), 500)
            nodes, edges, visited = {}, [], set()
            edge_set = set()
            cycle_nodes = set()
            item_count = 0
            def add_node(f_ea):
                if f_ea not in nodes:
                    nodes[f_ea] = idc.get_func_name(f_ea) or f"sub_{f_ea:x}"
            
            def traverse(f_ea, d, stack):
                nonlocal item_count
                if d > depth or f_ea in visited: return
                if item_count >= max_items: return
                visited.add(f_ea)
                add_node(f_ea)
                stack.add(f_ea)
                for item in idautils.FuncItems(f_ea):
                    if item_count >= max_items: break
                    for xref in idautils.CodeRefsFrom(item, 0):
                        if item_count >= max_items: break
                        target = ida_funcs.get_func(xref)
                        if target and target.start_ea != f_ea:
                            add_node(target.start_ea)
                            edge = (f_ea, target.start_ea)
                            if edge not in edge_set:
                                edge_set.add(edge)
                                edges.append(edge)
                                item_count += 1
                            if target.start_ea in stack:
                                cycle_nodes.add(target.start_ea)
                            else:
                                traverse(target.start_ea, d + 1, stack)
                stack.discard(f_ea)
            
            traverse(ea, 0, set())
            
            return _format_graph(nodes, edges, format, cycle_nodes=cycle_nodes)
        
        elif action == "cfg":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            
            import ida_gdl
            func = ida_funcs.get_func(ea)
            nodes = {}
            edges = []
            for block in ida_gdl.FlowChart(func):
                label = f"{hex(block.start_ea)}-{hex(block.end_ea)}"
                nodes[block.start_ea] = label
                for succ in block.succs():
                    edges.append((block.start_ea, succ.start_ea))
                    if succ.start_ea not in nodes:
                        nodes[succ.start_ea] = f"{hex(succ.start_ea)}-{hex(succ.end_ea)}"

            result = _format_graph(nodes, edges, format)
            result["function"] = idc.get_func_name(ea)
            return result

        elif action == "xref_graph":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err

            depth = max(0, int(depth))
            max_items = min(max(1, int(max_items)), 500)
            nodes, edges, visited = {}, [], set()
            edge_set = set()
            cycle_nodes = set()
            item_count = 0
            name = idc.get_name(ea) or hex(ea)
            nodes[ea] = name

            def traverse_xrefs(target_ea, d, stack):
                nonlocal item_count
                if d > depth or target_ea in visited: return
                if item_count >= max_items: return
                visited.add(target_ea)
                stack.add(target_ea)
                # Traverse callers (xrefs TO this address)
                if direction in ("up", "both"):
                    for xref in idautils.XrefsTo(target_ea):
                        if item_count >= max_items: break
                        if not xref.iscode: continue
                        src_func = ida_funcs.get_func(xref.frm)
                        src_ea = src_func.start_ea if src_func else xref.frm
                        src_name = idc.get_name(src_ea) or hex(src_ea)
                        if src_ea not in nodes: nodes[src_ea] = src_name
                        edge = (src_ea, target_ea)
                        if edge not in edge_set:
                            edge_set.add(edge)
                            edges.append(edge)
                            item_count += 1
                        if src_ea in stack:
                            cycle_nodes.add(src_ea)
                        else:
                            traverse_xrefs(src_ea, d + 1, stack)
                # Traverse callees (xrefs FROM this address)
                if direction in ("down", "both"):
                    func = ida_funcs.get_func(target_ea)
                    if func:
                        for item in idautils.FuncItems(target_ea):
                            if item_count >= max_items: break
                            for xref in idautils.XrefsFrom(item, 0):
                                if item_count >= max_items: break
                                if not xref.iscode: continue
                                dst_func = ida_funcs.get_func(xref.to)
                                dst_ea = dst_func.start_ea if dst_func else xref.to
                                if dst_ea == target_ea: continue
                                dst_name = idc.get_name(dst_ea) or hex(dst_ea)
                                if dst_ea not in nodes: nodes[dst_ea] = dst_name
                                edge = (target_ea, dst_ea)
                                if edge not in edge_set:
                                    edge_set.add(edge)
                                    edges.append(edge)
                                    item_count += 1
                                if dst_ea in stack:
                                    cycle_nodes.add(dst_ea)
                                else:
                                    traverse_xrefs(dst_ea, d + 1, stack)
                stack.discard(target_ea)

            traverse_xrefs(ea, 0, set())
            return _format_graph(nodes, edges, format, cycle_nodes=cycle_nodes)

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _format_graph(nodes, edges, format, cycle_nodes=None):
    """Format graph nodes/edges into the requested output format."""
    cycle_nodes = cycle_nodes or set()
    if len(nodes) > 500:
        keep = set(sorted(nodes.keys())[:500])
        nodes = {ea: name for ea, name in nodes.items() if ea in keep}
        edges = [(src, dst) for src, dst in edges if src in keep and dst in keep]
    if format == "mermaid":
        mm = ["graph TD"]
        def _sid(name, ea):
            safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in str(name))
            return f"N_{ea:x}_{safe[:40]}"
        for src, dst in edges:
            u_name = nodes.get(src, hex(src))
            v_name = nodes.get(dst, hex(dst))
            u_id = _sid(u_name, src)
            v_id = _sid(v_name, dst)
            mm.append(f'  {u_id}["{u_name}"] --> {v_id}["{v_name}"]')
        for ea in cycle_nodes:
            if ea in nodes:
                mm.append(f'  {_sid(nodes[ea], ea)}:::cycle')
        if cycle_nodes:
            mm.append("  classDef cycle fill:#ffd6d6,stroke:#d00,stroke-width:2px;")
        return {"ok": True, "format": "mermaid", "graph": "\n".join(mm),
                "node_count": len(nodes), "edge_count": len(edges)}

    elif format == "dot":
        dot = ["digraph G {", "  rankdir=TB;", '  node [shape=box, style=filled, fillcolor="#e8e8e8"];']
        for ea, name in sorted(nodes.items()):
            dot.append(f'  "{name}" [label="{name}\\n{hex(ea)}"];')
        for src, dst in edges:
            u_name = nodes.get(src, hex(src))
            v_name = nodes.get(dst, hex(dst))
            dot.append(f'  "{u_name}" -> "{v_name}";')
        dot.append("}")
        return {"ok": True, "format": "dot", "graph": "\n".join(dot),
                "node_count": len(nodes), "edge_count": len(edges)}

    else:  # json
        node_lines = [f"{hex(ea)}  {name}" + ("  cycle=true" if ea in cycle_nodes else "") for ea, name in sorted(nodes.items())]
        edge_lines = [f"{hex(src)} -> {hex(dst)}" for src, dst in edges]
        return {"ok": True, "format": "json", "nodes": "\n".join(node_lines),
                "edges": "\n".join(edge_lines),
                "node_count": len(nodes), "edge_count": len(edges)}


# ============================================================================
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================
