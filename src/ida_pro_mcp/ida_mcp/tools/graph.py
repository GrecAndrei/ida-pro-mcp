
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
    action: Annotated[Literal["callgraph", "cfg", "dominators", "xref_graph"],
                      "Action: callgraph|cfg|dominators|xref_graph"],
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
    - dominators: Compute dominator tree (forward or reverse) for the function at addr
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
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            fc = ida_gdl.FlowChart(func)
            id_by_start = {}
            nodes = []
            edges = []
            mm = ["flowchart TD"]

            blocks = list(fc)
            for i, b in enumerate(blocks):
                bid = f"B{i}"
                id_by_start[b.start_ea] = bid
                insn_count = 0
                cur = b.start_ea
                while cur != idaapi.BADADDR and cur < b.end_ea:
                    insn_count += 1
                    cur = idc.next_head(cur, b.end_ea)
                btype = "block"
                last = idc.prev_head(b.end_ea, b.start_ea)
                mnem = (idc.print_insn_mnem(last) or "").lower() if last != idaapi.BADADDR else ""
                if mnem.startswith("ret"):
                    btype = "ret"
                elif mnem.startswith("call"):
                    btype = "call"
                nodes.append({
                    "id": bid,
                    "addr": hex(b.start_ea),
                    "size": int(max(0, b.end_ea - b.start_ea)),
                    "type": btype,
                    "insn_count": insn_count,
                })
                mm.append(f'  {bid}["{hex(b.start_ea)}\\ninsn:{insn_count}"]')

            for b in blocks:
                src = id_by_start.get(b.start_ea)
                succs = list(b.succs())
                for _idx, s in enumerate(succs):
                    dst = id_by_start.get(s.start_ea)
                    if not src or not dst:
                        continue
                    etype = "branch" if len(succs) > 1 else "fall_through"
                    edges.append({"from": src, "to": dst, "type": etype})
                    mm.append(f"  {src} --> {dst}")
                if not succs:
                    # terminal block
                    edges.append({"from": src, "to": src, "type": "ret"})

            result = {
                "ok": True,
                "action": "cfg",
                "function": idc.get_func_name(ea),
                "addr": hex(func.start_ea),
                "mermaid": "\n".join(mm),
                "adjacency": {"nodes": nodes, "edges": edges},
                "node_count": len(nodes),
                "edge_count": len(edges),
            }
            return result

        elif action == "dominators":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            import ida_gdl
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            blocks = list(ida_gdl.FlowChart(func))
            if not blocks:
                return {"ok": True, "action": "dominators", "dominators": []}

            preds = {b.start_ea: set() for b in blocks}
            all_nodes = {b.start_ea for b in blocks}
            start = blocks[0].start_ea
            for b in blocks:
                for s in b.succs():
                    preds.setdefault(s.start_ea, set()).add(b.start_ea)

            dom = {n: set(all_nodes) for n in all_nodes}
            dom[start] = {start}
            changed = True
            while changed:
                changed = False
                for n in all_nodes:
                    if n == start:
                        continue
                    pset = preds.get(n, set())
                    if not pset:
                        new_dom = {n}
                    else:
                        inter = None
                        for p in pset:
                            inter = set(dom[p]) if inter is None else inter.intersection(dom[p])
                        new_dom = (inter if inter is not None else set()) | {n}
                    if new_dom != dom[n]:
                        dom[n] = new_dom
                        changed = True

            idom = {}
            for n in all_nodes:
                if n == start:
                    idom[n] = None
                    continue
                cands = list(dom[n] - {n})
                if not cands:
                    idom[n] = None
                    continue
                # immediate dominator: dominator not dominated by any other candidate
                imm = None
                for c in cands:
                    dominated_by_other = False
                    for o in cands:
                        if o == c:
                            continue
                        if c in dom.get(o, set()):
                            dominated_by_other = True
                            break
                    if not dominated_by_other:
                        imm = c
                        break
                idom[n] = imm

            rows = []
            for b in blocks:
                n = b.start_ea
                rows.append({
                    "block_addr": hex(n),
                    "idom_addr": hex(idom[n]) if idom.get(n) is not None else None,
                })
            return {
                "ok": True,
                "action": "dominators",
                "function": idc.get_func_name(func.start_ea),
                "entry": hex(start),
                "dominators": rows,
                "count": len(rows),
            }

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
        def _esc_mermaid(label: str) -> str:
            return str(label).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        def _sid(name, ea):
            safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in str(name))
            return f"N_{ea:x}_{safe[:40]}"
        for src, dst in edges:
            u_name = nodes.get(src, hex(src))
            v_name = nodes.get(dst, hex(dst))
            u_id = _sid(u_name, src)
            v_id = _sid(v_name, dst)
            mm.append(f'  {u_id}["{_esc_mermaid(u_name)}"] --> {v_id}["{_esc_mermaid(v_name)}"]')
        for ea in cycle_nodes:
            if ea in nodes:
                mm.append(f'  {_sid(nodes[ea], ea)}:::cycle')
        if cycle_nodes:
            mm.append("  classDef cycle fill:#ffd6d6,stroke:#d00,stroke-width:2px;")
        return {"ok": True, "format": "mermaid", "graph": "\n".join(mm),
                "node_count": len(nodes), "edge_count": len(edges)}

    elif format == "dot":
        dot = ["digraph G {", "  rankdir=TB;", '  node [shape=box, style=filled, fillcolor="#e8e8e8"];']
        def _esc_dot(label: str) -> str:
            return str(label).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        for ea, name in sorted(nodes.items()):
            en = _esc_dot(name)
            dot.append(f'  "{en}" [label="{en}\\n{hex(ea)}"];')
        for src, dst in edges:
            u_name = nodes.get(src, hex(src))
            v_name = nodes.get(dst, hex(dst))
            dot.append(f'  "{_esc_dot(u_name)}" -> "{_esc_dot(v_name)}";')
        dot.append("}")
        return {"ok": True, "format": "dot", "graph": "\n".join(dot),
                "node_count": len(nodes), "edge_count": len(edges)}

    else:  # json
        node_rows = [{"addr": hex(ea), "name": name, "cycle": ea in cycle_nodes} for ea, name in sorted(nodes.items())]
        edge_rows = [{"from": hex(src), "to": hex(dst)} for src, dst in edges]
        return {"ok": True, "format": "json", "nodes": node_rows,
                "edges": edge_rows,
                "node_count": len(nodes), "edge_count": len(edges)}


# ============================================================================
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================
