
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]



# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================

# Safety cap for the raw-blob head scan (no defined function boundaries to
# bound the iteration otherwise).
_MAX_CODE_SCAN = 8192


def _raw_blob_note() -> str:
    """Note appended to graph responses built without any defined function."""
    return ("No defined functions: graph built from mapped code heads; "
            "function-less targets are kept as sub_<ea> placeholder nodes "
            "(functions auto-defined for graph traversal).")


class _RangeLike:
    """Duck-typed ea_range_t stand-in for minimal IDA builds / test fakes."""

    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea


def _build_range_chart(ida_gdl, ea):
    """Build an ida_gdl FlowChart over a mapped code range (raw-blob fallback).

    Used when no function is defined at *ea* (opaque raw blobs): IDA's
    FlowChart accepts a range in place of a function_t, so the graph tools can
    still produce cfg/dominator output without auto-defining functions.
    """
    seg = _compat.get_segment(ea)
    end = seg.end_ea if seg else idaapi.BADADDR
    rng_cls = getattr(idaapi, "ea_range_t", None)
    if rng_cls is not None:
        try:
            return ida_gdl.FlowChart(rng_cls(ea, end))
        except Exception:
            pass
    return ida_gdl.FlowChart(_RangeLike(ea, end))


def _code_items(f_ea):
    """Instruction EAs to scan for outgoing code xrefs.

    Uses the defined function's items when one exists; otherwise falls back to
    scanning mapped code heads from *f_ea* to the end of its segment so raw
    blobs with no defined functions still yield a call graph. Bounded by
    ``_MAX_CODE_SCAN`` to prevent hangs on pathological scans.
    """
    func = _compat.get_func_start(f_ea)
    if func is not None:
        return list(idautils.FuncItems(f_ea))
    seg = _compat.get_segment(f_ea)
    end = seg.end_ea if seg else idaapi.BADADDR
    items = []
    cur = f_ea
    scanned = 0
    while cur != idaapi.BADADDR and (end == idaapi.BADADDR or cur < end) and scanned < _MAX_CODE_SCAN:
        try:
            if ida_bytes.is_code(ida_bytes.get_flags(cur)):
                items.append(cur)
        except Exception:
            pass
        scanned += 1
        cur = idc.next_head(cur, end)
    return items


def _compute_idoms_lt(entry, succ, pred, all_nodes):
    """Immediate dominators via Lengauer–Tarjan (near-linear, O(E·α(V,E))).

    Pure-Python fallback used when ``ida_gdl.calc_idom`` is unavailable; the
    real IDA path delegates to ida_gdl, which is also near-linear. This
    replaces the previous O(n^3) dataflow fixpoint.

    Args:
        entry: entry node.
        succ: mapping node -> list of successors.
        pred: mapping node -> list of predecessors.
        all_nodes: iterable of nodes.

    Returns:
        dict mapping each node to its immediate dominator (None for entry).
    """
    nodes = list(all_nodes)
    if not nodes:
        return {}

    # Step 1: DFS from the entry to number nodes and build spanning-tree parents.
    num = {}
    vertex = {}
    parent = {}
    num[entry] = 0
    vertex[0] = entry
    counter = 1
    stack = [(entry, iter(succ.get(entry, [])))]
    while stack:
        v, it = stack[-1]
        advanced = False
        for w in it:
            if w not in num:
                num[w] = counter
                vertex[counter] = w
                counter += 1
                parent[w] = num[v]
                stack.append((w, iter(succ.get(w, []))))
                advanced = True
                break
        if not advanced:
            stack.pop()

    n = counter
    semi = list(range(n))
    label = list(range(n))
    ancestor = [-1] * n
    bucket = [[] for _ in range(n)]
    idom = [-1] * n

    def compress(v):
        a = ancestor[v]
        if a == -1 or ancestor[a] == -1:
            return
        compress(a)
        if semi[label[a]] < semi[label[v]]:
            label[v] = label[a]
        ancestor[v] = ancestor[a]

    def eval_vertex(v):
        a = ancestor[v]
        if a == -1:
            return v
        compress(v)
        return label[v]

    # Step 2: process vertices in reverse DFS order.
    for i in range(n - 1, 0, -1):
        w = vertex[i]
        for pnode in pred.get(w, []):
            p = num.get(pnode)
            if p is None:
                continue
            u = eval_vertex(p)
            semi[i] = min(semi[i], semi[u])
        bucket[semi[i]].append(i)
        pw = parent[w]
        ancestor[i] = pw
        for v in bucket[pw]:
            u = eval_vertex(v)
            idom[v] = u if semi[u] < semi[v] else pw
        bucket[pw] = []

    # Step 3: propagate idoms down the tree.
    for i in range(1, n):
        if idom[i] != semi[i]:
            idom[i] = idom[idom[i]]

    result = {}
    for nd in nodes:
        i = num.get(nd)
        if i is None or i == 0:
            result[nd] = None
        else:
            dom_i = idom[i]
            result[nd] = vertex[dom_i] if dom_i != -1 else None
    return result


def _immediate_dominators(ida_gdl, fc, blocks):
    """Map each basic-block start EA to its immediate dominator's start EA.

    Near-linear: prefers ``ida_gdl.calc_idom`` (IDA's Lengauer–Tarjan), falling
    back to the pure-Python Lengauer–Tarjan implementation.
    """
    calc_idom = getattr(ida_gdl, "calc_idom", None)
    if calc_idom is not None:
        try:
            idom_arr = calc_idom(fc)
            out = {}
            for i, b in enumerate(blocks):
                didx = int(idom_arr[i]) if i < len(idom_arr) else -1
                out[b.start_ea] = blocks[didx].start_ea if didx >= 0 else None
            return out
        except Exception:
            pass
    succ = {}
    pred = {}
    for b in blocks:
        s = [x.start_ea for x in b.succs()]
        succ.setdefault(b.start_ea, []).extend(s)
        for t in s:
            pred.setdefault(t, []).append(b.start_ea)
    return _compute_idoms_lt(blocks[0].start_ea, succ, pred, [b.start_ea for b in blocks])


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
            ea, err = validate_addr(addr)
            if err: return err

            depth = max(0, int(depth))
            max_items = min(max(1, int(max_items)), 500)
            nodes, edges, visited = {}, [], set()
            edge_set = set()
            cycle_nodes = set()
            item_count = 0
            function_less_targets = 0
            auto_defined = _compat.get_func_start(ea) is None

            def add_node(f_ea):
                nonlocal item_count
                if f_ea not in nodes:
                    nodes[f_ea] = idc.get_func_name(f_ea) or f"sub_{f_ea:x}"
                    item_count += 1

            def traverse(f_ea, d, stack):
                nonlocal item_count, function_less_targets
                if d > depth or f_ea in visited: return
                if item_count >= max_items: return
                visited.add(f_ea)
                add_node(f_ea)
                stack.add(f_ea)
                for item in _code_items(f_ea):
                    if item_count >= max_items: break
                    for xref in idautils.XrefsFrom(item):
                        if item_count >= max_items: break
                        if not xref.iscode or xref.type not in (idaapi.fl_CN, idaapi.fl_CF):
                            continue
                        target_func = _compat.get_func_start(xref.to)
                        if target_func is not None:
                            if target_func == f_ea:
                                continue
                            target = target_func
                            recurse = True
                        else:
                            # Function-less target: keep the edge and a
                            # placeholder node named sub_<ea>. Chase further
                            # only on raw blobs where the whole image is code.
                            target = xref.to
                            function_less_targets += 1
                            recurse = auto_defined
                        add_node(target)
                        if item_count >= max_items:
                            break
                        edge = (f_ea, target)
                        if edge not in edge_set:
                            edge_set.add(edge)
                            edges.append(edge)
                            item_count += 1
                        if target in stack:
                            cycle_nodes.add(target)
                        elif recurse:
                            traverse(target, d + 1, stack)
                stack.discard(f_ea)

            traverse(ea, 0, set())

            resp = _format_graph(nodes, edges, format, cycle_nodes=cycle_nodes, root_ea=ea)
            resp["function_less_targets"] = function_less_targets
            if auto_defined:
                resp["note"] = _raw_blob_note()
            return resp

        elif action == "cfg":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err

            import ida_gdl
            func = _compat.get_func_info(ea)
            auto_defined = func is None
            fc = _compat.get_flow_chart(ea) if func is not None else _build_range_chart(ida_gdl, ea)
            max_items = min(max(1, int(max_items)), 500)
            id_by_start = {}
            nodes = []
            edges = []
            mm = ["flowchart TD"]

            blocks = list(fc)
            nodes_before = len(blocks)
            for i, b in enumerate(blocks):
                if len(nodes) >= max_items:
                    break
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

            # Total edges in the FlowChart (pre-truncation count). FlowChart
            # successors are always blocks in the chart, so the full edge set
            # is simply the sum of each block's successors.
            edges_before = sum(len(list(b.succs())) for b in blocks)

            for b in blocks:
                src = id_by_start.get(b.start_ea)
                if not src:
                    continue
                succs = list(b.succs())
                for _idx, s in enumerate(succs):
                    if len(edges) >= max_items:
                        break
                    dst = id_by_start.get(s.start_ea)
                    if not dst:
                        continue
                    etype = "branch" if len(succs) > 1 else "fall_through"
                    edges.append({"from": src, "to": dst, "type": etype})
                    mm.append(f"  {src} --> {dst}")

            result = {
                "ok": True,
                "action": "cfg",
                "function": idc.get_func_name(func.start_ea) if func else f"sub_{ea:x}",
                "addr": hex(func.start_ea if func else ea),
                "mermaid": "\n".join(mm),
                "adjacency": {"nodes": nodes, "edges": edges},
                "node_count": len(nodes),
                "edge_count": len(edges),
                "nodes_before_truncation": nodes_before,
                "edges_before_truncation": edges_before,
                "truncated": nodes_before > max_items or edges_before > max_items,
            }
            if auto_defined:
                result["note"] = _raw_blob_note()
            return result

        elif action == "dominators":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            import ida_gdl
            func = _compat.get_func_info(ea)
            auto_defined = func is None
            fc = _compat.get_flow_chart(ea) if func is not None else _build_range_chart(ida_gdl, ea)
            blocks = list(fc)
            if not blocks:
                resp = {"ok": True, "action": "dominators", "dominators": []}
                if auto_defined:
                    resp["note"] = _raw_blob_note()
                return resp

            max_items = min(max(1, int(max_items)), 500)
            nodes_before = len(blocks)

            # Near-linear immediate dominators (ida_gdl's Lengauer–Tarjan, or
            # the pure-Python fallback) — not the O(n^3) fixpoint. Computed
            # over the full block list so the tree stays correct; only the
            # emitted rows are bounded by max_items.
            idoms = _immediate_dominators(ida_gdl, fc, blocks)

            rows = []
            for b in blocks:
                dom = idoms.get(b.start_ea)
                rows.append({
                    "block_addr": hex(b.start_ea),
                    "idom_addr": hex(dom) if dom is not None else None,
                })
            rows = rows[:max_items]
            resp = {
                "ok": True,
                "action": "dominators",
                "function": idc.get_func_name(func.start_ea) if func else f"sub_{ea:x}",
                "entry": hex(blocks[0].start_ea),
                "dominators": rows,
                "count": len(rows),
                "nodes_before_truncation": nodes_before,
                "truncated": nodes_before > max_items,
            }
            if auto_defined:
                resp["note"] = _raw_blob_note()
            return resp

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
            item_count += 1

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
                        src_func = _compat.get_func_start(xref.frm)
                        src_ea = src_func if src_func is not None else xref.frm
                        src_name = idc.get_name(src_ea) or hex(src_ea)
                        if src_ea not in nodes:
                            nodes[src_ea] = src_name
                            item_count += 1
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
                    if _compat.get_func_start(target_ea) is not None:
                        for item in idautils.FuncItems(target_ea):
                            if item_count >= max_items: break
                            for xref in idautils.XrefsFrom(item, 0):
                                if item_count >= max_items: break
                                if not xref.iscode: continue
                                dst_func = _compat.get_func_start(xref.to)
                                dst_ea = dst_func if dst_func is not None else xref.to
                                if dst_ea == target_ea: continue
                                dst_name = idc.get_name(dst_ea) or hex(dst_ea)
                                if dst_ea not in nodes:
                                    nodes[dst_ea] = dst_name
                                    item_count += 1
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
            return _format_graph(nodes, edges, format, cycle_nodes=cycle_nodes, root_ea=ea)

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _format_graph(nodes, edges, format, cycle_nodes=None, root_ea=None):
    """Format graph nodes/edges into the requested output format.

    Reports pre/post truncation counts so callers can tell how many nodes and
    edges were dropped by the 500-node safety cap.
    """
    cycle_nodes = cycle_nodes or set()
    nodes_before = len(nodes)
    edges_before = len(edges)
    if len(nodes) > 500:
        # Keep the traversal anchored on relevance, not address order: the
        # requested root first, then the most-connected nodes. Address-sorted
        # truncation could silently drop the root (and every edge touching
        # it), yielding a graph that reports 500 nodes but loses the subtree.
        degree = {}
        for src, dst in edges:
            degree[src] = degree.get(src, 0) + 1
            degree[dst] = degree.get(dst, 0) + 1

        def _relevance_key(ea):
            return (0 if ea == root_ea else 1, -degree.get(ea, 0), ea)

        keep = set(sorted(nodes.keys(), key=_relevance_key)[:500])
        nodes = {ea: name for ea, name in nodes.items() if ea in keep}
        edges = [(src, dst) for src, dst in edges if src in keep and dst in keep]

    base = {
        "ok": True,
        "format": format,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes_before_truncation": nodes_before,
        "edges_before_truncation": edges_before,
        "truncated": nodes_before > 500,
    }

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
        base["graph"] = "\n".join(mm)
        return base

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
        base["graph"] = "\n".join(dot)
        return base

    else:  # json
        node_rows = [{"addr": hex(ea), "name": name, "cycle": ea in cycle_nodes} for ea, name in sorted(nodes.items())]
        edge_rows = [{"from": hex(src), "to": hex(dst)} for src, dst in edges]
        base["nodes"] = node_rows
        base["edges"] = edge_rows
        return base
