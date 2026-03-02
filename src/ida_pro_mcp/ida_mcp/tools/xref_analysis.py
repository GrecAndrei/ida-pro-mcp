try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from collections import defaultdict, deque


_MAX_LIMIT = 500
_MAX_DEPTH = 64


def _clip_text(value: Any, max_len: int = 220) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _func_name(ea: int) -> str:
    name = idc.get_func_name(ea)
    if name:
        return name
    return f"sub_{ea:x}"


def _fmt_func(ea: int) -> str:
    return f"{hex_ea(ea)}  {_func_name(ea)}"


def _all_functions() -> list[int]:
    try:
        return [int(ea) for ea in idautils.Functions()]
    except Exception:
        return []


def _sanitize_limit(limit: int) -> int:
    try:
        value = int(limit)
    except Exception:
        value = 50
    if value <= 0:
        return 1
    return min(value, _MAX_LIMIT)


def _sanitize_offset(offset: int) -> int:
    try:
        return max(0, int(offset))
    except Exception:
        return 0


def _sanitize_depth(depth: int) -> int:
    try:
        value = int(depth)
    except Exception:
        value = 10
    if value < 0:
        return 0
    return min(value, _MAX_DEPTH)


def _paginate(rows: list[Any], offset: int, limit: int) -> tuple[list[Any], int, bool]:
    total = len(rows)
    page = rows[offset : offset + limit]
    truncated = (offset + len(page)) < total
    return page, total, truncated


def _resolve_multi_addrs(
    addr: Optional[str],
    addr2: Optional[str],
    addrs: Optional[str],
) -> list[int] | dict:
    targets: list[int] = []

    if addrs:
        try:
            parts = normalize_list_input(addrs)
        except Exception:
            parts = [p.strip() for p in str(addrs).split(",") if p.strip()]
        for part in parts:
            ea, err = validate_addr(str(part), require_func=True)
            if err:
                return err
            if ea not in targets:
                targets.append(ea)

    if addr:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return err
        if ea not in targets:
            targets.insert(0, ea)

    if addr2:
        ea, err = validate_addr(addr2, require_func=True)
        if err:
            return err
        if ea not in targets:
            targets.append(ea)

    return targets


def _find_entry_functions() -> list[int]:
    entries: set[int] = set()
    try:
        qty = int(idaapi.get_entry_qty())
    except Exception:
        qty = 0

    for i in range(qty):
        try:
            ordinal = idaapi.get_entry_ordinal(i)
            ep = idaapi.get_entry(ordinal)
        except Exception:
            continue
        if ep == idaapi.BADADDR:
            continue
        fn = ida_funcs.get_func(ep)
        if fn:
            entries.add(int(fn.start_ea))

    # Fallback: use lowest-address function if IDB has no explicit entries.
    if not entries:
        funcs = _all_functions()
        if funcs:
            entries.add(min(funcs))

    return sorted(entries)


def _count_external_refs(target_ea: int) -> int:
    count = 0
    for xref in idautils.XrefsTo(target_ea, 0):
        src_fn = ida_funcs.get_func(xref.frm)
        if src_fn is None:
            count += 1
    return count


def _bfs_dist(
    seeds: list[int] | set[int],
    neighbor_fn,
    depth: int,
) -> dict[int, int]:
    distances: dict[int, int] = {}
    queue: deque[int] = deque()

    for seed in seeds:
        if seed in distances:
            continue
        distances[seed] = 0
        queue.append(seed)

    while queue:
        current = queue.popleft()
        cur_depth = distances[current]
        if cur_depth >= depth:
            continue
        for nxt in neighbor_fn(current):
            if nxt in distances:
                continue
            distances[nxt] = cur_depth + 1
            queue.append(nxt)

    return distances


def _shortest_paths(
    start_ea: int,
    end_ea: int,
    depth: int,
    get_callees,
    max_paths: int,
) -> tuple[list[list[int]], int]:
    if start_ea == end_ea:
        return [[start_ea]], 0

    dist: dict[int, int] = {start_ea: 0}
    parents: dict[int, set[int]] = defaultdict(set)
    queue: deque[int] = deque([start_ea])

    while queue:
        current = queue.popleft()
        cur_depth = dist[current]
        if cur_depth >= depth:
            continue
        for callee in get_callees(current):
            nd = cur_depth + 1
            if nd > depth:
                continue
            if callee not in dist:
                dist[callee] = nd
                parents[callee].add(current)
                queue.append(callee)
            elif dist[callee] == nd:
                parents[callee].add(current)

    if end_ea not in dist:
        return [], -1

    shortest = dist[end_ea]
    paths: list[list[int]] = []

    def _build(node: int, suffix: list[int]) -> None:
        if len(paths) >= max_paths:
            return
        if node == start_ea:
            paths.append([start_ea] + suffix)
            return
        parent_list = sorted(parents.get(node, set()))
        for parent in parent_list:
            _build(parent, [node] + suffix)
            if len(paths) >= max_paths:
                return

    _build(end_ea, [])
    return paths, shortest


def _compute_sccs(nodes: list[int], callees: dict[int, set[int]], callers: dict[int, set[int]]) -> list[list[int]]:
    node_set = set(nodes)

    visited: set[int] = set()
    order: list[int] = []
    for start in nodes:
        if start in visited:
            continue
        stack: list[tuple[int, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for nxt in callees.get(node, set()):
                if nxt in node_set and nxt not in visited:
                    stack.append((nxt, False))

    assigned: set[int] = set()
    components: list[list[int]] = []
    for start in reversed(order):
        if start in assigned:
            continue
        comp: list[int] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            comp.append(node)
            for prev in callers.get(node, set()):
                if prev in node_set and prev not in assigned:
                    assigned.add(prev)
                    stack.append(prev)
        components.append(sorted(comp))

    return components


def _common_return(
    rows: list[str],
    *,
    action: str,
    offset: int,
    limit: int,
    key: Optional[str] = None,
    include_items: bool = False,
    item_rows: Optional[list[dict]] = None,
    **extra,
) -> dict:
    page, total, truncated = _paginate(rows, offset, limit)
    result = {
        "ok": True,
        "action": action,
        "matches": "\n".join(page),
        "offset": offset,
        "count": len(page),
        "total": total,
        "truncated": truncated,
    }
    if key:
        result[key] = result["matches"]
    if include_items and item_rows is not None:
        item_page, _, _ = _paginate(item_rows, offset, limit)
        result["items"] = item_page
    result.update(extra)
    return result


@tool
@idaread
def xref_analysis(
    action: Annotated[
        Literal[
            "call_chain",
            "common_callers",
            "common_callees",
            "hub_functions",
            "leaf_functions",
            "recursive",
            "dominator",
            "influence",
            "dependency_graph",
            "dead_functions",
        ],
        "Cross-reference analysis action",
    ],
    addr: Annotated[Optional[str], "Primary function address"] = None,
    addr2: Annotated[Optional[str], "Secondary function address (for chain/common actions)"] = None,
    addrs: Annotated[Optional[str], "Comma-separated addresses for multi-function actions"] = None,
    depth: Annotated[int, "Max search depth"] = 10,
    limit: Annotated[int, "Max results"] = 50,
    offset: Annotated[int, "Pagination offset"] = 0,
    include_items: Annotated[bool, "Include structured items array"] = False,
    direction: Annotated[Literal["forward", "backward", "both"], "Traversal direction for influence/dependency_graph"] = "forward",
) -> dict:
    """
    Cross-reference and callgraph analysis for reverse engineering.

    Actions:
    - call_chain: shortest call path(s) between addr and addr2.
    - common_callers: functions calling all target functions.
    - common_callees: functions called by all target functions.
    - hub_functions: high-centrality functions by in/out degree.
    - leaf_functions: functions with no outgoing calls.
    - recursive: direct + mutual recursion (SCC-based).
    - dominator: likely bottleneck functions on entry-reachable callgraph.
    - influence: reachability fan-out/fan-in from addr.
    - dependency_graph: compact subgraph around one or more seeds.
    - dead_functions: unreachable functions with no inbound/external refs.

    Output defaults to compact text (`matches`) for context efficiency.
    Use `include_items=true` to include structured objects in `items`.
    """
    try:
        limit = _sanitize_limit(limit)
        offset = _sanitize_offset(offset)
        depth = _sanitize_depth(depth)

        callee_cache: dict[int, set[int]] = {}
        caller_cache: dict[int, set[int]] = {}

        def get_callees(func_ea: int) -> set[int]:
            if func_ea in callee_cache:
                return callee_cache[func_ea]
            out: set[int] = set()
            fn = ida_funcs.get_func(func_ea)
            if not fn:
                callee_cache[func_ea] = out
                return out
            for item_ea in idautils.FuncItems(fn.start_ea):
                for xref in idautils.CodeRefsFrom(item_ea, 0):
                    target = ida_funcs.get_func(xref)
                    if not target:
                        continue
                    tgt = int(target.start_ea)
                    if tgt == int(fn.start_ea):
                        continue
                    out.add(tgt)
            callee_cache[func_ea] = out
            return out

        def get_callers(func_ea: int) -> set[int]:
            if func_ea in caller_cache:
                return caller_cache[func_ea]
            out: set[int] = set()
            for xref in idautils.CodeRefsTo(func_ea, 0):
                caller = ida_funcs.get_func(xref)
                if not caller:
                    continue
                src = int(caller.start_ea)
                if src != func_ea:
                    out.add(src)
            caller_cache[func_ea] = out
            return out

        global_graph: Optional[tuple[list[int], dict[int, set[int]], dict[int, set[int]]]] = None

        def build_global_graph() -> tuple[list[int], dict[int, set[int]], dict[int, set[int]]]:
            nonlocal global_graph
            if global_graph is not None:
                return global_graph

            funcs = _all_functions()
            callee_map: dict[int, set[int]] = {}
            caller_map: dict[int, set[int]] = {ea: set() for ea in funcs}

            for ea in funcs:
                cset = set(get_callees(ea))
                callee_map[ea] = cset
                for target in cset:
                    caller_map.setdefault(target, set()).add(ea)
                    callee_map.setdefault(target, set())

            for ea in caller_map:
                callee_map.setdefault(ea, set())

            global_graph = (funcs, callee_map, caller_map)
            return global_graph

        if action == "call_chain":
            if not addr or not addr2:
                return make_error(MCPError.INVALID_ARGS, "call_chain requires addr and addr2")
            start_ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            end_ea, err = validate_addr(addr2, require_func=True)
            if err:
                return err

            paths, shortest = _shortest_paths(start_ea, end_ea, depth, get_callees, max_paths=max(limit * 4, 32))
            path_rows: list[str] = []
            item_rows: list[dict] = []
            for idx, path in enumerate(paths, 1):
                rendered = " -> ".join(_func_name(ea) for ea in path)
                path_rows.append(f"#{idx}  hops={len(path) - 1}  {rendered}")
                item_rows.append(
                    {
                        "index": idx,
                        "hops": len(path) - 1,
                        "path": [{"addr": hex_ea(ea), "name": _func_name(ea)} for ea in path],
                    }
                )

            return _common_return(
                path_rows,
                action=action,
                offset=offset,
                limit=limit,
                key="chains",
                include_items=include_items,
                item_rows=item_rows,
                **{
                    "from": _fmt_func(start_ea),
                    "to": _fmt_func(end_ea),
                    "chain_count": len(paths),
                    "shortest_length": shortest,
                },
            )

        elif action == "common_callers":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets
            if len(targets) < 2:
                return make_error(MCPError.INVALID_ARGS, "common_callers requires at least 2 target functions")

            shared = None
            for ea in targets:
                cset = get_callers(ea)
                shared = set(cset) if shared is None else (shared & cset)
            shared = shared or set()

            ranked = sorted(
                shared,
                key=lambda ea: (len(get_callers(ea)) + len(get_callees(ea)), len(get_callees(ea)), _func_name(ea)),
                reverse=True,
            )
            rows: list[str] = []
            items: list[dict] = []
            for ea in ranked:
                in_deg = len(get_callers(ea))
                out_deg = len(get_callees(ea))
                rows.append(f"{_fmt_func(ea)}  callers={in_deg}  callees={out_deg}")
                items.append({"addr": hex_ea(ea), "name": _func_name(ea), "callers": in_deg, "callees": out_deg})

            target_rows = [_fmt_func(ea) for ea in targets]
            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="common_callers",
                include_items=include_items,
                item_rows=items,
                targets="\n".join(target_rows),
                target_count=len(targets),
            )

        elif action == "common_callees":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets
            if len(targets) < 2:
                return make_error(MCPError.INVALID_ARGS, "common_callees requires at least 2 target functions")

            shared = None
            for ea in targets:
                cset = get_callees(ea)
                shared = set(cset) if shared is None else (shared & cset)
            shared = shared or set()

            ranked = sorted(
                shared,
                key=lambda ea: (len(get_callers(ea)) + len(get_callees(ea)), len(get_callers(ea)), _func_name(ea)),
                reverse=True,
            )
            rows: list[str] = []
            items: list[dict] = []
            for ea in ranked:
                in_deg = len(get_callers(ea))
                out_deg = len(get_callees(ea))
                rows.append(f"{_fmt_func(ea)}  callers={in_deg}  callees={out_deg}")
                items.append({"addr": hex_ea(ea), "name": _func_name(ea), "callers": in_deg, "callees": out_deg})

            target_rows = [_fmt_func(ea) for ea in targets]
            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="common_callees",
                include_items=include_items,
                item_rows=items,
                targets="\n".join(target_rows),
                target_count=len(targets),
            )

        elif action == "hub_functions":
            funcs, callee_map, caller_map = build_global_graph()
            scored: list[tuple[int, int, int, int]] = []
            for ea in funcs:
                in_deg = len(caller_map.get(ea, set()))
                out_deg = len(callee_map.get(ea, set()))
                if in_deg == 0 or out_deg == 0:
                    continue
                score = (in_deg * out_deg) + in_deg + out_deg
                scored.append((score, in_deg, out_deg, ea))

            scored.sort(reverse=True)
            rows: list[str] = []
            items: list[dict] = []
            for score, in_deg, out_deg, ea in scored:
                rows.append(f"{_fmt_func(ea)}  callers={in_deg}  callees={out_deg}  score={score}")
                items.append(
                    {
                        "addr": hex_ea(ea),
                        "name": _func_name(ea),
                        "callers": in_deg,
                        "callees": out_deg,
                        "score": score,
                    }
                )

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="hubs",
                include_items=include_items,
                item_rows=items,
                graph_nodes=len(callee_map),
            )

        elif action == "leaf_functions":
            funcs, callee_map, caller_map = build_global_graph()
            leaves = [ea for ea in funcs if len(callee_map.get(ea, set())) == 0]
            leaves.sort(key=lambda ea: (len(caller_map.get(ea, set())), _func_name(ea)), reverse=True)

            rows: list[str] = []
            items: list[dict] = []
            for ea in leaves:
                caller_cnt = len(caller_map.get(ea, set()))
                rows.append(f"{_fmt_func(ea)}  callers={caller_cnt}")
                items.append({"addr": hex_ea(ea), "name": _func_name(ea), "callers": caller_cnt})

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="leaves",
                include_items=include_items,
                item_rows=items,
                graph_nodes=len(callee_map),
            )

        elif action == "recursive":
            funcs, callee_map, caller_map = build_global_graph()
            comps = _compute_sccs(funcs, callee_map, caller_map)

            recursive_nodes: set[int] = set()
            comp_kind: dict[int, str] = {}
            comp_size: dict[int, int] = {}

            for comp in comps:
                if len(comp) > 1:
                    for ea in comp:
                        recursive_nodes.add(ea)
                        comp_kind[ea] = "mutual"
                        comp_size[ea] = len(comp)
                elif len(comp) == 1:
                    ea = comp[0]
                    if ea in callee_map.get(ea, set()):
                        recursive_nodes.add(ea)
                        comp_kind[ea] = "direct"
                        comp_size[ea] = 1

            ranked = sorted(
                recursive_nodes,
                key=lambda ea: (comp_size.get(ea, 1), len(caller_map.get(ea, set())), _func_name(ea)),
                reverse=True,
            )

            rows: list[str] = []
            items: list[dict] = []
            for ea in ranked:
                kind = comp_kind.get(ea, "unknown")
                size = comp_size.get(ea, 1)
                rows.append(f"{_fmt_func(ea)}  type={kind}  scc_size={size}")
                items.append({"addr": hex_ea(ea), "name": _func_name(ea), "type": kind, "scc_size": size})

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="recursive",
                include_items=include_items,
                item_rows=items,
                component_count=sum(1 for comp in comps if len(comp) > 1),
            )

        elif action == "dominator":
            funcs, callee_map, caller_map = build_global_graph()
            entries = _find_entry_functions()
            if not entries:
                return {"ok": True, "action": action, "dominators": "", "count": 0, "total": 0, "truncated": False}

            full_depth = max(len(callee_map) + 1, _MAX_DEPTH)
            reachable_dist = _bfs_dist(entries, lambda ea: callee_map.get(ea, set()), depth=full_depth)
            reachable = set(reachable_dist.keys())
            if not reachable:
                return {"ok": True, "action": action, "dominators": "", "count": 0, "total": 0, "truncated": False}

            root = -1
            all_nodes = set(reachable) | {root}
            preds: dict[int, set[int]] = {}
            for ea in reachable:
                preds[ea] = set(caller_map.get(ea, set())) & reachable
                if ea in entries:
                    preds[ea].add(root)
            preds[root] = set()

            dom: dict[int, set[int]] = {n: set(all_nodes) for n in all_nodes}
            dom[root] = {root}

            changed = True
            while changed:
                changed = False
                for n in sorted(reachable):
                    pset = preds.get(n, set())
                    if not pset:
                        new_dom = {root, n}
                    else:
                        inter = set(all_nodes)
                        for p in pset:
                            inter &= dom[p]
                        new_dom = inter | {n}
                    if new_dom != dom[n]:
                        dom[n] = new_dom
                        changed = True

            idom: dict[int, int] = {}
            for n in reachable:
                strict = dom[n] - {n}
                if not strict:
                    continue
                best = None
                for cand in strict:
                    if all((other == cand) or (cand not in dom.get(other, set())) for other in strict):
                        best = cand
                        break
                if best is not None:
                    idom[n] = best

            dominated_count: dict[int, int] = defaultdict(int)
            for n in reachable:
                for d in dom[n]:
                    if d in (n, root):
                        continue
                    dominated_count[d] += 1

            ranked = sorted(
                [ea for ea in dominated_count if dominated_count[ea] > 0],
                key=lambda ea: (dominated_count[ea], len(caller_map.get(ea, set())), _func_name(ea)),
                reverse=True,
            )

            rows: list[str] = []
            items: list[dict] = []
            for ea in ranked:
                idom_ea = idom.get(ea)
                idom_str = "root" if idom_ea == root else (hex_ea(idom_ea) if idom_ea is not None else "none")
                rows.append(
                    f"{_fmt_func(ea)}  dominates={dominated_count[ea]}  idom={idom_str}  callers={len(caller_map.get(ea, set()))}"
                )
                items.append(
                    {
                        "addr": hex_ea(ea),
                        "name": _func_name(ea),
                        "dominates": dominated_count[ea],
                        "idom": idom_str,
                        "callers": len(caller_map.get(ea, set())),
                    }
                )

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="dominators",
                include_items=include_items,
                item_rows=items,
                entry_points="\n".join(_fmt_func(ea) for ea in entries),
                reachable_nodes=len(reachable),
            )

        elif action == "influence":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "influence requires addr")
            source_ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            if direction not in ("forward", "backward", "both"):
                return make_error(MCPError.INVALID_ARGS, "direction must be forward|backward|both")

            fwd = _bfs_dist([source_ea], get_callees, depth=depth) if direction in ("forward", "both") else {}
            rev = _bfs_dist([source_ea], get_callers, depth=depth) if direction in ("backward", "both") else {}

            merged: dict[int, dict[str, Any]] = {}
            for ea, d in fwd.items():
                if ea == source_ea:
                    continue
                merged.setdefault(ea, {})["forward_depth"] = d
            for ea, d in rev.items():
                if ea == source_ea:
                    continue
                merged.setdefault(ea, {})["backward_depth"] = d

            ranked = sorted(
                merged.items(),
                key=lambda kv: (
                    min(kv[1].get("forward_depth", 10**9), kv[1].get("backward_depth", 10**9)),
                    kv[0],
                ),
            )

            rows: list[str] = []
            items: list[dict] = []
            for ea, info in ranked:
                fd = info.get("forward_depth")
                bd = info.get("backward_depth")
                depth_bits = []
                if fd is not None:
                    depth_bits.append(f"out={fd}")
                if bd is not None:
                    depth_bits.append(f"in={bd}")
                degree_bits = f"callers={len(get_callers(ea))}  callees={len(get_callees(ea))}"
                rows.append(f"{_fmt_func(ea)}  {'  '.join(depth_bits)}  {degree_bits}")
                item = {"addr": hex_ea(ea), "name": _func_name(ea), **info}
                item["callers"] = len(get_callers(ea))
                item["callees"] = len(get_callees(ea))
                items.append(item)

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="reachable",
                include_items=include_items,
                item_rows=items,
                function=_fmt_func(source_ea),
                reachable_count=len(merged),
                direction=direction,
                depth=depth,
            )

        elif action == "dependency_graph":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets
            if not targets:
                return make_error(MCPError.INVALID_ARGS, "dependency_graph requires at least one target function")
            if direction not in ("forward", "backward", "both"):
                return make_error(MCPError.INVALID_ARGS, "direction must be forward|backward|both")

            node_depth: dict[int, int] = {}
            edge_set: set[tuple[int, int]] = set()
            queue: deque[tuple[int, int]] = deque()

            for ea in targets:
                if ea in node_depth:
                    continue
                node_depth[ea] = 0
                queue.append((ea, 0))

            while queue:
                current, cur_depth = queue.popleft()
                if cur_depth >= depth:
                    continue

                if direction in ("forward", "both"):
                    for callee in get_callees(current):
                        edge_set.add((current, callee))
                        if callee not in node_depth or (cur_depth + 1 < node_depth[callee]):
                            node_depth[callee] = cur_depth + 1
                            queue.append((callee, cur_depth + 1))

                if direction in ("backward", "both"):
                    for caller in get_callers(current):
                        edge_set.add((caller, current))
                        if caller not in node_depth or (cur_depth + 1 < node_depth[caller]):
                            node_depth[caller] = cur_depth + 1
                            queue.append((caller, cur_depth + 1))

            nodes_sorted = sorted(node_depth.keys(), key=lambda ea: (node_depth[ea], _func_name(ea)))
            edges_sorted = sorted(edge_set, key=lambda edge: (_func_name(edge[0]), _func_name(edge[1]), edge[0], edge[1]))

            node_rows = [f"{_fmt_func(ea)}  depth={node_depth[ea]}" for ea in nodes_sorted]
            edge_rows = [
                f"{hex_ea(src)}  {_func_name(src)} -> {hex_ea(dst)}  {_func_name(dst)}"
                for src, dst in edges_sorted
            ]

            edge_page, edge_total, edge_truncated = _paginate(edge_rows, offset, limit)
            node_page, node_total, node_truncated = _paginate(node_rows, offset, limit)

            result = {
                "ok": True,
                "action": action,
                "direction": direction,
                "depth": depth,
                "seeds": "\n".join(_fmt_func(ea) for ea in targets),
                "nodes": "\n".join(node_page),
                "edges": "\n".join(edge_page),
                "matches": "\n".join(edge_page),
                "offset": offset,
                "count": len(edge_page),
                "total": edge_total,
                "truncated": edge_truncated,
                "node_count": node_total,
                "edge_count": edge_total,
                "nodes_truncated": node_truncated,
            }

            if include_items:
                node_items = [
                    {
                        "addr": hex_ea(ea),
                        "name": _func_name(ea),
                        "depth": node_depth[ea],
                    }
                    for ea in nodes_sorted[offset : offset + limit]
                ]
                edge_items = [
                    {
                        "from": hex_ea(src),
                        "from_name": _func_name(src),
                        "to": hex_ea(dst),
                        "to_name": _func_name(dst),
                    }
                    for src, dst in edges_sorted[offset : offset + limit]
                ]
                result["items"] = {"nodes": node_items, "edges": edge_items}

            return result

        elif action == "dead_functions":
            funcs, callee_map, caller_map = build_global_graph()
            entries = set(_find_entry_functions())
            full_depth = max(len(callee_map) + 1, _MAX_DEPTH)
            reachable = set(_bfs_dist(list(entries), lambda ea: callee_map.get(ea, set()), depth=full_depth).keys())

            dead_records: list[tuple[int, int, str, int, int]] = []
            for ea in funcs:
                if ea in entries:
                    continue
                if ea in reachable:
                    continue
                internal_callers = len(caller_map.get(ea, set()))
                external_refs = _count_external_refs(ea)
                if internal_callers > 0 or external_refs > 0:
                    continue
                fn = ida_funcs.get_func(ea)
                size = int(fn.end_ea - fn.start_ea) if fn else 0
                dead_records.append((size, ea, _func_name(ea), internal_callers, external_refs))

            dead_records.sort(key=lambda rec: (rec[0], rec[2]), reverse=True)

            rows: list[str] = []
            items: list[dict] = []
            for size, ea, name, internal_callers, external_refs in dead_records:
                rows.append(
                    f"{hex_ea(ea)}  {name}  size={hex_size(size)}  callers={internal_callers}  ext_refs={external_refs}"
                )
                items.append(
                    {
                        "addr": hex_ea(ea),
                        "name": name,
                        "size": hex_size(size),
                        "callers": internal_callers,
                        "external_refs": external_refs,
                    }
                )

            return _common_return(
                rows,
                action=action,
                offset=offset,
                limit=limit,
                key="dead",
                include_items=include_items,
                item_rows=items,
                entry_points="\n".join(_fmt_func(ea) for ea in sorted(entries)),
                reachable_nodes=len(reachable),
            )

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as exc:
        return handle_error(exc)
