
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from collections import deque


def _get_callees(func_ea):
    """Get set of function addresses called by func_ea."""
    callees = set()
    for item in idautils.FuncItems(func_ea):
        for xref in idautils.CodeRefsFrom(item, 0):
            target = ida_funcs.get_func(xref)
            if target and target.start_ea != func_ea:
                callees.add(target.start_ea)
    return callees


def _get_callers(func_ea):
    """Get set of function addresses that call func_ea."""
    callers = set()
    for xref in idautils.CodeRefsTo(func_ea, 0):
        caller = ida_funcs.get_func(xref)
        if caller and caller.start_ea != func_ea:
            callers.add(caller.start_ea)
    return callers


def _func_label(ea):
    """Return 'name (0xaddr)' label for a function."""
    name = idc.get_func_name(ea)
    return name or f"sub_{ea:x}"


def _all_functions():
    """Yield start_ea for every function in the database."""
    for seg_ea in idautils.Segments():
        for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
            yield func_ea


@tool
@idaread
def xref_analysis(
    action: Annotated[Literal["call_chain", "common_callers", "common_callees",
                              "hub_functions", "leaf_functions", "recursive",
                              "dominator", "influence", "dependency_graph",
                              "dead_functions"],
                      "Cross-reference analysis action"],
    addr: Annotated[Optional[str], "Primary function address"] = None,
    addr2: Annotated[Optional[str], "Secondary function address (for chain/common actions)"] = None,
    addrs: Annotated[Optional[str], "Comma-separated addresses for multi-function actions"] = None,
    depth: Annotated[int, "Max search depth"] = 10,
    limit: Annotated[int, "Max results"] = 50,
) -> dict:
    """
    Deep cross-reference analysis for LLM-assisted reverse engineering.

    ACTIONS:

    call_chain - Find call chains between two functions (BFS shortest path)
        Requires: addr, addr2.  Optional: depth
        Returns: {chains[], shortest_length}
        Example: xref_analysis(action="call_chain", addr="main", addr2="malloc")

    common_callers - Find functions that call ALL of the given functions
        Requires: addr + addr2  OR  addrs (comma-separated)
        Returns: {common_callers[], count}
        Example: xref_analysis(action="common_callers", addr="funcA", addr2="funcB")

    common_callees - Find functions called by ALL of the given functions
        Requires: addr + addr2  OR  addrs (comma-separated)
        Returns: {common_callees[], count}
        Example: xref_analysis(action="common_callees", addrs="0x401000,0x402000")

    hub_functions - Find central hub functions (many callers AND callees)
        Optional: limit
        Returns: {hubs[], count}
        Example: xref_analysis(action="hub_functions", limit=20)

    leaf_functions - Find leaf functions (no outgoing calls)
        Optional: limit
        Returns: {leaves[], count}
        Example: xref_analysis(action="leaf_functions")

    recursive - Find recursive functions (direct or mutual recursion)
        Optional: depth, limit
        Returns: {recursive[], count}
        Example: xref_analysis(action="recursive")

    dominator - Find dominator functions that all paths from entry must traverse
        Optional: limit
        Returns: {dominators[], count}
        Example: xref_analysis(action="dominator")

    influence - Calculate how many functions are reachable from addr
        Requires: addr.  Optional: depth
        Returns: {function, reachable_count, reachable[]}
        Example: xref_analysis(action="influence", addr="main")

    dependency_graph - Build dependency graph for a set of functions
        Requires: addrs (comma-separated).  Optional: depth
        Returns: {nodes[], edges[], node_count, edge_count}
        Example: xref_analysis(action="dependency_graph", addrs="main,sub_401000")

    dead_functions - Find unreachable functions (no callers, not entry points)
        Optional: limit
        Returns: {dead[], count}
        Example: xref_analysis(action="dead_functions")
    """
    try:
        # ---- call_chain: BFS shortest path between two functions ----
        if action == "call_chain":
            if not addr or not addr2:
                return make_error(MCPError.INVALID_ARGS, "call_chain requires addr and addr2")
            ea1, err = validate_addr(addr, require_func=True)
            if err: return err
            ea2, err = validate_addr(addr2, require_func=True)
            if err: return err

            # BFS from ea1 to ea2
            queue = deque([(ea1, [ea1])])
            visited = {ea1}
            chains = []

            while queue and len(chains) < limit:
                cur, path = queue.popleft()
                if len(path) - 1 > depth:
                    continue
                if cur == ea2:
                    chains.append([{"addr": hex_ea(e), "name": _func_label(e)} for e in path])
                    continue
                for callee in _get_callees(cur):
                    if callee not in visited:
                        visited.add(callee)
                        queue.append((callee, path + [callee]))

            shortest = min((len(c) for c in chains), default=0)
            return {
                "ok": True,
                "from": _func_label(ea1),
                "to": _func_label(ea2),
                "chains": chains,
                "chain_count": len(chains),
                "shortest_length": shortest - 1 if shortest else -1,
            }

        # ---- common_callers ----
        elif action == "common_callers":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets  # error
            if len(targets) < 2:
                return make_error(MCPError.INVALID_ARGS, "Need at least 2 functions")

            caller_sets = [_get_callers(ea) for ea in targets]
            common = caller_sets[0]
            for s in caller_sets[1:]:
                common = common & s

            results = sorted(common)[:limit]
            return {
                "ok": True,
                "targets": [{"addr": hex_ea(ea), "name": _func_label(ea)} for ea in targets],
                "common_callers": [{"addr": hex_ea(ea), "name": _func_label(ea)} for ea in results],
                "count": len(common),
            }

        # ---- common_callees ----
        elif action == "common_callees":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets
            if len(targets) < 2:
                return make_error(MCPError.INVALID_ARGS, "Need at least 2 functions")

            callee_sets = [_get_callees(ea) for ea in targets]
            common = callee_sets[0]
            for s in callee_sets[1:]:
                common = common & s

            results = sorted(common)[:limit]
            return {
                "ok": True,
                "targets": [{"addr": hex_ea(ea), "name": _func_label(ea)} for ea in targets],
                "common_callees": [{"addr": hex_ea(ea), "name": _func_label(ea)} for ea in results],
                "count": len(common),
            }

        # ---- hub_functions ----
        elif action == "hub_functions":
            hubs = []
            for func_ea in _all_functions():
                callers = _get_callers(func_ea)
                callees = _get_callees(func_ea)
                if callers and callees:
                    score = len(callers) * len(callees)
                    hubs.append((score, f"{hex_ea(func_ea)}  {_func_label(func_ea)}  callers={len(callers)}  callees={len(callees)}  score={score}"))
            hubs.sort(key=lambda h: h[0], reverse=True)
            hubs = [h[1] for h in hubs]
            hubs = hubs[:limit]
            return {"ok": True, "hubs": "\n".join(hubs), "count": len(hubs)}

        # ---- leaf_functions ----
        elif action == "leaf_functions":
            leaves = []
            for func_ea in _all_functions():
                if not _get_callees(func_ea):
                    leaves.append(f"{hex_ea(func_ea)}  {_func_label(func_ea)}")
                    if len(leaves) >= limit:
                        break
            return {"ok": True, "leaves": "\n".join(leaves), "count": len(leaves)}

        # ---- recursive ----
        elif action == "recursive":
            recursive = []
            for func_ea in _all_functions():
                if len(recursive) >= limit:
                    break
                # Direct recursion: function calls itself
                direct = False
                for item in idautils.FuncItems(func_ea):
                    for xref in idautils.CodeRefsFrom(item, 0):
                        target = ida_funcs.get_func(xref)
                        if target and target.start_ea == func_ea:
                            direct = True
                            break
                    if direct:
                        break
                if direct:
                    recursive.append(f"{hex_ea(func_ea)}  {_func_label(func_ea)}  direct")
                    continue

                # Mutual recursion: check if func_ea is reachable from its callees
                callees = _get_callees(func_ea)
                if not callees:
                    continue
                mutual = False
                visited = set()
                stack = list(callees)
                d = 0
                level_sizes = [len(stack)]
                while stack and d < depth:
                    next_stack = []
                    for c in stack:
                        if c in visited:
                            continue
                        visited.add(c)
                        if c == func_ea:
                            mutual = True
                            break
                        next_stack.extend(_get_callees(c) - visited)
                    if mutual:
                        break
                    stack = next_stack
                    d += 1
                if mutual:
                    recursive.append(f"{hex_ea(func_ea)}  {_func_label(func_ea)}  mutual  depth={d + 1}")
            return {"ok": True, "recursive": "\n".join(recursive), "count": len(recursive)}

        # ---- dominator ----
        elif action == "dominator":
            # Find entry points
            entry_points = set()
            for i in range(idaapi.get_entry_qty()):
                ordinal = idaapi.get_entry_ordinal(i)
                ep_ea = idaapi.get_entry(ordinal)
                if ep_ea != idaapi.BADADDR:
                    func = ida_funcs.get_func(ep_ea)
                    if func:
                        entry_points.add(func.start_ea)

            if not entry_points:
                return {"ok": True, "dominators": [],
                        "count": 0, "note": "No entry points found"}

            # For each entry point, BFS and count how many functions
            # are unreachable without a given function (approximation:
            # functions that ALL entry-reachable paths go through).
            # Simplified: a function dominates if removing it disconnects
            # many functions from all entry points.
            all_funcs = set(_all_functions())
            # First compute full reachable set from entries
            full_reachable = set()
            queue = deque(entry_points)
            while queue:
                cur = queue.popleft()
                if cur in full_reachable:
                    continue
                full_reachable.add(cur)
                for callee in _get_callees(cur):
                    if callee not in full_reachable:
                        queue.append(callee)

            # For candidate dominators: functions with many callers that
            # lie on paths from entries
            candidates = []
            for func_ea in full_reachable:
                if func_ea in entry_points:
                    continue
                callers = _get_callers(func_ea) & full_reachable
                callees = _get_callees(func_ea) & full_reachable
                if not callers or not callees:
                    continue
                candidates.append((func_ea, len(callers), len(callees)))
            # Score by caller count (more callers = more likely dominator)
            candidates.sort(key=lambda x: x[1], reverse=True)

            dominators = []
            for func_ea, caller_cnt, callee_cnt in candidates[:limit]:
                # Approximate: BFS from entries excluding this function
                reachable_without = set()
                queue = deque(entry_points - {func_ea})
                while queue:
                    cur = queue.popleft()
                    if cur in reachable_without:
                        continue
                    reachable_without.add(cur)
                    for callee in _get_callees(cur):
                        if callee != func_ea and callee not in reachable_without:
                            queue.append(callee)
                disconnected = len(full_reachable) - len(reachable_without) - 1
                if disconnected > 0:
                    dominators.append((disconnected, f"{hex_ea(func_ea)}  {_func_label(func_ea)}  disconnects={disconnected}  callers={caller_cnt}"))
            dominators.sort(key=lambda d: d[0], reverse=True)
            dominators = [d[1] for d in dominators]
            dominators = dominators[:limit]
            return {"ok": True, "dominators": "\n".join(dominators), "count": len(dominators)}

        # ---- influence ----
        elif action == "influence":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "influence requires addr")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err

            visited = set()
            queue = deque([(ea, 0)])
            reachable = []

            while queue:
                cur, d = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                if cur != ea:
                    reachable.append((d, f"{hex_ea(cur)}  {_func_label(cur)}  depth={d}"))
                if d < depth:
                    for callee in _get_callees(cur):
                        if callee not in visited:
                            queue.append((callee, d + 1))

            reachable.sort(key=lambda r: r[0])
            reachable = [r[1] for r in reachable]
            return {
                "ok": True,
                "function": _func_label(ea),
                "addr": hex_ea(ea),
                "reachable_count": len(reachable),
                "reachable": reachable[:limit],
            }

        # ---- dependency_graph ----
        elif action == "dependency_graph":
            targets = _resolve_multi_addrs(addr, addr2, addrs)
            if isinstance(targets, dict):
                return targets
            if not targets:
                return make_error(MCPError.INVALID_ARGS, "Need at least one address")

            nodes = {}
            edges = []
            visited = set()

            def traverse(func_ea, d):
                if func_ea in visited or d > depth:
                    return
                visited.add(func_ea)
                nodes[func_ea] = _func_label(func_ea)
                for callee in _get_callees(func_ea):
                    edge = (func_ea, callee)
                    if edge not in edges:
                        edges.append(edge)
                    if callee not in nodes:
                        nodes[callee] = _func_label(callee)
                    traverse(callee, d + 1)

            for ea in targets:
                traverse(ea, 0)

            node_list = [{"addr": hex_ea(ea), "name": name}
                         for ea, name in sorted(nodes.items())]
            edge_list = [{"from": hex_ea(s), "to": hex_ea(d),
                          "from_name": nodes.get(s, ""), "to_name": nodes.get(d, "")}
                         for s, d in edges]
            return {
                "ok": True,
                "nodes": node_list[:limit],
                "edges": edge_list[:limit],
                "node_count": len(nodes),
                "edge_count": len(edges),
            }

        # ---- dead_functions ----
        elif action == "dead_functions":
            entry_points = set()
            for i in range(idaapi.get_entry_qty()):
                ordinal = idaapi.get_entry_ordinal(i)
                ep_ea = idaapi.get_entry(ordinal)
                if ep_ea != idaapi.BADADDR:
                    func = ida_funcs.get_func(ep_ea)
                    if func:
                        entry_points.add(func.start_ea)

            dead = []
            for func_ea in _all_functions():
                if func_ea in entry_points:
                    continue
                callers = _get_callers(func_ea)
                if not callers:
                    dead.append(f"{hex_ea(func_ea)}  {_func_label(func_ea)}")
                    if len(dead) >= limit:
                        break
            return {"ok": True, "dead": "\n".join(dead), "count": len(dead)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


def _resolve_multi_addrs(addr, addr2, addrs):
    """Resolve addr/addr2/addrs into a list of validated EAs. Returns list or error dict."""
    eas = []
    if addrs:
        for part in addrs.split(","):
            part = part.strip()
            if not part:
                continue
            ea, err = validate_addr(part, require_func=True)
            if err:
                return err
            eas.append(ea)
    if addr:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return err
        if ea not in eas:
            eas.insert(0, ea)
    if addr2:
        ea, err = validate_addr(addr2, require_func=True)
        if err:
            return err
        if ea not in eas:
            eas.append(ea)
    return eas
