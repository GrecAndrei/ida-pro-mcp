
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# CFG_ANALYSIS - Control Flow Graph Analysis for LLMs
# ============================================================================

def _get_func_flowchart(addr):
    """Get function and its FlowChart. Returns (func, flowchart, error_dict_or_None)."""
    if not addr:
        return None, None, make_error(MCPError.INVALID_ARGS, "addr required")
    ea, err = validate_addr(addr, require_func=True)
    if err:
        return None, None, err
    import ida_gdl
    func = ida_funcs.get_func(ea)
    fc = ida_gdl.FlowChart(func)
    return func, fc, None


def _build_cfg(fc):
    """Build adjacency list and block info from FlowChart."""
    blocks = {}
    succs_map = {}
    preds_map = {}
    for block in fc:
        bid = block.start_ea
        blocks[bid] = (block.start_ea, block.end_ea)
        succs_map[bid] = [s.start_ea for s in block.succs()]
        preds_map.setdefault(bid, [])
        for s in block.succs():
            preds_map.setdefault(s.start_ea, []).append(bid)
    return blocks, succs_map, preds_map


def _compute_dominators(blocks, succs_map, preds_map, entry):
    """Iterative dominator computation."""
    all_nodes = set(blocks.keys())
    dom = {n: set(all_nodes) for n in all_nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in all_nodes:
            if n == entry:
                continue
            preds = preds_map.get(n, [])
            if not preds:
                new_dom = {n}
            else:
                new_dom = set.intersection(*(dom[p] for p in preds if p in dom))
                new_dom = new_dom | {n}
            if new_dom != dom[n]:
                dom[n] = new_dom
                changed = True
    return dom


def _compute_idom(dom, entry):
    """Compute immediate dominators from dominator sets."""
    idom = {}
    for n in dom:
        if n == entry:
            continue
        strict = dom[n] - {n}
        # Immediate dominator = strict dominator that is dominated by every
        # other strict dominator of n (the deepest strict dominator).
        best = None
        for candidate in strict:
            if all(other in dom.get(candidate, set()) for other in strict if other != candidate):
                best = candidate
                break
        if best is not None:
            idom[n] = best
    return idom


@tool
@idaread
def cfg_analysis(
    action: Annotated[Literal["complexity", "loops", "branches", "paths", "dominators", "post_dominators", "back_edges", "natural_loops", "irreducible", "flatten_detect"],
                      "CFG analysis action"],
    addr: Annotated[Optional[str], "Function address"] = None,
    limit: Annotated[int, "Max results"] = 50,
    depth: Annotated[int, "Max path depth"] = 20,
) -> dict:
    """
    Control flow graph analysis for reverse engineering.

    Actions:
    - complexity: Cyclomatic complexity (E - N + 2P) for a function
    - loops: Detect all loops with nesting depth
    - branches: List all conditional branches with their conditions
    - paths: Enumerate paths through function (up to limit)
    - dominators: Compute dominator tree for function CFG
    - post_dominators: Compute post-dominator tree
    - back_edges: Find all back edges (loop indicators)
    - natural_loops: Identify natural loops and their headers
    - irreducible: Detect irreducible control flow (goto-heavy code)
    - flatten_detect: Detect control flow flattening obfuscation
    """
    try:
        func, fc, err = _get_func_flowchart(addr)
        if err:
            return err

        blocks, succs_map, preds_map = _build_cfg(fc)
        if not blocks:
            return {"ok": True, "note": "No basic blocks found"}

        entry = func.start_ea
        num_nodes = len(blocks)
        num_edges = sum(len(s) for s in succs_map.values())

        if action == "complexity":
            # Cyclomatic complexity: E - N + 2P (P=1 for single function)
            cc = num_edges - num_nodes + 2
            return {
                "ok": True,
                "function": idc.get_func_name(entry) or hex(entry),
                "addr": hex(entry),
                "cyclomatic_complexity": cc,
                "num_blocks": num_nodes,
                "num_edges": num_edges,
            }

        elif action == "loops":
            dom = _compute_dominators(blocks, succs_map, preds_map, entry)
            loop_info = []
            for n in blocks:
                for s in succs_map.get(n, []):
                    if s in dom.get(n, set()):
                        # Back edge n -> s, s is loop header
                        # Compute loop body
                        body = {s, n}
                        stack = [n]
                        while stack:
                            cur = stack.pop()
                            for p in preds_map.get(cur, []):
                                if p not in body:
                                    body.add(p)
                                    stack.append(p)
                        loop_info.append(f"header={hex(s)}  back_edge={hex(n)}->{hex(s)}  body_size={len(body)}")
            # Estimate nesting by counting how many loops a block belongs to
            return {"ok": True, "loops": "\n".join(loop_info[:limit]), "count": len(loop_info)}

        elif action == "branches":
            results = []
            for bid, (start, end) in blocks.items():
                successors = succs_map.get(bid, [])
                if len(successors) == 2:
                    # Conditional branch - last instruction of block
                    last_insn = idc.prev_head(end)
                    if last_insn != idaapi.BADADDR:
                        disasm = ida_lines.tag_remove(idc.generate_disasm_line(last_insn, 0))
                        mnem = idc.print_insn_mnem(last_insn)
                        results.append(
                            f"{hex(last_insn)}  {mnem}  true={hex(successors[0])}  false={hex(successors[1])}  {disasm}"
                        )
                    if len(results) >= limit:
                        break
            return {"ok": True, "branches": "\n".join(results), "count": len(results)}

        elif action == "paths":
            # Enumerate paths from entry to exit blocks (blocks with no successors)
            exits = [b for b in blocks if not succs_map.get(b, [])]
            if not exits:
                exits = [max(blocks.keys())]
            paths_found = []

            def dfs_paths(current, target, path, visited):
                if len(paths_found) >= limit:
                    return
                if len(path) > depth:
                    return
                if current == target:
                    paths_found.append(list(path))
                    return
                for s in succs_map.get(current, []):
                    if s not in visited:
                        visited.add(s)
                        path.append(s)
                        dfs_paths(s, target, path, visited)
                        path.pop()
                        visited.discard(s)

            for exit_block in exits:
                if len(paths_found) >= limit:
                    break
                dfs_paths(entry, exit_block, [entry], {entry})

            path_strs = [" -> ".join(hex(b) for b in p) for p in paths_found]
            return {"ok": True, "paths": "\n".join(path_strs), "count": len(paths_found)}

        elif action == "dominators":
            dom = _compute_dominators(blocks, succs_map, preds_map, entry)
            idom = _compute_idom(dom, entry)
            lines = []
            for n in sorted(blocks.keys()):
                parent = idom.get(n)
                lines.append(f"{hex(n)}  idom={hex(parent) if parent else 'root'}")
            return {"ok": True, "dominator_tree": "\n".join(lines[:limit])}

        elif action == "post_dominators":
            # Reverse the CFG for post-dominators
            rev_succs = {n: list(preds_map.get(n, [])) for n in blocks}
            rev_preds = {n: list(succs_map.get(n, [])) for n in blocks}
            exits = [b for b in blocks if not succs_map.get(b, [])]
            if not exits:
                return {"ok": True, "post_dominator_tree": "No exit blocks found"}
            # Use first exit as root for post-dom computation
            exit_node = exits[0]
            pdom = _compute_dominators(blocks, rev_succs, rev_preds, exit_node)
            idom = _compute_idom(pdom, exit_node)
            lines = []
            for n in sorted(blocks.keys()):
                parent = idom.get(n)
                lines.append(f"{hex(n)}  ipdom={hex(parent) if parent else 'root'}")
            return {"ok": True, "post_dominator_tree": "\n".join(lines[:limit])}

        elif action == "back_edges":
            dom = _compute_dominators(blocks, succs_map, preds_map, entry)
            back = []
            for n in blocks:
                for s in succs_map.get(n, []):
                    if s in dom.get(n, set()):
                        back.append(f"{hex(n)} -> {hex(s)}  (header={hex(s)})")
            return {"ok": True, "back_edges": "\n".join(back[:limit]), "count": len(back)}

        elif action == "natural_loops":
            dom = _compute_dominators(blocks, succs_map, preds_map, entry)
            loops = []
            for n in blocks:
                for s in succs_map.get(n, []):
                    if s in dom.get(n, set()):
                        body = {s, n}
                        stack = [n]
                        while stack:
                            cur = stack.pop()
                            for p in preds_map.get(cur, []):
                                if p not in body:
                                    body.add(p)
                                    stack.append(p)
                        body_hex = ", ".join(hex(b) for b in sorted(body))
                        loops.append(f"header={hex(s)}  size={len(body)}  body=[{body_hex}]")
            return {"ok": True, "natural_loops": "\n".join(loops[:limit]), "count": len(loops)}

        elif action == "irreducible":
            dom = _compute_dominators(blocks, succs_map, preds_map, entry)
            # Check for edges where neither node dominates the other (merge without domination)
            irreducible_edges = []
            for n in blocks:
                for s in succs_map.get(n, []):
                    if s != entry and n not in dom.get(s, set()) and s not in dom.get(n, set()):
                        irreducible_edges.append(f"{hex(n)} -> {hex(s)}")
            is_irreducible = len(irreducible_edges) > 0
            return {
                "ok": True,
                "is_irreducible": is_irreducible,
                "suspicious_edges": "\n".join(irreducible_edges[:limit]),
                "count": len(irreducible_edges),
            }

        elif action == "flatten_detect":
            # Heuristic: control flow flattening has a dispatcher block with many successors
            # and most blocks jump back to it
            indicators = []
            dispatcher = None
            max_preds = 0
            for bid in blocks:
                pred_count = len(preds_map.get(bid, []))
                if pred_count > max_preds:
                    max_preds = pred_count
                    dispatcher = bid

            if dispatcher and max_preds > num_nodes * 0.3:
                indicators.append(f"Likely dispatcher at {hex(dispatcher)} with {max_preds} incoming edges")

            # Check for switch-like pattern: one block with many successors
            for bid in blocks:
                succ_count = len(succs_map.get(bid, []))
                if succ_count > 5:
                    indicators.append(f"Switch/dispatch at {hex(bid)} with {succ_count} successors")

            # Check ratio of blocks returning to a single target
            if dispatcher:
                return_to_disp = sum(1 for b in blocks if dispatcher in succs_map.get(b, []))
                ratio = return_to_disp / num_nodes if num_nodes else 0
                if ratio > 0.4:
                    indicators.append(f"Flattening ratio: {ratio:.2f} ({return_to_disp}/{num_nodes} blocks return to dispatcher)")

            is_flattened = len(indicators) >= 2
            return {
                "ok": True,
                "is_flattened": is_flattened,
                "num_blocks": num_nodes,
                "num_edges": num_edges,
                "indicators": "\n".join(indicators) if indicators else "No flattening indicators found",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
