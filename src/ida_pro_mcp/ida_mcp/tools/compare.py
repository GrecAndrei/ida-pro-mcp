
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# COMPARE - Function Comparison and Similarity Analysis
# ============================================================================

@tool
@idaread
def compare(
    action: Annotated[Literal["functions", "blocks", "apis", "strings", "constants",
                               "structure", "semantics", "batch_compare",
                               "find_clones", "changelog"],
                      "Comparison action"],
    addr: Annotated[Optional[str], "First function address"] = None,
    addr2: Annotated[Optional[str], "Second function address"] = None,
    addrs: Annotated[Optional[str], "Comma-separated addresses for batch_compare"] = None,
    threshold: Annotated[float, "Similarity threshold (0.0-1.0)"] = 0.7,
    limit: Annotated[int, "Max results"] = 30,
) -> dict:
    """
    Compare functions for similarity, structural differences, and clone detection.

    ACTIONS:

    functions - Compare two functions side-by-side (pseudocode diff, size, complexity, shared APIs)
        Params: addr, addr2
        Returns: {similarity, size1, size2, diff, shared_apis}

    blocks - Compare basic blocks between two functions
        Params: addr, addr2
        Returns: {blocks1, blocks2, matched, unmatched}

    apis - Compare API/callee usage between two functions
        Params: addr, addr2
        Returns: {apis1, apis2, shared, only1, only2, jaccard}

    strings - Compare string references between two functions
        Params: addr, addr2
        Returns: {strings1, strings2, shared, only1, only2, jaccard}

    constants - Compare immediate/constant values between two functions
        Params: addr, addr2
        Returns: {constants1, constants2, shared, only1, only2, jaccard}

    structure - Compare structural features (block count, edges, cyclomatic complexity)
        Params: addr, addr2
        Returns: {func1, func2, block_diff, edge_diff, complexity_diff}

    semantics - Semantic comparison (call patterns, data flow shape)
        Params: addr, addr2
        Returns: {call_seq1, call_seq2, similarity, data_refs1, data_refs2}

    batch_compare - Compare one function against multiple, return similarity scores
        Params: addr, addrs, threshold, limit
        Returns: {results: [{addr, name, similarity}]}

    find_clones - Find code clones / near-duplicates across the binary
        Params: threshold, limit
        Returns: {clones: [{group, functions}]}

    changelog - Compare function against a reference snapshot (highlight changes)
        Params: addr, addr2
        Returns: {added, removed, changed, diff}
    """
    try:
        import difflib
        import hashlib

        # -- helpers ----------------------------------------------------------

        def _resolve_func(address, label="addr"):
            """Resolve address to function EA, returning (ea, error_dict_or_None)."""
            if not address:
                return None, make_error(MCPError.INVALID_ARGS, f"{label} required")
            ea, err = validate_addr(address, require_func=True)
            if err:
                return None, err
            return ea, None

        def _decompile_lines(ea):
            """Return cleaned pseudocode lines for *ea*."""
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return []
            return [ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode()]

        def _get_callees(ea):
            """Return set of callee names for the function at *ea*."""
            func = ida_funcs.get_func(ea)
            if not func:
                return set()
            callees = set()
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.CodeRefsFrom(head, 0):
                    name = idc.get_func_name(xref)
                    if name:
                        callees.add(name)
            return callees

        def _get_string_refs(ea):
            """Return set of strings referenced inside the function at *ea*."""
            func = ida_funcs.get_func(ea)
            if not func:
                return set()
            strings = set()
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for dref in idautils.DataRefsFrom(head):
                    stype = idc.get_str_type(dref)
                    if stype is not None and stype >= 0:
                        s = idc.get_strlit_contents(dref, -1, stype)
                        if s:
                            strings.add(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s)
            return strings

        def _get_constants(ea):
            """Return set of immediate operand values inside the function."""
            func = ida_funcs.get_func(ea)
            if not func:
                return set()
            constants = set()
            for head in idautils.Heads(func.start_ea, func.end_ea):
                if not idc.is_code(idc.get_full_flags(head)):
                    continue
                for n in range(2):
                    optype = idc.get_operand_type(head, n)
                    if optype == idc.o_imm:
                        val = idc.get_operand_value(head, n)
                        if val not in (0, 1, -1):
                            constants.add(val)
            return constants

        def _jaccard(s1, s2):
            """Jaccard similarity between two sets."""
            if not s1 and not s2:
                return 1.0
            union = s1 | s2
            if not union:
                return 1.0
            return round(len(s1 & s2) / len(union), 3)

        def _flowchart_info(ea):
            """Return (block_count, edge_count, cyclomatic_complexity) for *ea*."""
            func = ida_funcs.get_func(ea)
            if not func:
                return 0, 0, 0
            fc = idaapi.FlowChart(func)
            blocks = list(fc)
            block_count = len(blocks)
            edge_count = 0
            for block in blocks:
                for succ_idx in range(block.nsucc()):
                    edge_count += 1
            complexity = edge_count - block_count + 2
            return block_count, edge_count, complexity

        def _mnemonic_hash(ea):
            """Hash the mnemonic sequence of a function for clone detection."""
            func = ida_funcs.get_func(ea)
            if not func:
                return None
            mnemonics = []
            for head in idautils.Heads(func.start_ea, func.end_ea):
                if idc.is_code(idc.get_full_flags(head)):
                    mnemonics.append(idc.print_insn_mnem(head))
            if not mnemonics:
                return None
            return hashlib.md5("|".join(mnemonics).encode()).hexdigest()

        # -- actions ----------------------------------------------------------

        if action == "functions":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            lines1 = _decompile_lines(ea1)
            lines2 = _decompile_lines(ea2)
            matcher = difflib.SequenceMatcher(None, lines1, lines2)
            udiff = list(difflib.unified_diff(lines1, lines2, lineterm=""))

            f1 = ida_funcs.get_func(ea1)
            f2 = ida_funcs.get_func(ea2)
            size1 = f1.end_ea - f1.start_ea if f1 else 0
            size2 = f2.end_ea - f2.start_ea if f2 else 0

            shared_apis = sorted(_get_callees(ea1) & _get_callees(ea2))

            return {
                "ok": True,
                "func1": idc.get_func_name(ea1) or hex_ea(ea1),
                "func2": idc.get_func_name(ea2) or hex_ea(ea2),
                "similarity": round(matcher.ratio(), 3),
                "size1": size1,
                "size2": size2,
                "added": len([l for l in udiff if l.startswith("+") and not l.startswith("+++")]),
                "removed": len([l for l in udiff if l.startswith("-") and not l.startswith("---")]),
                "shared_apis": shared_apis,
                "diff": udiff[:50],
            }

        elif action == "blocks":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            def _block_info(ea):
                func = ida_funcs.get_func(ea)
                if not func:
                    return []
                fc = idaapi.FlowChart(func)
                result = []
                for block in fc:
                    mnemonics = []
                    for head in idautils.Heads(block.start_ea, block.end_ea):
                        if idc.is_code(idc.get_full_flags(head)):
                            mnemonics.append(idc.print_insn_mnem(head))
                    result.append({
                        "start": hex_ea(block.start_ea),
                        "size": block.end_ea - block.start_ea,
                        "insn_count": len(mnemonics),
                        "mnemonics": " ".join(mnemonics),
                    })
                return result

            b1 = _block_info(ea1)
            b2 = _block_info(ea2)

            # Match blocks by mnemonic sequence similarity
            matched = []
            unmatched1 = list(range(len(b1)))
            unmatched2 = list(range(len(b2)))
            for i, blk1 in enumerate(b1):
                best_j, best_sim = -1, 0.0
                for j in unmatched2:
                    sim = difflib.SequenceMatcher(None, blk1["mnemonics"], b2[j]["mnemonics"]).ratio()
                    if sim > best_sim:
                        best_sim = sim
                        best_j = j
                if best_sim >= threshold and best_j >= 0:
                    matched.append(f"{blk1['start']}={b2[best_j]['start']}  sim={round(best_sim, 3)}")
                    if i in unmatched1:
                        unmatched1.remove(i)
                    if best_j in unmatched2:
                        unmatched2.remove(best_j)

            return {
                "ok": True,
                "blocks1": len(b1),
                "blocks2": len(b2),
                "matched": "\n".join(str(x) for x in matched[:limit]),
                "unmatched1": [b1[i]["start"] for i in unmatched1][:limit],
                "unmatched2": [b2[j]["start"] for j in unmatched2][:limit],
            }

        elif action == "apis":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            apis1 = _get_callees(ea1)
            apis2 = _get_callees(ea2)
            return {
                "ok": True,
                "apis1": sorted(apis1),
                "apis2": sorted(apis2),
                "shared": sorted(apis1 & apis2),
                "only1": sorted(apis1 - apis2),
                "only2": sorted(apis2 - apis1),
                "jaccard": _jaccard(apis1, apis2),
            }

        elif action == "strings":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            s1 = _get_string_refs(ea1)
            s2 = _get_string_refs(ea2)
            return {
                "ok": True,
                "strings1": sorted(s1),
                "strings2": sorted(s2),
                "shared": sorted(s1 & s2),
                "only1": sorted(s1 - s2),
                "only2": sorted(s2 - s1),
                "jaccard": _jaccard(s1, s2),
            }

        elif action == "constants":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            c1 = _get_constants(ea1)
            c2 = _get_constants(ea2)
            return {
                "ok": True,
                "constants1": sorted(hex(v) for v in c1),
                "constants2": sorted(hex(v) for v in c2),
                "shared": sorted(hex(v) for v in c1 & c2),
                "only1": sorted(hex(v) for v in c1 - c2),
                "only2": sorted(hex(v) for v in c2 - c1),
                "jaccard": _jaccard(c1, c2),
            }

        elif action == "structure":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            bc1, ec1, cc1 = _flowchart_info(ea1)
            bc2, ec2, cc2 = _flowchart_info(ea2)
            return {
                "ok": True,
                "func1": {
                    "name": idc.get_func_name(ea1) or hex_ea(ea1),
                    "blocks": bc1, "edges": ec1, "complexity": cc1,
                },
                "func2": {
                    "name": idc.get_func_name(ea2) or hex_ea(ea2),
                    "blocks": bc2, "edges": ec2, "complexity": cc2,
                },
                "block_diff": bc1 - bc2,
                "edge_diff": ec1 - ec2,
                "complexity_diff": cc1 - cc2,
            }

        elif action == "semantics":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            def _call_sequence(ea):
                """Ordered list of calls made inside a function."""
                func = ida_funcs.get_func(ea)
                if not func:
                    return []
                seq = []
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    if not idc.is_code(idc.get_full_flags(head)):
                        continue
                    for xref in idautils.CodeRefsFrom(head, 0):
                        name = idc.get_func_name(xref)
                        if name:
                            seq.append(name)
                return seq

            def _data_ref_set(ea):
                """Set of data addresses referenced by the function."""
                func = ida_funcs.get_func(ea)
                if not func:
                    return set()
                refs = set()
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for dref in idautils.DataRefsFrom(head):
                        refs.add(dref)
                return refs

            cs1 = _call_sequence(ea1)
            cs2 = _call_sequence(ea2)
            dr1 = _data_ref_set(ea1)
            dr2 = _data_ref_set(ea2)

            call_sim = difflib.SequenceMatcher(None, cs1, cs2).ratio()
            data_jaccard = _jaccard(dr1, dr2)

            return {
                "ok": True,
                "call_seq1": cs1[:limit],
                "call_seq2": cs2[:limit],
                "call_similarity": round(call_sim, 3),
                "data_refs1": len(dr1),
                "data_refs2": len(dr2),
                "data_jaccard": data_jaccard,
                "overall_similarity": round((call_sim + data_jaccard) / 2, 3),
            }

        elif action == "batch_compare":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            if not addrs:
                return make_error(MCPError.INVALID_ARGS, "addrs (comma-separated) required")

            target_lines = _decompile_lines(ea1)
            results = []
            for raw in addrs.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                ea_other, err = validate_addr(raw, require_func=True)
                if err:
                    continue
                other_lines = _decompile_lines(ea_other)
                sim = difflib.SequenceMatcher(None, target_lines, other_lines).ratio()
                if sim >= threshold:
                    results.append((round(sim, 3), f"{hex_ea(ea_other)}  {idc.get_func_name(ea_other) or hex_ea(ea_other)}  sim={round(sim, 3)}"))
            results.sort(key=lambda r: r[0], reverse=True)
            return {"ok": True, "target": idc.get_func_name(ea1) or hex_ea(ea1),
                    "results": "\n".join(r[1] for r in results[:limit])}

        elif action == "find_clones":
            # Hash each function by its mnemonic sequence, group duplicates
            hash_map: dict[str, list] = {}
            for func_ea in idautils.Functions():
                h = _mnemonic_hash(func_ea)
                if h is None:
                    continue
                func = ida_funcs.get_func(func_ea)
                size = (func.end_ea - func.start_ea) if func else 0
                if size < 8:
                    continue
                entry = {"addr": hex_ea(func_ea),
                         "name": idc.get_func_name(func_ea) or hex_ea(func_ea),
                         "size": size}
                hash_map.setdefault(h, []).append(entry)

            clones = []
            for h, funcs_list in hash_map.items():
                if len(funcs_list) >= 2:
                    funcs_str = ", ".join(funcs_list[:5])
                    clones.append((len(funcs_list), f"hash={h}  count={len(funcs_list)}  {funcs_str}"))
                if len(clones) >= limit:
                    break
            clones.sort(key=lambda c: c[0], reverse=True)
            return {"ok": True, "clone_groups": len(clones), "clones": "\n".join(c[1] for c in clones[:limit])}

        elif action == "changelog":
            ea1, err = _resolve_func(addr, "addr")
            if err: return err
            ea2, err = _resolve_func(addr2, "addr2")
            if err: return err

            lines1 = _decompile_lines(ea1)
            lines2 = _decompile_lines(ea2)
            udiff = list(difflib.unified_diff(lines1, lines2,
                                               fromfile=idc.get_func_name(ea1) or hex_ea(ea1),
                                               tofile=idc.get_func_name(ea2) or hex_ea(ea2),
                                               lineterm=""))

            added = [l for l in udiff if l.startswith("+") and not l.startswith("+++")]
            removed = [l for l in udiff if l.startswith("-") and not l.startswith("---")]

            # Structural delta
            bc1, ec1, cc1 = _flowchart_info(ea1)
            bc2, ec2, cc2 = _flowchart_info(ea2)

            return {
                "ok": True,
                "reference": idc.get_func_name(ea1) or hex_ea(ea1),
                "current": idc.get_func_name(ea2) or hex_ea(ea2),
                "added_lines": len(added),
                "removed_lines": len(removed),
                "complexity_delta": cc2 - cc1,
                "block_delta": bc2 - bc1,
                "diff": udiff[:50],
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
