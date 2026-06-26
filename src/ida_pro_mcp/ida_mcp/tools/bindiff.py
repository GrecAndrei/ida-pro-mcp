
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# BINDIFF - Binary Diffing via Snapshots (cross-IDB / cross-version comparison)
# ============================================================================

import hashlib
import json
import difflib


# -- helpers ------------------------------------------------------------------

def _mnemonic_hash(ea, max_insns=10000):
    """Hash the mnemonic sequence of a function for fingerprinting."""
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    mnemonics = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            mnemonics.append(idc.print_insn_mnem(head))
            if len(mnemonics) >= max_insns:
                break
    if not mnemonics:
        return None
    return hashlib.md5("|".join(mnemonics).encode()).hexdigest()


def _func_name(ea):
    """Return the function name or hex address as a string key."""
    name = idc.get_func_name(ea)
    if name and not name.startswith("sub_"):
        return name
    return hex_ea(ea)


def _get_callees(ea):
    """Return sorted list of callee names for the function at ea."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    callees = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            name = idc.get_func_name(xref)
            if name:
                callees.add(name)
    return sorted(callees)


def _get_constants(ea):
    """Return sorted list of immediate operand values inside the function."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    constants = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if not idc.is_code(idc.get_full_flags(head)):
            continue
        for n in range(2):
            if idc.get_operand_type(head, n) == idc.o_imm:
                val = idc.get_operand_value(head, n)
                if val not in (0, 1, -1):
                    constants.add(val)
    return sorted(constants)


def _get_string_refs(ea):
    """Return sorted list of strings referenced inside the function."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    strings = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for dref in idautils.DataRefsFrom(head):
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                s = idc.get_strlit_contents(dref, -1, stype)
                if s:
                    strings.add(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s)
    return sorted(strings)


def _flowchart_info(ea):
    """Return (block_count, edge_count) for the function at ea."""
    func = ida_funcs.get_func(ea)
    if not func:
        return 0, 0
    fc = idaapi.FlowChart(func)
    blocks = list(fc)
    block_count = len(blocks)
    edge_count = 0
    for block in blocks:
        edge_count += len(list(block.succs()))
    return block_count, edge_count


def _fingerprint_function(ea):
    """Build a fingerprint dict for a single function."""
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    size = func.end_ea - func.start_ea
    block_count, edge_count = _flowchart_info(ea)
    return {
        "addr": hex_ea(ea),
        "size": size,
        "mnemonic_hash": _mnemonic_hash(ea),
        "block_count": block_count,
        "edge_count": edge_count,
        "callees": _get_callees(ea),
        "constants": _get_constants(ea),
        "string_refs": _get_string_refs(ea),
    }


def _resolve_snapshot(snapshot):
    """Resolve a snapshot from a dict or JSON string/path. Returns (dict, error)."""
    if isinstance(snapshot, dict):
        return snapshot, None
    if isinstance(snapshot, str):
        try:
            parsed = json.loads(snapshot)
            if isinstance(parsed, dict):
                return parsed, None
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            with open(snapshot, "r") as f:
                return json.load(f), None
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    return None, make_error(MCPError.INVALID_ARGS,
                            "snapshot must be a dict, JSON string, or valid file path")


_SECURITY_APIS = {
    "malloc", "free", "realloc", "calloc", "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
    "open", "read", "write", "recv", "send", "socket", "connect", "bind",
    "exec", "system", "popen", "CreateProcess", "VirtualAlloc",
    "VirtualProtect", "HeapAlloc", "HeapFree", "CryptEncrypt", "CryptDecrypt",
}


# -- main tool ----------------------------------------------------------------

@tool
@idaread
def bindiff(
    action: Annotated[Literal["snapshot", "diff", "patch_analysis", "function_match", "summary"],
                      "Action: snapshot|diff|patch_analysis|function_match|summary"],
    addr: Annotated[Optional[str], "Function address (for patch_analysis)"] = None,
    snapshot: Annotated[Optional[Any], "Previous snapshot dict or JSON string/path"] = None,
    limit: Annotated[int, "Max results to return"] = 50,
    threshold: Annotated[float, "Match confidence threshold (0.0-1.0)"] = 0.6,
    **kwargs
) -> dict:
    """
    Binary diffing via snapshots - compare across IDB versions or saved baselines.

    ACTIONS:

    snapshot - Fingerprint all functions → {functions: {name: {addr, size, mnemonic_hash, block_count, edge_count, callees, constants, string_refs}}}

    diff - Compare current state against snapshot → {new/removed/modified functions with deltas}
        Params: snapshot

    patch_analysis - Focused single-function diff with block-level detail and security notes
        Params: addr, snapshot

    function_match - Match functions between snapshot and current binary via multiple heuristics
        Params: snapshot, threshold

    summary - High-level diff summary with security impact assessment and change categories
        Params: snapshot
    """
    try:
        if action == "snapshot":
            functions = {}
            for func_ea in idautils.Functions():
                fp = _fingerprint_function(func_ea)
                if fp is None:
                    continue
                key = _func_name(func_ea)
                functions[key] = fp
            return {
                "ok": True,
                "function_count": len(functions),
                "functions": functions,
            }

        elif action == "diff":
            if not snapshot:
                return make_error(MCPError.INVALID_ARGS, "snapshot required for diff action")
            snap, err = _resolve_snapshot(snapshot)
            if err:
                return err
            snap_funcs = snap.get("functions", snap)

            # Build current state
            current = {}
            for func_ea in idautils.Functions():
                key = _func_name(func_ea)
                current[key] = _fingerprint_function(func_ea)

            snap_keys = set(snap_funcs.keys())
            curr_keys = set(current.keys())

            new_funcs = sorted(curr_keys - snap_keys)
            removed_funcs = sorted(snap_keys - curr_keys)
            common = snap_keys & curr_keys

            modified = []
            for name in sorted(common):
                old = snap_funcs[name]
                cur = current[name]
                if cur is None:
                    continue
                changes = {}
                # Size delta
                if old.get("size", 0) != cur.get("size", 0):
                    changes["size_delta"] = cur["size"] - old.get("size", 0)
                if old.get("mnemonic_hash") != cur.get("mnemonic_hash"):
                    changes["code_changed"] = True
                if old.get("block_count", 0) != cur.get("block_count", 0):
                    changes["block_delta"] = cur["block_count"] - old.get("block_count", 0)
                old_c, cur_c = set(old.get("callees", [])), set(cur.get("callees", []))
                if old_c != cur_c:
                    if cur_c - old_c: changes["new_callees"] = sorted(cur_c - old_c)
                    if old_c - cur_c: changes["removed_callees"] = sorted(old_c - cur_c)
                old_k, cur_k = set(old.get("constants", [])), set(cur.get("constants", []))
                if old_k != cur_k:
                    if cur_k - old_k: changes["new_constants"] = [hex(v) if isinstance(v, int) else v for v in sorted(cur_k - old_k)]
                    if old_k - cur_k: changes["removed_constants"] = [hex(v) if isinstance(v, int) else v for v in sorted(old_k - cur_k)]

                if changes:
                    changes["name"] = name
                    modified.append(changes)

            return {
                "ok": True,
                "new_functions": new_funcs[:limit],
                "new_count": len(new_funcs),
                "removed_functions": removed_funcs[:limit],
                "removed_count": len(removed_funcs),
                "modified_functions": modified[:limit],
                "modified_count": len(modified),
                "total_current": len(current),
                "total_snapshot": len(snap_funcs),
            }

        elif action == "patch_analysis":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for patch_analysis")
            if not snapshot:
                return make_error(MCPError.INVALID_ARGS, "snapshot required for patch_analysis")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            snap, err = _resolve_snapshot(snapshot)
            if err:
                return err
            snap_funcs = snap.get("functions", snap)

            func_key = _func_name(ea)
            old_fp = snap_funcs.get(func_key)
            if not old_fp:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Function '{func_key}' not found in snapshot")

            cur_fp = _fingerprint_function(ea)
            if not cur_fp:
                return make_error(MCPError.INVALID_ARGS, "Cannot fingerprint current function")

            # Block-level analysis
            func = ida_funcs.get_func(ea)
            fc = idaapi.FlowChart(func)
            block_hashes = []
            for block in fc:
                mnemonics = []
                for head in idautils.Heads(block.start_ea, block.end_ea):
                    if idc.is_code(idc.get_full_flags(head)):
                        mnemonics.append(idc.print_insn_mnem(head))
                bh = hashlib.md5("|".join(mnemonics).encode()).hexdigest() if mnemonics else None
                block_hashes.append({
                    "addr": hex_ea(block.start_ea),
                    "size": block.end_ea - block.start_ea,
                    "insn_count": len(mnemonics),
                    "hash": bh,
                })

            # Callee changes
            old_callees = set(old_fp.get("callees", []))
            cur_callees = set(cur_fp.get("callees", []))
            new_callees = sorted(cur_callees - old_callees)
            removed_callees = sorted(old_callees - cur_callees)

            # Constant changes
            old_consts = set(old_fp.get("constants", []))
            cur_consts = set(cur_fp.get("constants", []))
            new_consts = sorted(cur_consts - old_consts)
            removed_consts = sorted(old_consts - cur_consts)

            # String ref changes
            old_strings = set(old_fp.get("string_refs", []))
            cur_strings = set(_get_string_refs(ea))
            new_strings = sorted(cur_strings - old_strings)
            removed_strings = sorted(old_strings - cur_strings)

            # Security notes
            security_notes = []
            dangerous_new = set(new_callees) & _SECURITY_APIS
            dangerous_removed = set(removed_callees) & _SECURITY_APIS
            if dangerous_new:
                security_notes.append(f"New security-relevant APIs: {sorted(dangerous_new)}")
            if dangerous_removed:
                security_notes.append(f"Removed security-relevant APIs: {sorted(dangerous_removed)}")
            old_blocks, cur_blocks = old_fp.get("block_count", 0), cur_fp.get("block_count", 0)
            if cur_blocks > old_blocks:
                security_notes.append(f"+{cur_blocks - old_blocks} block(s) - possible new checks")
            elif cur_blocks < old_blocks:
                security_notes.append(f"-{old_blocks - cur_blocks} block(s) - possible removed handling")

            return {
                "ok": True,
                "function": func_key,
                "size_delta": cur_fp["size"] - old_fp.get("size", 0),
                "code_changed": old_fp.get("mnemonic_hash") != cur_fp.get("mnemonic_hash"),
                "block_count_old": old_blocks,
                "block_count_new": cur_blocks,
                "current_blocks": block_hashes[:limit],
                "new_callees": new_callees,
                "removed_callees": removed_callees,
                "new_constants": [hex(v) if isinstance(v, int) else v for v in new_consts],
                "removed_constants": [hex(v) if isinstance(v, int) else v for v in removed_consts],
                "new_strings": new_strings,
                "removed_strings": removed_strings,
                "security_notes": security_notes,
            }

        elif action == "function_match":
            if not snapshot:
                return make_error(MCPError.INVALID_ARGS, "snapshot required for function_match")
            snap, err = _resolve_snapshot(snapshot)
            if err:
                return err
            snap_funcs = snap.get("functions", snap)

            # Build current indices
            current_by_name, current_by_hash, current_by_callees = {}, {}, {}
            for func_ea in idautils.Functions():
                key = _func_name(func_ea)
                fp = _fingerprint_function(func_ea)
                if fp is None:
                    continue
                current_by_name[key] = fp
                mh = fp.get("mnemonic_hash")
                if mh:
                    current_by_hash.setdefault(mh, []).append(key)
                ck = "|".join(sorted(fp.get("callees", [])))
                if ck:
                    current_by_callees.setdefault(ck, []).append(key)

            matches, matched_snap, matched_curr = [], set(), set()

            # Pass 1: Exact name match
            for snap_name in snap_funcs:
                if snap_name in current_by_name:
                    matches.append({"snapshot_name": snap_name, "current_name": snap_name,
                                    "confidence": 1.0, "method": "exact_name"})
                    matched_snap.add(snap_name)
                    matched_curr.add(snap_name)

            # Pass 2: Mnemonic hash match (renamed but same code)
            for snap_name, snap_fp in snap_funcs.items():
                if snap_name in matched_snap:
                    continue
                mh = snap_fp.get("mnemonic_hash")
                if not mh:
                    continue
                for cand in current_by_hash.get(mh, []):
                    if cand in matched_curr:
                        continue
                    matches.append({"snapshot_name": snap_name, "current_name": cand,
                                    "confidence": 0.95, "method": "mnemonic_hash"})
                    matched_snap.add(snap_name)
                    matched_curr.add(cand)
                    break

            # Pass 3: Callee signature match
            for snap_name, snap_fp in snap_funcs.items():
                if snap_name in matched_snap:
                    continue
                callees_key = "|".join(sorted(snap_fp.get("callees", [])))
                if not callees_key:
                    continue
                for cand in current_by_callees.get(callees_key, []):
                    if cand in matched_curr:
                        continue
                    cur_fp = current_by_name.get(cand)
                    if cur_fp and snap_fp.get("size", 0) > 0 and cur_fp.get("size", 0) > 0:
                        if min(snap_fp["size"], cur_fp["size"]) / max(snap_fp["size"], cur_fp["size"]) < 0.3:
                            continue
                    matches.append({"snapshot_name": snap_name, "current_name": cand,
                                    "confidence": 0.8, "method": "callee_signature"})
                    matched_snap.add(snap_name)
                    matched_curr.add(cand)
                    break

            # Pass 4: Fuzzy structural match (similar CFG shape + size)
            unmatched_snaps = [(n, f) for n, f in snap_funcs.items()
                               if n not in matched_snap and f.get("size", 0) > 0]
            for snap_name, snap_fp in unmatched_snaps[:200]:
                snap_blocks = snap_fp.get("block_count", 0)
                snap_edges = snap_fp.get("edge_count", 0)
                snap_size = snap_fp["size"]
                best_match, best_score = None, 0.0
                for cur_name, cur_fp in current_by_name.items():
                    if cur_name in matched_curr:
                        continue
                    cur_size = cur_fp.get("size", 0)
                    if cur_size == 0:
                        continue
                    size_sim = min(snap_size, cur_size) / max(snap_size, cur_size)
                    block_sim = 1.0 - abs(snap_blocks - cur_fp.get("block_count", 0)) / max(snap_blocks, cur_fp.get("block_count", 0), 1)
                    edge_sim = 1.0 - abs(snap_edges - cur_fp.get("edge_count", 0)) / max(snap_edges, cur_fp.get("edge_count", 0), 1)
                    score = size_sim * 0.4 + block_sim * 0.3 + edge_sim * 0.3
                    if score > best_score:
                        best_score = score
                        best_match = cur_name
                if best_match and best_score >= threshold:
                    matches.append({
                        "snapshot_name": snap_name, "current_name": best_match,
                        "confidence": round(best_score, 3), "method": "structural_fuzzy",
                    })
                    matched_snap.add(snap_name)
                    matched_curr.add(best_match)

            # Sort by confidence descending
            matches.sort(key=lambda m: m["confidence"], reverse=True)
            return {
                "ok": True,
                "matches": matches[:limit],
                "total_matched": len(matches),
                "unmatched_snapshot": len(snap_funcs) - len(matched_snap),
                "unmatched_current": len(current_by_name) - len(matched_curr),
            }

        elif action == "summary":
            if not snapshot:
                return make_error(MCPError.INVALID_ARGS, "snapshot required for summary")
            snap, err = _resolve_snapshot(snapshot)
            if err:
                return err
            snap_funcs = snap.get("functions", snap)

            # Build current state
            current = {}
            for func_ea in idautils.Functions():
                key = _func_name(func_ea)
                current[key] = _fingerprint_function(func_ea)

            snap_keys = set(snap_funcs.keys())
            curr_keys = set(current.keys())
            new_funcs = curr_keys - snap_keys
            removed_funcs = snap_keys - curr_keys
            common = snap_keys & curr_keys

            modified_names, total_size_delta = [], 0
            security_modified, new_dangerous_apis = [], set()
            cats = {"bugfix": [], "feature": [], "refactor": [], "security": []}
            for name in common:
                old, cur = snap_funcs[name], current[name]
                if cur is None or old.get("mnemonic_hash") == cur.get("mnemonic_hash"):
                    continue
                modified_names.append(name)
                size_d = cur.get("size", 0) - old.get("size", 0)
                total_size_delta += size_d
                added_apis = set(cur.get("callees", [])) - set(old.get("callees", []))
                dangerous = added_apis & _SECURITY_APIS
                if dangerous:
                    new_dangerous_apis.update(dangerous)
                    security_modified.append(name)
                    cats["security"].append(name)
                elif cur.get("block_count", 0) > old.get("block_count", 0) and size_d < 50:
                    cats["bugfix"].append(name)
                elif len(added_apis) > 3 or size_d > 200:
                    cats["feature"].append(name)
                else:
                    cats["refactor"].append(name)

            security_new_funcs = [n for n in list(new_funcs)[:200]
                                  if current.get(n) and set(current[n].get("callees", [])) & _SECURITY_APIS]

            return {
                "ok": True,
                "stats": {
                    "functions_added": len(new_funcs), "functions_removed": len(removed_funcs),
                    "functions_modified": len(modified_names), "total_size_delta": total_size_delta,
                    "total_current": len(current), "total_snapshot": len(snap_funcs),
                },
                "security_impact": {
                    "modified_security_functions": security_modified[:limit],
                    "new_dangerous_apis": sorted(new_dangerous_apis),
                    "new_functions_with_security_apis": security_new_funcs[:limit],
                },
                "categories": {k: v[:limit] for k, v in cats.items()},
                "new_functions_sample": sorted(new_funcs)[:20],
                "removed_functions_sample": sorted(removed_funcs)[:20],
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
