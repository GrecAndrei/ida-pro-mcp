
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]
import contextlib
import hashlib

# ============================================================================
# 10. FUNCS - Function management
# ============================================================================


def _clip_text(value: Any, max_len: int = 240) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _iter_overlapping_functions(start_ea: int, end_ea: int):
    """Yield functions whose ranges overlap [start_ea, end_ea)."""
    for fn_start in idautils.Functions():
        fn = ida_funcs.get_func(fn_start)
        if not fn:
            continue
        if fn.end_ea <= start_ea or fn.start_ea >= end_ea:
            continue
        yield fn


def _collect_callers(func_start_ea: int) -> list[int]:
    callers = set()
    for xref_ea in idautils.CodeRefsTo(func_start_ea, 0):
        caller = ida_funcs.get_func(xref_ea)
        if caller and caller.start_ea != func_start_ea:
            callers.add(caller.start_ea)
    return sorted(callers)


def _collect_callees(func_start_ea: int, max_items=50000) -> list[int]:
    fn = ida_funcs.get_func(func_start_ea)
    if not fn:
        return []
    callees = set()
    for item_ea in idautils.FuncItems(fn.start_ea):
        for ref in idautils.CodeRefsFrom(item_ea, 0):
            target = ida_funcs.get_func(ref)
            if target and target.start_ea != fn.start_ea:
                callees.add(target.start_ea)
        if len(callees) >= max_items:
            break
    return sorted(callees)


def _persist_symbol_knowledge(func_ea: int, name: str) -> None:
    if not name or name.startswith("sub_"):
        return
    try:
        from ida_pro_mcp.services import SymbolDB
    except Exception:
        try:
            from host.symbol_db import SymbolDB  # type: ignore
        except Exception:
            return
    callers = _collect_callers(func_ea)[:32]
    callees = _collect_callees(func_ea, max_items=128)[:64]
    strs = []
    fn = ida_funcs.get_func(func_ea)
    if fn:
        for item_ea in idautils.FuncItems(fn.start_ea):
            for ref in idautils.DataRefsFrom(item_ea):
                s = idc.get_strlit_contents(ref, -1, idc.STRTYPE_C)
                if not s:
                    continue
                txt = s.decode(errors="ignore").strip()
                if txt and txt not in strs:
                    strs.append(txt[:120])
                if len(strs) >= 24:
                    break
            if len(strs) >= 24:
                break
    graph = "|".join([f"c:{hex(x)}" for x in callers] + [f"d:{hex(x)}" for x in callees])
    fingerprint = hashlib.sha1((graph + "||" + "|".join(sorted(strs)[:32])).encode("utf-8")).hexdigest()
    callgraph_hash = hashlib.sha1(graph.encode("utf-8")).hexdigest()
    try:
        SymbolDB().upsert_symbol(
            {
                "symbol_name": name,
                "source_binary": idc.get_idb_path() or "",
                "source_addr": hex(func_ea),
                "fingerprint": fingerprint,
                "callgraph_hash": callgraph_hash,
                "strings": strs,
                "confidence": 1.0,
            }
        )
    except Exception:
        return


def _try_map_raw_runtime_addr(ea: int) -> tuple[Optional[int], Optional[str]]:
    """Map runtime-like VA to raw IDB offset when safe."""
    try:
        if idaapi.is_mapped(ea):
            return ea, None
    except Exception:
        return None, None

    segs = []
    seg = idaapi.get_first_seg()
    while seg:
        segs.append(seg)
        seg = idaapi.get_next_seg(seg.start_ea)
    if len(segs) != 1:
        return None, None

    only = segs[0]
    start = int(only.start_ea)
    end = int(only.end_ea)
    size = end - start
    if size <= 0 or start != 0:
        return None, None

    # Common image-base alignments seen in runtime VAs.
    for align in (0x100000, 0x10000, 0x1000):
        base = ea & ~(align - 1)
        off = ea - base
        if 0 <= off < size:
            mapped = start + off
            try:
                if idaapi.is_mapped(mapped):
                    return mapped, f"runtime_va={hex(ea)} base={hex(base)} offset={hex(off)}"
            except Exception:
                pass
    return None, None


def _resolve_func_addr(addr: Any) -> tuple[Optional[int], Optional[dict]]:
    """Resolve function address from hex/int/name and normalize to function start when available."""
    if addr is None:
        return None, make_error(MCPError.INVALID_ARGS, "addr required")
    if isinstance(addr, int):
        ea = addr
    else:
        txt = str(addr).strip()
        if not txt:
            return None, make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(txt)
        if err:
            sym = idc.get_name_ea_simple(txt)
            if sym == idaapi.BADADDR:
                return None, err
            ea = sym
    fn = ida_funcs.get_func(ea)
    if fn:
        return fn.start_ea, None
    return ea, None


def _embedding_rename_suggestions(
    addr: Optional[str] = None,
    limit: int = 100,
    threshold: Optional[float] = None,
    nearest_top_k: int = 8,
) -> dict:
    """Shared embedding-backed rename suggestion engine used by funcs/agent."""
    try:
        from ida_pro_mcp.services import BgeCodeEmbedder, FunctionEmbeddingIndex, _extract_signature
    except ImportError:
        from host.intelligence.core import BgeCodeEmbedder, FunctionEmbeddingIndex, _extract_signature  # type: ignore

    embedder = BgeCodeEmbedder()
    idb_path = ""
    with contextlib.suppress(Exception):
        idb_path = idc.get_idb_path() or ""
    if not idb_path:
        return make_error(MCPError.INVALID_ARGS, "No IDB path available")

    idx = FunctionEmbeddingIndex(idb_path + ".embeddings.db", embedder)
    target_eas: list[int] = []
    if addr:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return err
        target_eas = [ea]
    else:
        for func_ea in idautils.Functions():
            fname = idc.get_func_name(func_ea) or ""
            if fname.startswith(("sub_", "nullsub_")):
                target_eas.append(func_ea)
            if len(target_eas) >= max(1, int(limit)):
                break

    suggestions = []
    for func_ea in target_eas:
        fname = idc.get_func_name(func_ea) or hex(func_ea)
        pseudo = None
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                pseudo = _extract_signature(str(cfunc), max_idents=40)
        except Exception:
            pass
        if not pseudo:
            continue

        similar = idx.similar(pseudo, top_k=max(1, int(nearest_top_k)), exclude_ea=hex(func_ea), threshold=0.0)
        named = [s for s in similar if not s["name"].startswith("sub_") and not s["name"].startswith("0x")]
        if not named:
            continue

        if threshold is not None:
            gate = float(threshold or 0.0)
        else:
            ns = sorted(float(s.get("similarity") or 0.0) for s in named)
            q50 = ns[len(ns) // 2]
            q75 = ns[min(len(ns) - 1, int(round((len(ns) - 1) * 0.75)))]
            gate = q50 + max(0.0, q75 - q50)
        named = [s for s in named if float(s.get("similarity") or 0.0) >= gate]
        if not named:
            continue

        best = named[0]
        suggestions.append(
            {
                "addr": hex(func_ea),
                "current_name": fname,
                "suggested_name": best["name"],
                "confidence": float(best["similarity"]),
                "source_addr": str(best["ea"]),
                "alternatives": [{"name": s["name"], "confidence": float(s["similarity"])} for s in named[1:3]],
            }
        )

    suggestions.sort(key=lambda x: -float(x.get("confidence") or 0.0))
    return {
        "ok": True,
        "suggestions": suggestions,
        "count": len(suggestions),
        "backend": embedder.backend,
        "note": "Apply with modify(action='rename', addr=..., name=...). High confidence (>0.8) suggestions are reliable.",
    }


def _funcs_impl(
    action: Annotated[Literal["create", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names"],
                      "Action: create|delete|set_flags|info|metrics|find_similar|suggest_names"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name (for create)"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    force: Annotated[bool, "Force creation by deleting overlapping functions/data"] = False,
    **kwargs
) -> dict:
    """
    Create and modify function definitions.

    Actions:
    - create: Define a new function at `addr`. Automatically converts bytes to code
      if needed. If address is inside an existing function, offers to split or
      suggests using the existing function's start. Optionally set `end`, `name`,
      `flags`, or `force` to delete overlapping functions/data.
    - delete: Remove function definition at `addr`. If addr is inside a function
      (but not at its start), the containing function is deleted.
    - set_flags: Update function attribute flags.
    - info: Detailed info about a single function.
    """
    try:
        if addr is None:
            addr = kwargs.get("ea") or kwargs.get("start") or kwargs.get("function") or kwargs.get("target")
        if end is None:
            end = kwargs.get("end_ea") or kwargs.get("stop")

        if action == "create":
            ea, err = validate_addr(addr)
            remap_note = None
            if err:
                raw_ea, parse_err = parse_address_safe(addr)
                if parse_err:
                    return err
                mapped, reason = _try_map_raw_runtime_addr(int(raw_ea))
                if mapped is None:
                    return err
                ea = mapped
                remap_note = reason
            end_ea = None
            if end:
                end_ea, err = validate_addr(end)
                if err: return err
            if end_ea is not None and end_ea <= ea:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"end address {hex(end_ea)} must be greater than start address {hex(ea)}",
                )
            if name is not None and not str(name).strip():
                return make_error(MCPError.INVALID_ARGS, "name cannot be empty")

            existing = ida_funcs.get_func(ea)
            if existing and existing.start_ea == ea:
                if name and not idc.set_name(ea, name, ida_name.SN_FORCE):
                    return make_error(MCPError.IDA_ERROR, f"Function exists at {hex(ea)} but failed to rename to '{name}'")
                return {
                    "ok": True,
                    "addr": hex(ea),
                    "end": hex(existing.end_ea),
                    "name": ida_funcs.get_func_name(ea),
                    "note": "Function already exists at this address",
                }
            if existing:
                # Address is inside an existing function but not at its start
                if force:
                    if not ida_funcs.del_func(existing.start_ea):
                        return make_error(
                            MCPError.IDA_ERROR,
                            f"Failed to delete containing function at {hex(existing.start_ea)}",
                        )
                else:
                    return make_error(
                        MCPError.ADDRESS_INVALID,
                        f"Address {hex(ea)} is inside function {ida_funcs.get_func_name(existing.start_ea)} ({hex(existing.start_ea)}-{hex(existing.end_ea)})",
                        "Delete the existing function first with funcs(action='delete', addr='" + hex(ea) + "') which will delete the containing function, then create the new one",
                    )

            removed_overlaps = []
            if end_ea is not None and force:
                # Delete overlapping functions before undefining data/code range.
                for overlap in _iter_overlapping_functions(ea, end_ea):
                    if overlap.start_ea == ea and overlap.end_ea == end_ea:
                        continue
                    ov_name = ida_funcs.get_func_name(overlap.start_ea)
                    if ida_funcs.del_func(overlap.start_ea):
                        removed_overlaps.append(
                            {
                                "addr": hex(overlap.start_ea),
                                "end": hex(overlap.end_ea),
                                "name": ov_name,
                            }
                        )
                    else:
                        return make_error(
                            MCPError.IDA_ERROR,
                            f"Failed to delete overlapping function at {hex(overlap.start_ea)}",
                        )
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, end_ea - ea)

            # Ensure code exists at the start address - auto-convert if possible
            byte_flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(byte_flags):
                # Cortex-M/raw blobs commonly need explicit Thumb state before
                # IDA can decode instruction bytes at vector-handler addresses.
                try:
                    proc = (_inf_procname() or "").lower()
                except Exception:
                    proc = ""
                is_arm = "arm" in proc and (idaapi.get_inf_structure().is_32bit() if hasattr(idaapi, "get_inf_structure") else True)
                if is_arm:
                    # Set T=1 segment register for Thumb mode (all Cortex-M is Thumb-2)
                    try:
                        sr_auto = getattr(idc, "SR_auto", 2)
                        idc.split_sreg_range(ea, "T", 1, sr_auto)
                    except Exception:
                        try:
                            import ida_segregs
                            ida_segregs.split_sreg_range(ea, "T", 1, 2)
                        except Exception:
                            pass

                # Try ida_ua.create_insn (IDA 9.x) first, fall back to idc.create_insn
                created = 0
                try:
                    import ida_ua
                    created = ida_ua.create_insn(ea)
                except Exception:
                    created = idc.create_insn(ea)
                if created == 0:
                    created = idc.create_insn(ea)

                if created == 0 or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    # Raw/firmware regions often need wider undefine + auto-analysis nudges.
                    converted = False
                    for carve_size in (16, 64, 256):
                        with contextlib.suppress(Exception):
                            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, carve_size)
                        try:
                            import ida_auto
                            if hasattr(ida_auto, "auto_make_code"):
                                ida_auto.auto_make_code(ea)
                        except Exception:
                            pass
                        if is_arm:
                            try:
                                sr_auto = getattr(idc, "SR_auto", 2)
                                idc.split_sreg_range(ea, "T", 1, sr_auto)
                            except Exception:
                                try:
                                    import ida_segregs
                                    ida_segregs.split_sreg_range(ea, "T", 1, 2)
                                except Exception:
                                    pass
                        try:
                            import ida_ua
                            created = ida_ua.create_insn(ea)
                        except Exception:
                            created = idc.create_insn(ea)
                        if created == 0:
                            created = idc.create_insn(ea)
                        if created != 0 and ida_bytes.is_code(ida_bytes.get_flags(ea)):
                            converted = True
                            break
                    if not converted:
                        return make_error(
                            MCPError.ADDRESS_INVALID,
                            f"Address {hex(ea)} cannot be converted to code",
                            "Tried carve-and-convert retries (16/64/256 bytes). Bytes may be invalid for current processor; verify architecture or use firmware_view(action='auto_retype'). For ARM Cortex-M firmware, ensure Thumb mode (T=1) is set via seg_reg action.",
                        )

            if ida_funcs.add_func(ea, end_ea or idaapi.BADADDR):
                fn = ida_funcs.get_func(ea)
                if name and not idc.set_name(ea, name, ida_name.SN_FORCE):
                    return make_error(
                        MCPError.IDA_ERROR,
                        f"Function created at {hex(ea)} but failed to set name '{name}'",
                    )
                if fn and flags:
                    fn.flags |= flags
                    ida_funcs.update_func(fn)
                # Do NOT call auto_wait() — it blocks IDA's main thread inside
                # the socket server loop and can crash IDA. Let the idle loop
                # handle follow-up analysis.
                fn = ida_funcs.get_func(ea)
                result = {
                    "ok": True,
                    "addr": hex(ea),
                    "end": hex(fn.end_ea) if fn else (hex(end_ea) if end_ea else None),
                    "name": ida_funcs.get_func_name(ea) if fn else name,
                }
                if remap_note:
                    result["addr_remap"] = remap_note
                if removed_overlaps:
                    result["removed_overlaps"] = removed_overlaps
                return result
            if end_ea and hasattr(idaapi, "auto_mark_range"):
                with contextlib.suppress(Exception):
                    idaapi.auto_mark_range(ea, end_ea, idaapi.AU_FINAL)
                if ida_funcs.add_func(ea, end_ea):
                    fn = ida_funcs.get_func(ea)
                    if name and not idc.set_name(ea, name, ida_name.SN_FORCE):
                        return make_error(
                            MCPError.IDA_ERROR,
                            f"Function created at {hex(ea)} but failed to set name '{name}'",
                        )
                    if fn and flags:
                        fn.flags |= flags
                        ida_funcs.update_func(fn)
                    result = {
                        "ok": True,
                        "addr": hex(ea),
                        "end": hex(fn.end_ea) if fn else hex(end_ea),
                        "name": ida_funcs.get_func_name(ea) if fn else name,
                        "note": "Function created after auto-analysis retry",
                    }
                    if remap_note:
                        result["addr_remap"] = remap_note
                    if removed_overlaps:
                        result["removed_overlaps"] = removed_overlaps
                    return result
            return make_error(MCPError.IDA_ERROR, f"Failed to create function at {hex(ea)}", "Ensure code exists at the address and there are no overlapping functions. Try specifying an explicit end address.")

        elif action == "delete":
            ea, err = _resolve_func_addr(addr)
            if err: return err
            # If the address is inside a function but not at its start, delete the containing function
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function found at or containing {hex(ea)}")
            target_ea = func.start_ea
            func_name = ida_funcs.get_func_name(target_ea)
            if ida_funcs.del_func(target_ea):
                result = {"ok": True, "addr": hex(target_ea), "name": func_name}
                if target_ea != ea:
                    result["note"] = f"Deleted containing function (start was at {hex(target_ea)}, you specified {hex(ea)})"
                return result
            return make_error(MCPError.IDA_ERROR, f"Failed to delete function at {hex(target_ea)}")

        elif action == "set_flags":
            ea, err = _resolve_func_addr(addr)
            if err: return err
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            old_flags = func.flags
            func.flags = flags
            if ida_funcs.update_func(func):
                return {
                    "ok": True,
                    "addr": hex(func.start_ea),
                    "old_flags": hex(old_flags),
                    "flags": hex(flags),
                }
            return make_error(MCPError.IDA_ERROR, "Failed to update flags")

        elif action == "info":
            ea, err = _resolve_func_addr(addr)
            if err: return err
            fn = ida_funcs.get_func(ea)
            if not fn:
                # Try to find containing function
                func = ida_funcs.get_func(ea)
                if func:
                    fn = func
                else:
                    return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at or containing {hex(ea)}")
            fname = ida_funcs.get_func_name(fn.start_ea)
            info = {
                "addr": hex(fn.start_ea),
                "end": hex(fn.end_ea),
                "size": hex(fn.end_ea - fn.start_ea),
                "name": fname,
                "flags": hex(fn.flags),
                "chunk_count": len(list(idautils.Chunks(fn.start_ea))),
            }
            cmt = idc.get_func_cmt(fn.start_ea, 0)
            rcmt = idc.get_func_cmt(fn.start_ea, 1)
            if cmt:
                info["comment"] = cmt
            if rcmt:
                info["repeatable_comment"] = rcmt
            callers = _collect_callers(fn.start_ea)
            callees = _collect_callees(fn.start_ea)
            info["caller_count"] = len(callers)
            info["callee_count"] = len(callees)
            # These optional flags are part of the tool schema but the function
            # signature uses **kwargs, so they must be extracted explicitly.
            include_xrefs = bool(kwargs.get("include_xrefs", False))
            include_prototype = bool(kwargs.get("include_prototype", False))
            include_stack = bool(kwargs.get("include_stack", False))
            if include_xrefs:
                info["callers_sample"] = [hex_ea(x) for x in callers[:16]]
                info["callees_sample"] = [hex_ea(x) for x in callees[:16]]
            if include_prototype:
                info["prototype"] = get_prototype(fn)
            if include_stack:
                info["stack_frame"] = get_stack_frame_variables_internal(fn.start_ea, raise_error=False)
            return {"ok": True, "function": info}

        elif action == "metrics":
            ea, err = _resolve_func_addr(addr)
            if err: return err
            fn = ida_funcs.get_func(ea)
            if not fn:
                func = ida_funcs.get_func(ea)
                if func:
                    fn = func
                else:
                    return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at or containing {hex(ea)}")
            # Compute metrics
            insn_count = 0
            bb_count = 0
            call_count = 0
            ret_count = 0
            jump_count = 0
            cond_jump_count = 0
            try:
                fc = idaapi.FlowChart(fn)
                bb_count = sum(1 for _ in fc)
                for b in fc:
                    head = b.start_ea
                    insn_iter = 0
                    while head < b.end_ea and head != idaapi.BADADDR:
                        insn_count += 1
                        mnem = (idc.print_insn_mnem(head) or "").lower()
                        if mnem in ("call", "bl", "blx"):
                            call_count += 1
                        elif mnem in ("ret", "retn", "bx", "jr", "blr"):
                            ret_count += 1
                        elif mnem.startswith(("j", "b")):
                            jump_count += 1
                            if mnem in ("jz", "je", "jnz", "jne", "ja", "jb", "jg", "jl", "jbe", "jge", "jle", "jc", "jnc"):
                                cond_jump_count += 1
                        head = idc.next_head(head, fn.end_ea)
                        insn_iter += 1
                        if insn_iter >= 500000:
                            break
            except Exception:
                pass
            # Cyclomatic complexity
            cyclomatic = max(1, bb_count + 1)
            try:
                edges = 0
                fc = idaapi.FlowChart(fn)
                for b in fc:
                    for _s in b.succs():
                        edges += 1
                cyclomatic = edges - bb_count + 2
                cyclomatic = max(cyclomatic, 1)
            except Exception:
                pass
            size = fn.end_ea - fn.start_ea
            return {
                "ok": True,
                "function": ida_funcs.get_func_name(fn.start_ea),
                "addr": hex(fn.start_ea),
                "metrics": {
                    "size_bytes": size,
                    "instruction_count": insn_count,
                    "basic_block_count": bb_count,
                    "cyclomatic_complexity": cyclomatic,
                    "call_count": call_count,
                    "return_count": ret_count,
                    "jump_count": jump_count,
                    "conditional_jump_count": cond_jump_count,
                    "calls_per_instruction": round(call_count / max(1, insn_count), 4),
                    "density": round(insn_count / max(1, size), 4),
                },
            }

        elif action == "find_similar":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = _resolve_func_addr(addr)
            if err: return err
            target_fn = ida_funcs.get_func(ea)
            if not target_fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            target_bytes = ida_bytes.get_bytes(target_fn.start_ea, target_fn.end_ea - target_fn.start_ea) or b""
            target_size = len(target_bytes)
            target_insn_count = sum(1 for _ in idautils.FuncItems(target_fn.start_ea))
            results = []
            raw_scores = []
            staged = []
            max_candidates = (kwargs.get("limit") or 20) * 10
            for func_ea in idautils.Functions():
                if func_ea == target_fn.start_ea:
                    continue
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue
                size = fn.end_ea - fn.start_ea
                if abs(size - target_size) > max(size, target_size) * 0.5:
                    continue
                func_bytes = ida_bytes.get_bytes(fn.start_ea, size) or b""
                if not func_bytes:
                    continue
                # Simple similarity: instruction count ratio + byte similarity
                insn_count = 0
                for _ in idautils.FuncItems(func_ea):
                    insn_count += 1
                    if insn_count >= 500000:
                        break
                insn_sim = 1.0 - abs(insn_count - target_insn_count) / max(insn_count, target_insn_count, 1)
                # Byte-level similarity (ignoring addresses in operands)
                min_len = min(len(target_bytes), len(func_bytes))
                if min_len == 0:
                    continue
                matches = sum(1 for i in range(min_len) if target_bytes[i] == func_bytes[i])
                byte_sim = matches / min_len
                score = round((insn_sim * 0.4 + byte_sim * 0.6) * 100, 2)
                raw_scores.append(score)
                staged.append({
                    "addr": hex(func_ea),
                    "name": ida_funcs.get_func_name(func_ea),
                    "score": score,
                    "size": hex(size),
                    "instructions": insn_count,
                })
                if len(staged) >= max_candidates:
                    break
            if staged:
                if kwargs.get("min_score") is not None:
                    gate = float(kwargs.get("min_score") or 0.0)
                else:
                    ss = sorted(raw_scores)
                    q50 = ss[len(ss) // 2]
                    q75 = ss[min(len(ss) - 1, int(round((len(ss) - 1) * 0.75)))]
                    gate = q50 + max(0.0, q75 - q50)
                results = [r for r in staged if float(r.get("score") or 0.0) >= gate]
            results.sort(key=lambda x: -x["score"])
            limit = kwargs.get("limit") or 20
            return {"ok": True, "target": hex(target_fn.start_ea), "similar_functions": results[:limit], "count": len(results)}

        elif action == "suggest_names":
            return _embedding_rename_suggestions(
                addr=addr,
                limit=int(kwargs.get("limit") or 100),
                threshold=(float(kwargs["threshold"]) if kwargs.get("threshold") is not None else None),
                nearest_top_k=int(kwargs.get("top_k") or 8),
            )

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


@tool
def funcs(
    action: Annotated[Literal["create", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names"],
                      "Action: create|delete|set_flags|info|metrics|find_similar|suggest_names"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name (for create)"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    force: Annotated[bool, "Force creation by deleting overlapping functions/data"] = False,
    **kwargs
) -> dict:
    """
    Create, modify, and analyze function definitions.

    Actions:
    - create: Define a new function at `addr`. Automatically converts bytes to code
      if needed. If address is inside an existing function, offers to split or
      suggests using the existing function's start. Optionally set `end`, `name`,
      `flags`, or `force` to delete overlapping functions/data.
    - delete: Remove function definition at `addr`. If addr is inside a function
      (but not at its start), the containing function is deleted.
    - set_flags: Update function attribute flags.
    - info: Detailed info about a single function.
    - metrics: Compute complexity metrics (cyclomatic complexity, instruction count,
      basic blocks, call/return/jump counts, density).
    - find_similar: Find functions with similar bytecode patterns to the function at `addr`.
      Returns ranked list with similarity scores.
    """
    call_kwargs = {
        "action": action,
        "addr": addr,
        "end": end,
        "name": name,
        "flags": flags,
        "force": force,
        **kwargs,
    }
    # The previous implementation routed read-only actions through
    # `_funcs_read_dispatch` (decorated with @idaread) and everything
    # else through `_funcs_write_dispatch` (@idawrite). Both
    # functions were no-ops that simply called `_funcs_impl(**kwargs)`,
    # so the read/write split added two layers of indirection with
    # no observable effect. Inline the call.
    return _funcs_impl(**call_kwargs)


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================
