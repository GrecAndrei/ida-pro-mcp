
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


def _remove_overlapping_functions(start_ea: int, end_ea: int) -> list[dict]:
    """Delete functions overlapping [start_ea, end_ea). Returns removed entries."""
    removed = []
    for overlap in _iter_overlapping_functions(start_ea, end_ea):
        if overlap.start_ea == start_ea and overlap.end_ea == end_ea:
            continue
        ov_name = ida_funcs.get_func_name(overlap.start_ea)
        if ida_funcs.del_func(overlap.start_ea):
            removed.append({
                "addr": hex(overlap.start_ea),
                "end": hex(overlap.end_ea),
                "name": ov_name,
            })
        else:
            raise RuntimeError(f"Failed to delete overlapping function at {hex(overlap.start_ea)}")
    return removed


def _ensure_code_at(ea: int) -> bool:
    """Try to convert bytes at ea to code. Returns True if code exists after attempt."""
    if ida_bytes.is_code(ida_bytes.get_flags(ea)):
        return True
    try:
        proc = (_inf_procname() or "").lower()
    except Exception:
        proc = ""
    is_arm = "arm" in proc or "aarch" in proc or "thumb" in proc
    if is_arm:
        _set_thumb_mode(ea)
    created = _try_create_insn(ea)
    if created and ida_bytes.is_code(ida_bytes.get_flags(ea)):
        return True
    for carve_size in (16, 64, 256):
        with contextlib.suppress(Exception):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, carve_size)
        with contextlib.suppress(Exception):
            import ida_auto
            if hasattr(ida_auto, "auto_make_code"):
                ida_auto.auto_make_code(ea)
        if is_arm:
            _set_thumb_mode(ea)
        created = _try_create_insn(ea)
        if created and ida_bytes.is_code(ida_bytes.get_flags(ea)):
            return True
    return False


def _set_thumb_mode(ea: int) -> None:
    """Set T=1 segment register for Thumb mode on ARM."""
    try:
        sr_auto = getattr(idc, "SR_auto", 2)
        idc.split_sreg_range(ea, "T", 1, sr_auto)
    except Exception:
        try:
            import ida_segregs
            ida_segregs.split_sreg_range(ea, "T", 1, 2)
        except Exception:
            pass


def _try_create_insn(ea: int) -> int:
    """Try ida_ua.create_insn (IDA 9.x) then fall back to idc.create_insn."""
    try:
        import ida_ua
        result = ida_ua.create_insn(ea)
        if result:
            return result
    except Exception:
        pass
    return idc.create_insn(ea)


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
    if idx.size == 0:
        return make_error(
            MCPError.NOT_FOUND,
            "No functions indexed yet. Index your functions to enable semantic search.",
            hint="Index your functions first:\n  index_fast:  seconds, disassembly-based (good for quick triage)\n  index_batch: minutes, decompile-based (best quality embeddings)",
        )
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
                if not force:
                    return make_error(
                        MCPError.ADDRESS_INVALID,
                        f"Address {hex(ea)} is inside function {ida_funcs.get_func_name(existing.start_ea)} ({hex(existing.start_ea)}-{hex(existing.end_ea)})",
                        "Delete the existing function first with funcs(action='delete', addr='" + hex(ea) + "') which will delete the containing function, then create the new one",
                    )
                if not ida_funcs.del_func(existing.start_ea):
                    return make_error(
                        MCPError.IDA_ERROR,
                        f"Failed to delete containing function at {hex(existing.start_ea)}",
                    )

            removed_overlaps = []
            if force:
                scan_end = end_ea if end_ea is not None else ea + 0x1000
                try:
                    removed_overlaps = _remove_overlapping_functions(ea, scan_end)
                except RuntimeError as e:
                    return make_error(MCPError.IDA_ERROR, str(e))
                if end_ea is not None:
                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, end_ea - ea)

            if not _ensure_code_at(ea):
                return make_error(
                    MCPError.ADDRESS_INVALID,
                    f"Address {hex(ea)} cannot be converted to code",
                    "Tried carve-and-convert retries (16/64/256 bytes). Bytes may be invalid for current processor; verify architecture or use firmware_view(action='auto_retype'). For ARM Cortex-M firmware, ensure Thumb mode (T=1) is set via seg_reg action.",
                )

            fn = ida_funcs.add_func(ea, end_ea or idaapi.BADADDR)
            if not fn and end_ea and hasattr(idaapi, "auto_mark_range"):
                with contextlib.suppress(Exception):
                    idaapi.auto_mark_range(ea, end_ea, idaapi.AU_FINAL)
                fn = ida_funcs.add_func(ea, end_ea)
            if not fn:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Failed to create function at {hex(ea)}",
                    "Ensure code exists at the address and there are no overlapping functions. Try specifying an explicit end address.",
                )
            if name and not idc.set_name(ea, name, ida_name.SN_FORCE):
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Function created at {hex(ea)} but failed to set name '{name}'",
                )
            if flags:
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

        elif action == "delete":
            ea, err = _resolve_func_addr(addr)
            if err: return err
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
            func.flags |= flags
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
            include_xrefs = bool(kwargs.get("include_xrefs", False))
            include_prototype = bool(kwargs.get("include_prototype", False))
            include_stack = bool(kwargs.get("include_stack", False))
            info["caller_count"] = 0
            info["callee_count"] = 0
            if include_xrefs:
                callers = _collect_callers(fn.start_ea)
                callees = _collect_callees(fn.start_ea)
                info["caller_count"] = len(callers)
                info["callee_count"] = len(callees)
                info["callers_sample"] = [hex_ea(x) for x in callers[:16]]
                info["callees_sample"] = [hex_ea(x) for x in callees[:16]]
            if include_prototype:
                info["prototype"] = get_prototype(fn)
                # Add structured parameter list using ida_typeinf
                try:
                    tinfo = ida_typeinf.tinfo_t()
                    if tinfo.get_numbered_type(idaapi.get_idb(), fn.start_ea):
                        func_data = ida_typeinf.func_type_data_t()
                        if tinfo.get_func_details(func_data):
                            params = []
                            for i in range(func_data.size()):
                                pi = func_data[i]
                                param = {
                                    "idx": i,
                                    "name": str(getattr(pi, "name", "") or f"arg{i}"),
                                    "type": str(getattr(pi, "type", "") or ""),
                                }
                                # Location: register or stack offset
                                loc = getattr(pi, "loc", None)
                                if loc:
                                    reg = getattr(loc, "reg", None)
                                    if reg is not None:
                                        param["location"] = f"reg:{reg}"
                                    else:
                                        offset = getattr(loc, "offset", None)
                                        if offset is not None:
                                            param["location"] = f"stack:{hex(offset)}"
                                params.append(param)
                            info["parameters"] = params
                            info["return_type"] = str(func_data.rettype) if hasattr(func_data, "rettype") else ""
                            info["calling_convention"] = str(func_data.cc) if hasattr(func_data, "cc") else ""
                except Exception:
                    pass
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
            insn_count = 0
            bb_count = 0
            edges = 0
            call_count = 0
            ret_count = 0
            jump_count = 0
            cond_jump_count = 0
            try:
                fc = idaapi.FlowChart(fn)
                for b in fc:
                    bb_count += 1
                    for _s in b.succs():
                        edges += 1
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
            cyclomatic = max(1, edges - bb_count + 2) if edges else max(1, bb_count + 1)
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
            import time as _time
            _FIND_SIMILAR_MAX_FUNCS = 50000
            _FIND_SIMILAR_MAX_SECS = 60
            results = []
            raw_scores = []
            staged = []
            scanned = 0
            timed_out = False
            max_candidates = (kwargs.get("limit") or 20) * 10
            t0 = _time.monotonic()
            for func_ea in idautils.Functions():
                if func_ea == target_fn.start_ea:
                    continue
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue
                scanned += 1
                if scanned >= _FIND_SIMILAR_MAX_FUNCS:
                    break
                if scanned % 500 == 0 and _time.monotonic() - t0 > _FIND_SIMILAR_MAX_SECS:
                    timed_out = True
                    break
                size = fn.end_ea - fn.start_ea
                if abs(size - target_size) > max(size, target_size) * 0.5:
                    continue
                func_bytes = ida_bytes.get_bytes(fn.start_ea, size) or b""
                if not func_bytes:
                    continue
                insn_count = 0
                for _ in idautils.FuncItems(func_ea):
                    insn_count += 1
                    if insn_count >= 500000:
                        break
                insn_sim = 1.0 - abs(insn_count - target_insn_count) / max(insn_count, target_insn_count, 1)
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
                    "size": size,
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
            resp = {"ok": True, "target": hex(target_fn.start_ea), "similar_functions": results[:limit], "count": len(results), "scanned": scanned}
            if timed_out:
                resp["note"] = f"Scan timed out after {_FIND_SIMILAR_MAX_SECS}s — results may be incomplete"
            return resp

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
    action: Annotated[Literal[
        "create", "delete", "set_flags", "info", "metrics", "find_similar",
        "suggest_names", "list",
    ],
                      "Action: create|delete|set_flags|info|metrics|find_similar|suggest_names|list"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name (for create)"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    force: Annotated[bool, "Force creation by deleting overlapping functions/data"] = False,
    query: Annotated[Optional[str], "Substring/regex filter for list"] = None,
    offset: Annotated[int, "Pagination offset for list"] = 0,
    count: Annotated[int, "Pagination count for list (0=all)"] = 50,
    min_size: Annotated[int, "Skip functions smaller than this for list"] = 0,
    min_xrefs: Annotated[Optional[int], "Keep only functions with >= this many xrefs_to (cuts stub-function noise on large binaries)"] = None,
    named_only: Annotated[bool, "Skip sub_* for list"] = False,
    **kwargs
) -> dict:
    """
    Create, modify, and analyze function definitions.

    Actions:
    - list: Read-only function enumeration. Returns {functions, total, count, offset}.
      Filters: query (substring/regex), min_size, min_xrefs (>= N xrefs_to cuts stub noise),
      named_only. Paginated with offset/count.
      Alias of data(action='functions', ...) — same payload, no _risk_ack needed.
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
    if action == "list":
        from ida_pro_mcp.ida_mcp.tools.data import data  # noqa: PLC0415

        return data(
            action="functions",
            query=query or "",
            offset=offset,
            count=count,
            include_prototype=False,
            include_xrefs=True,
            min_size=min_size,
            min_xrefs=min_xrefs,
            named_only=named_only,
        )

    call_kwargs = {
        "action": action,
        "addr": addr,
        "end": end,
        "name": name,
        "flags": flags,
        "force": force,
        **kwargs,
    }
    return _funcs_impl(**call_kwargs)


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================
