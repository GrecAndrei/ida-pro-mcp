
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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


def _funcs_impl(
    action: Annotated[Literal["create", "delete", "set_flags", "set_name", "rename", "add_comment", "list", "info"],
                      "Action: create|delete|set_flags|set_name|rename|add_comment|list|info"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    force: Annotated[bool, "Force creation by deleting overlapping functions/data"] = False,
    comment: Annotated[Optional[str], "Function comment"] = None,
    repeatable: Annotated[bool, "Is comment repeatable?"] = False,
    query: Annotated[Optional[str], "Filter for function names - supports regex, glob, or substring (list action)"] = None,
    offset: Annotated[int, "Pagination offset (list action)"] = 0,
    count: Annotated[int, "Max results (0=all) (list action)"] = 100,
    named_only: Annotated[bool, "Only return named functions (list action)"] = False,
    include_prototype: Annotated[bool, "Include function prototype (info/list)"] = False,
    include_stack: Annotated[bool, "Include stack frame variables (info)"] = False,
    include_items: Annotated[bool, "Include structured `items` list in list output (default: false for context efficiency)"] = False,
    include_xrefs: Annotated[bool, "Include caller/callee samples in info output"] = False,
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
    - set_name/rename: Rename function at `addr`.
    - add_comment: Set function-level comment.
    - list: Paginated listing with optional name filtering.
      Query supports regex (e.g. ^init, \\w+alloc), glob (*alloc*), or plain substring.
      Returns compact text: "addr  size  name [prototype]" per line.
    - info: Detailed info about a single function.
    """
    try:
        # "rename" is an alias for "set_name"
        if action == "rename":
            action = "set_name"

        if action == "create":
            ea, err = validate_addr(addr)
            if err: return err
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
                if name:
                    if not idc.set_name(ea, name, ida_name.SN_FORCE):
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
                # Try to make code at this address
                created = idc.create_insn(ea)
                if created == 0 or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    # Try harder: undefine first, then make code
                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 16)
                    created = idc.create_insn(ea)
                    if created == 0 or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                        return make_error(
                            MCPError.ADDRESS_INVALID,
                            f"Address {hex(ea)} cannot be converted to code",
                            "The bytes at this address may not form valid instructions. Try data_ops(action='make_code', addr=...) first.",
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
                try:
                    import ida_auto
                    ida_auto.auto_wait()
                except (ImportError, AttributeError):
                    pass
                fn = ida_funcs.get_func(ea)
                result = {
                    "ok": True,
                    "addr": hex(ea),
                    "end": hex(fn.end_ea) if fn else (hex(end_ea) if end_ea else None),
                    "name": ida_funcs.get_func_name(ea) if fn else name,
                }
                if removed_overlaps:
                    result["removed_overlaps"] = removed_overlaps
                return result
            if end_ea and hasattr(idaapi, "auto_mark_range"):
                try:
                    idaapi.auto_mark_range(ea, end_ea, idaapi.AU_FINAL)
                    idaapi.auto_wait()
                except Exception:
                    pass
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
                    if removed_overlaps:
                        result["removed_overlaps"] = removed_overlaps
                    return result
            return make_error(MCPError.IDA_ERROR, f"Failed to create function at {hex(ea)}", "Ensure code exists at the address and there are no overlapping functions. Try specifying an explicit end address.")

        elif action == "delete":
            ea, err = validate_addr(addr)
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
            ea, err = validate_addr(addr)
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

        elif action == "set_name":
            ea, err = validate_addr(addr)
            if err: return err
            if not name: return make_error(MCPError.INVALID_ARGS, "name required")
            # Find the function containing this address
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at or containing {hex(ea)}")
            target_ea = func.start_ea
            if idc.set_name(target_ea, name, ida_name.SN_FORCE):
                result = {"ok": True, "addr": hex(target_ea), "name": name}
                if func and target_ea != ea:
                    result["note"] = f"Renamed function at start address {hex(target_ea)}"
                return result
            return make_error(MCPError.IDA_ERROR, "Failed to set name", "Check if name is a valid C identifier")

        elif action == "add_comment":
            ea, err = validate_addr(addr)
            if err: return err
            if comment is None: return make_error(MCPError.INVALID_ARGS, "comment required")
            # Find function start for the comment
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at or containing {hex(ea)}")
            target_ea = func.start_ea
            idc.set_func_cmt(target_ea, comment, 1 if repeatable else 0)
            return {"ok": True, "addr": hex(target_ea), "comment": comment, "repeatable": repeatable}

        elif action == "list":
            if offset < 0:
                return make_error(MCPError.INVALID_ARGS, "offset must be >= 0")
            if count < 0:
                return make_error(MCPError.INVALID_ARGS, "count must be >= 0 (or 0 for all)")

            func_lines = []
            items = [] if include_items else None
            total = 0
            # Use smart pattern matching for queries
            if query:
                try:
                    matcher = compile_smart_pattern(query, case_sensitive=False)
                except Exception as e:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid query pattern: {e}")
            else:
                matcher = None

            for ea in idautils.Functions():
                fname = ida_funcs.get_func_name(ea)
                if named_only and fname.startswith("sub_"):
                    continue
                if matcher and not matcher(fname):
                    continue

                total += 1
                if total <= offset:
                    continue
                if count != 0 and len(func_lines) >= count:
                    break

                fn = ida_funcs.get_func(ea)
                if not fn:
                    continue
                size = hex_size(fn.end_ea - fn.start_ea)
                item = None
                if include_items:
                    item = {
                        "addr": hex_ea(ea),
                        "end": hex_ea(fn.end_ea),
                        "size": size,
                        "name": fname,
                    }
                if include_prototype:
                    proto = get_prototype(fn)
                    proto_text = _clip_text(proto, 280)
                    if item is not None:
                        item["prototype"] = proto_text
                    func_lines.append(f"{hex_ea(ea)}  {size}  {fname}  {proto_text}")
                else:
                    func_lines.append(f"{hex_ea(ea)}  {size}  {fname}")
                if item is not None:
                    items.append(item)

            returned = len(func_lines)
            has_more = (count != 0) and ((offset + returned) < total)
            result = {
                "ok": True,
                "functions": "\n".join(func_lines),
                "total": total,
                "offset": offset,
                "count": returned,
                "requested_count": count,
                "has_more": has_more,
            }
            if include_items:
                result["items"] = items
            return result

        elif action == "info":
            ea, err = validate_addr(addr)
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
            if include_xrefs:
                info["callers_sample"] = [hex_ea(x) for x in callers[:16]]
                info["callees_sample"] = [hex_ea(x) for x in callees[:16]]
            if include_prototype:
                info["prototype"] = get_prototype(fn)
            if include_stack:
                info["stack_frame"] = get_stack_frame_variables_internal(fn.start_ea, raise_error=False)
            return {"ok": True, "function": info}

        elif action == "metrics":
            ea, err = validate_addr(addr)
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
                        elif mnem.startswith("j") or mnem.startswith("b"):
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
                    for s in b.succs():
                        edges += 1
                cyclomatic = edges - bb_count + 2
                if cyclomatic < 1:
                    cyclomatic = 1
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
            ea, err = validate_addr(addr)
            if err: return err
            target_fn = ida_funcs.get_func(ea)
            if not target_fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            target_bytes = ida_bytes.get_bytes(target_fn.start_ea, target_fn.end_ea - target_fn.start_ea) or b""
            target_size = len(target_bytes)
            target_insn_count = sum(1 for _ in idautils.FuncItems(target_fn.start_ea))
            results = []
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
                if score >= (kwargs.get("min_score") or 60.0):
                    results.append({
                        "addr": hex(func_ea),
                        "name": ida_funcs.get_func_name(func_ea),
                        "score": score,
                        "size": hex(size),
                        "instructions": insn_count,
                    })
                    if len(results) >= max_candidates:
                        break
            results.sort(key=lambda x: -x["score"])
            limit = kwargs.get("limit") or 20
            return {"ok": True, "target": hex(target_fn.start_ea), "similar_functions": results[:limit], "count": len(results)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


@idaread
def _funcs_read_dispatch(**kwargs):
    return _funcs_impl(**kwargs)


@idawrite
def _funcs_write_dispatch(**kwargs):
    return _funcs_impl(**kwargs)


@tool
def funcs(
    action: Annotated[Literal["create", "delete", "set_flags", "set_name", "rename", "add_comment", "list", "info", "metrics", "find_similar"],
                      "Action: create|delete|set_flags|set_name|rename|add_comment|list|info|metrics|find_similar"],
    addr: Annotated[Optional[str], "Address"] = None,
    end: Annotated[Optional[str], "Optional end address (for create)"] = None,
    name: Annotated[Optional[str], "Function name"] = None,
    flags: Annotated[int, "Function flags (e.g. FUNC_NORET)"] = 0,
    force: Annotated[bool, "Force creation by deleting overlapping functions/data"] = False,
    comment: Annotated[Optional[str], "Function comment"] = None,
    repeatable: Annotated[bool, "Is comment repeatable?"] = False,
    query: Annotated[Optional[str], "Filter for function names - supports regex, glob, or substring (list action)"] = None,
    offset: Annotated[int, "Pagination offset (list action)"] = 0,
    count: Annotated[int, "Max results (0=all) (list action)"] = 100,
    named_only: Annotated[bool, "Only return named functions (list action)"] = False,
    include_prototype: Annotated[bool, "Include function prototype (info/list)"] = False,
    include_stack: Annotated[bool, "Include stack frame variables (info)"] = False,
    include_items: Annotated[bool, "Include structured `items` list in list output (default: false for context efficiency)"] = False,
    include_xrefs: Annotated[bool, "Include caller/callee samples in info output"] = False,
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
    - set_name/rename: Rename function at `addr`.
    - add_comment: Set function-level comment.
    - list: Paginated listing with optional name filtering.
      Query supports regex (e.g. ^init, \\w+alloc), glob (*alloc*), or plain substring.
      Returns compact text: "addr  size  name [prototype]" per line.
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
        "comment": comment,
        "repeatable": repeatable,
        "query": query,
        "offset": offset,
        "count": count,
        "named_only": named_only,
        "include_prototype": include_prototype,
        "include_stack": include_stack,
        "include_items": include_items,
        "include_xrefs": include_xrefs,
        **kwargs,
    }
    normalized_action = "set_name" if action == "rename" else action
    if normalized_action in ("list", "info"):
        return _funcs_read_dispatch(**call_kwargs)
    return _funcs_write_dispatch(**call_kwargs)


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================
