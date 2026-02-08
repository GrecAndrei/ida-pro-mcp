
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 10. FUNCS - Function management
# ============================================================================

@tool
@idawrite
def funcs(
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
            existing = ida_funcs.get_func(ea)
            if existing and existing.start_ea == ea:
                if name:
                    idc.set_name(ea, name, ida_name.SN_FORCE)
                return {"ok": True, "addr": hex(ea), "name": name or ida_funcs.get_func_name(ea), "note": "Function already exists at this address"}
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
            if end_ea and force:
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, end_ea - ea)
            if ida_funcs.add_func(ea, end_ea or idaapi.BADADDR):
                if name:
                    idc.set_name(ea, name, ida_name.SN_FORCE)
                fn = ida_funcs.get_func(ea)
                if fn and flags:
                    fn.flags |= flags
                    ida_funcs.update_func(fn)
                try:
                    import ida_auto
                    ida_auto.auto_wait()
                except (ImportError, AttributeError):
                    pass
                # Get the created function's actual boundaries
                actual_end = hex(fn.end_ea) if fn else (hex(end_ea) if end_ea else None)
                return {"ok": True, "addr": hex(ea), "end": actual_end, "name": name or (ida_funcs.get_func_name(ea) if fn else None)}
            if end_ea and hasattr(idaapi, "auto_mark_range"):
                try:
                    idaapi.auto_mark_range(ea, end_ea, idaapi.AU_FINAL)
                    idaapi.auto_wait()
                except Exception:
                    pass
                if ida_funcs.add_func(ea, end_ea):
                    fn = ida_funcs.get_func(ea)
                    if fn and flags:
                        fn.flags |= flags
                        ida_funcs.update_func(fn)
                    actual_end = hex(fn.end_ea) if fn else hex(end_ea)
                    return {"ok": True, "addr": hex(ea), "end": actual_end, "name": name or (ida_funcs.get_func_name(ea) if fn else None), "note": "Function created after auto-analysis retry"}
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
            func.flags = flags
            if ida_funcs.update_func(func): return {"ok": True, "addr": hex(func.start_ea), "flags": hex(flags)}
            return make_error(MCPError.IDA_ERROR, "Failed to update flags")

        elif action == "set_name":
            ea, err = validate_addr(addr)
            if err: return err
            if not name: return make_error(MCPError.INVALID_ARGS, "name required")
            # Find the function containing this address
            func = ida_funcs.get_func(ea)
            target_ea = func.start_ea if func else ea
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
            target_ea = func.start_ea if func else ea
            idc.set_func_cmt(target_ea, comment, 1 if repeatable else 0)
            return {"ok": True, "addr": hex(target_ea), "comment": comment, "repeatable": repeatable}

        elif action == "list":
            func_lines = []
            total = 0
            # Use smart pattern matching for queries
            if query:
                matcher = compile_smart_pattern(query, case_sensitive=False)
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
                    continue

                fn = idaapi.get_func(ea)
                size = hex_size(fn.end_ea - fn.start_ea)
                if include_prototype:
                    proto = get_prototype(fn)
                    func_lines.append(f"{hex_ea(ea)}  {size}  {fname}  {proto}")
                else:
                    func_lines.append(f"{hex_ea(ea)}  {size}  {fname}")

            return {"ok": True, "functions": "\n".join(func_lines), "total": total, "offset": offset, "count": len(func_lines)}

        elif action == "info":
            ea, err = validate_addr(addr)
            if err: return err
            fn = idaapi.get_func(ea)
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
            }
            if include_prototype:
                info["prototype"] = get_prototype(fn)
            if include_stack:
                info["stack_frame"] = get_stack_frame_variables_internal(fn.start_ea, raise_error=False)
            return {"ok": True, "function": info}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 11. SEGMENTS - Segment management
# ============================================================================
