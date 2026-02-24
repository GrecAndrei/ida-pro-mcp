
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# ABI - Calling convention and ABI analysis
# ============================================================================

@tool
@idaread
def abi(
    action: Annotated[Literal["detect", "stack_args", "reg_args", "return_type", "varargs", "struct_return", "tail_calls", "prologue", "epilogue", "abi_violations"],
                      "ABI analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    **kwargs
) -> dict:
    """
    Analyze ABI and calling conventions for functions.

    Actions:
    - detect: Detect calling convention of a function (cdecl, stdcall, fastcall, thiscall, etc.)
    - stack_args: Analyze stack-passed arguments for a function.
    - reg_args: Analyze register-passed arguments.
    - return_type: Infer return type and register from function behavior.
    - varargs: Detect variadic function patterns.
    - struct_return: Detect functions returning structs (hidden pointer arg).
    - tail_calls: Detect tail call optimization.
    - prologue: Analyze function prologue pattern.
    - epilogue: Analyze function epilogue pattern.
    - abi_violations: Find calling convention violations/mismatches.
    """
    try:
        CC_MAP = {
            0: "unknown",
            0x10: "voidarg",
            0x20: "cdecl",
            0x30: "ellipsis",
            0x40: "stdcall",
            0x50: "pascal",
            0x60: "fastcall",
            0x70: "thiscall",
            0x80: "manual",
        }
        # IDA uses CM_CC_* constants; build a reverse map from idc if available
        for attr_name in dir(idc):
            if attr_name.startswith("CM_CC_"):
                val = getattr(idc, attr_name)
                if isinstance(val, int) and val not in CC_MAP:
                    CC_MAP[val] = attr_name.replace("CM_CC_", "").lower()

        def _get_func_ea(address):
            """Resolve address string to function start EA."""
            ea, err = validate_addr(address)
            if err:
                return None, err
            fn = ida_funcs.get_func(ea)
            if not fn:
                return None, make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at or containing {hex(ea)}")
            return fn, None

        def _disasm_range(start_ea, end_ea, max_insns=20):
            """Disassemble instructions in a range, returning list of dicts."""
            insns = []
            ea = start_ea
            while ea < end_ea and ea != idaapi.BADADDR and len(insns) < max_insns:
                mnem = idc.print_insn_mnem(ea)
                if not mnem:
                    break
                ops = []
                for i in range(6):
                    op = idc.print_operand(ea, i)
                    if op:
                        ops.append(op)
                    else:
                        break
                insns.append({"addr": hex(ea), "mnem": mnem, "operands": ops})
                ea = idc.next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
            return insns

        def _cc_raw_from_tif(tif, fdet=None):
            """
            Extract calling-convention raw value across IDA SDK variants.
            Some builds expose it via tinfo_t.get_cc(), others via func_type_data_t.cc.
            """
            try:
                if hasattr(tif, "get_cc") and callable(getattr(tif, "get_cc")):
                    val = tif.get_cc()
                    if isinstance(val, int):
                        return val & 0xF0
            except Exception:
                pass
            if fdet is not None:
                try:
                    cc_attr = getattr(fdet, "cc", None)
                    if isinstance(cc_attr, int):
                        return cc_attr & 0xF0
                    if callable(cc_attr):
                        maybe = cc_attr()
                        if isinstance(maybe, int):
                            return maybe & 0xF0
                except Exception:
                    pass
            return 0

        if action == "detect":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            # The calling convention is stored via the type info
            cc_raw = 0
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                fdet = ida_typeinf.func_type_data_t()
                if tif.get_func_details(fdet):
                    cc_raw = _cc_raw_from_tif(tif, fdet)
                else:
                    cc_raw = _cc_raw_from_tif(tif, None)
            cc_name = CC_MAP.get(cc_raw, f"unknown(0x{cc_raw:02x})")
            fname = ida_funcs.get_func_name(fn.start_ea)
            proto = get_prototype(fn)
            return {
                "ok": True,
                "addr": hex(fn.start_ea),
                "name": fname,
                "calling_convention": cc_name,
                "cc_raw": hex(cc_raw),
                "prototype": proto,
            }

        elif action == "stack_args":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            frame = ida_frame.get_frame(fn.start_ea)
            if not frame:
                return {"ok": True, "addr": hex(fn.start_ea), "stack_args": [], "note": "No stack frame found"}
            args = []
            for i in range(frame.memqty):
                member = frame.get_member(i)
                if not member:
                    continue
                if hasattr(ida_frame, "get_member_name"):
                    mname = ida_frame.get_member_name(member.id)
                elif hasattr(idc, "get_member_name"):
                    mname = idc.get_member_name(frame.id, member.soff)
                else:
                    mname = f"member_{i}"
                if not mname:
                    mname = f"member_{i}"
                offset = member.soff
                msize = member.eoff - member.soff
                # Determine type string
                tif_m = ida_typeinf.tinfo_t()
                type_str = ""
                if hasattr(ida_frame, "get_member_tinfo"):
                    try:
                        if ida_frame.get_member_tinfo(tif_m, member):
                            type_str = str(tif_m)
                    except Exception:
                        pass
                args.append({
                    "name": mname,
                    "offset": hex(offset),
                    "size": msize,
                    "type": type_str,
                })
                if len(args) >= limit:
                    break
            return {"ok": True, "addr": hex(fn.start_ea), "name": ida_funcs.get_func_name(fn.start_ea), "stack_args": args}

        elif action == "reg_args":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            # Try to get register arguments from type info
            reg_args = []
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                fdet = ida_typeinf.func_type_data_t()
                if tif.get_func_details(fdet):
                    for i in range(fdet.size()):
                        arg = fdet[i]
                        argloc = arg.argloc
                        if argloc.is_reg1():
                            reg_info = ida_typeinf.reg_info_t()
                            reg_name = ""
                            reg_no = argloc.reg1()
                            if hasattr(idaapi, "get_reg_name"):
                                # Try to get register name from register number
                                # Use ph_get_regnames or direct mapping
                                try:
                                    reg_name = idaapi.get_reg_name(reg_no, arg.type.get_size())
                                except Exception:
                                    reg_name = f"reg{reg_no}"
                            else:
                                reg_name = f"reg{reg_no}"
                            reg_args.append({
                                "index": i,
                                "name": arg.name or f"arg{i}",
                                "register": reg_name,
                                "type": str(arg.type),
                            })
                        if len(reg_args) >= limit:
                            break
            if not reg_args:
                # Fallback: check first few instructions for common register usage
                insns = _disasm_range(fn.start_ea, fn.end_ea, max_insns=10)
                note = "No type info available; inspect prologue instructions for register usage"
                return {"ok": True, "addr": hex(fn.start_ea), "name": ida_funcs.get_func_name(fn.start_ea), "reg_args": [], "prologue_insns": "\n".join(str(x) for x in insns), "note": note}
            return {"ok": True, "addr": hex(fn.start_ea), "name": ida_funcs.get_func_name(fn.start_ea), "reg_args": reg_args}

        elif action == "return_type":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            ret_type = "unknown"
            ret_reg = get_return_register()  # arch-aware default
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                fdet = ida_typeinf.func_type_data_t()
                if tif.get_func_details(fdet):
                    ret_tif = tif.get_rettype()
                    ret_type = str(ret_tif) if ret_tif else "void"
                    # Check return location
                    retloc = fdet.retloc
                    if retloc.is_reg1():
                        reg_no = retloc.reg1()
                        if hasattr(idaapi, "get_reg_name"):
                            try:
                                ret_reg = idaapi.get_reg_name(reg_no, ret_tif.get_size() if ret_tif else 4)
                            except Exception:
                                ret_reg = f"reg{reg_no}"
                        else:
                            ret_reg = f"reg{reg_no}"
            proto = get_prototype(fn)
            return {
                "ok": True,
                "addr": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea),
                "return_type": ret_type,
                "return_register": ret_reg,
                "prototype": proto,
            }

        elif action == "varargs":
            if not addr:
                # Scan all functions for variadic patterns
                results = []
                for ea in idautils.Functions():
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, ea):
                        fdet = ida_typeinf.func_type_data_t()
                        if tif.get_func_details(fdet):
                            cc = _cc_raw_from_tif(tif, fdet)
                            if cc == 0x30:  # CM_CC_ELLIPSIS
                                fname = ida_funcs.get_func_name(ea)
                                results.append(f"{hex(ea)}  {fname}")
                                if len(results) >= limit:
                                    break
                    # Also check prototype string for "..."
                    proto = idc.get_type(ea)
                    if proto and "..." in proto:
                        fname = ida_funcs.get_func_name(ea)
                        entry = f"{hex(ea)}  {fname}"
                        if entry not in results:
                            results.append(entry)
                            if len(results) >= limit:
                                break
                return {"ok": True, "varargs_functions": "\n".join(results), "count": len(results)}
            else:
                fn, err = _get_func_ea(addr)
                if err:
                    return err
                is_varargs = False
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, fn.start_ea):
                    fdet = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(fdet):
                        cc = _cc_raw_from_tif(tif, fdet)
                        if cc == 0x30:
                            is_varargs = True
                proto = idc.get_type(fn.start_ea) or get_prototype(fn)
                if proto and "..." in proto:
                    is_varargs = True
                return {
                    "ok": True,
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea),
                    "is_varargs": is_varargs,
                    "prototype": proto,
                }

        elif action == "struct_return":
            if not addr:
                # Scan all functions for struct return patterns
                results = []
                for ea in idautils.Functions():
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, ea):
                        ret_tif = tif.get_rettype()
                        if ret_tif and ret_tif.is_struct():
                            fname = ida_funcs.get_func_name(ea)
                            results.append(f"{hex(ea)}  {fname}  ret={ret_tif}")
                            if len(results) >= limit:
                                break
                return {"ok": True, "struct_return_functions": "\n".join(results), "count": len(results)}
            else:
                fn, err = _get_func_ea(addr)
                if err:
                    return err
                is_struct_ret = False
                ret_type_str = ""
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, fn.start_ea):
                    ret_tif = tif.get_rettype()
                    if ret_tif:
                        ret_type_str = str(ret_tif)
                        if ret_tif.is_struct():
                            is_struct_ret = True
                return {
                    "ok": True,
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea),
                    "is_struct_return": is_struct_ret,
                    "return_type": ret_type_str,
                    "prototype": get_prototype(fn),
                }

        elif action == "tail_calls":
            results = []
            if addr:
                fn, err = _get_func_ea(addr)
                if err:
                    return err
                func_iter = [fn]
            else:
                func_iter = []
                for ea in idautils.Functions():
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        func_iter.append(fn)
                    if len(func_iter) >= limit * 10:
                        break

            for fn in func_iter:
                # Walk backward from end to find last instruction
                ea = idc.prev_head(fn.end_ea, fn.start_ea)
                if ea == idaapi.BADADDR:
                    continue
                mnem = idc.print_insn_mnem(ea)
                if not mnem:
                    continue
                mnem_lower = mnem.lower()
                if mnem_lower in get_tail_call_mnemonics():  # arch-aware tail call detection
                    target_op = idc.print_operand(ea, 0)
                    fname = ida_funcs.get_func_name(fn.start_ea)
                    results.append(f"{hex(fn.start_ea)}  {fname}  tail_jmp={target_op}")
                    if len(results) >= limit:
                        break
            return {"ok": True, "tail_calls": "\n".join(results), "count": len(results)}

        elif action == "prologue":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            insns = _disasm_range(fn.start_ea, fn.end_ea, max_insns=15)
            # Classify prologue pattern
            pattern = get_prologue_pattern(
                [i["mnem"] for i in insns[:5]]) if insns else "unknown"
            return {
                "ok": True,
                "addr": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea),
                "pattern": pattern,
                "instructions": "\n".join(str(x) for x in insns),
            }

        elif action == "epilogue":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            fn, err = _get_func_ea(addr)
            if err:
                return err
            # Collect last N instructions
            all_heads = []
            ea = fn.start_ea
            while ea < fn.end_ea and ea != idaapi.BADADDR:
                all_heads.append(ea)
                ea = idc.next_head(ea, fn.end_ea)
                if ea == idaapi.BADADDR:
                    break
            tail_heads = all_heads[-15:] if len(all_heads) > 15 else all_heads
            insns = []
            for h in tail_heads:
                mnem = idc.print_insn_mnem(h)
                if not mnem:
                    continue
                ops = []
                for i in range(6):
                    op = idc.print_operand(h, i)
                    if op:
                        ops.append(op)
                    else:
                        break
                insns.append({"addr": hex(h), "mnem": mnem, "operands": ops})
            # Classify epilogue pattern
            pattern = get_epilogue_pattern(
                [i["mnem"] for i in insns]) if insns else "unknown"
            return {
                "ok": True,
                "addr": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea),
                "pattern": pattern,
                "instructions": "\n".join(str(x) for x in insns),
            }

        elif action == "abi_violations":
            results = []
            if addr:
                fn, err = _get_func_ea(addr)
                if err:
                    return err
                func_iter = [fn]
            else:
                func_iter = []
                for ea in idautils.Functions():
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        func_iter.append(fn)

            for fn in func_iter:
                fname = ida_funcs.get_func_name(fn.start_ea)
                # Check 1: Function has type info with mismatched stack cleanup
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, fn.start_ea):
                    fdet = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(fdet):
                        cc = _cc_raw_from_tif(tif, fdet)
                        cc_name = CC_MAP.get(cc, f"0x{cc:02x}")
                        # Check for stdcall with non-zero purge mismatch
                        if cc == 0x40:  # stdcall
                            # Stdcall functions should clean their own stack
                            # Check last instruction for ret N
                            last_ea = idc.prev_head(fn.end_ea, fn.start_ea)
                            if last_ea != idaapi.BADADDR:
                                mnem = idc.print_insn_mnem(last_ea)
                                if mnem:
                                    ml = mnem.lower()
                                    disasm = (idc.print_operand(last_ea, 0) or "").lower()
                                    if is_return_mnemonic(ml, disasm):
                                        op = idc.print_operand(last_ea, 0)
                                        # stdcall with args should have ret N
                                        if fdet.size() > 0 and (not op or op == ""):
                                            results.append(f"{hex(fn.start_ea)}  {fname}  stdcall_no_stack_cleanup  cc={cc_name}")
                # Check 2: NORET flag but function has ret instruction
                if fn.flags & ida_funcs.FUNC_NORET:
                    last_ea = idc.prev_head(fn.end_ea, fn.start_ea)
                    if last_ea != idaapi.BADADDR:
                        mnem = idc.print_insn_mnem(last_ea)
                        if mnem:
                            ml = mnem.lower()
                            disasm = (idc.print_operand(last_ea, 0) or "").lower()
                            if is_return_mnemonic(ml, disasm):
                                results.append(f"{hex(fn.start_ea)}  {fname}  noret_has_ret")
                if len(results) >= limit:
                    break

            return {"ok": True, "violations": "\n".join(results), "count": len(results)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
