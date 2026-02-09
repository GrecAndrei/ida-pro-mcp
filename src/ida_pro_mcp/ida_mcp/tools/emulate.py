
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 27. EMULATE - Code Emulation and Snippet Execution
# ============================================================================

@tool
@idaread
def emulate(
    action: Annotated[Literal["static_trace", "appcall", "decrypt_strings", "eval_expr"],
                      "Action: static_trace|appcall|decrypt_strings|eval_expr"],
    addr: Annotated[Optional[str], "Address to trace from or function to call"] = None,
    func_name: Annotated[Optional[str], "Function name for appcall"] = None,
    args: Annotated[Optional[list], "Arguments for appcall"] = None,
    max_steps: Annotated[int, "Maximum instructions to trace"] = 1000,
    follow_calls: Annotated[bool, "Follow call edges in static_trace"] = False,
    max_depth: Annotated[int, "Max call depth in static_trace"] = 1,
    include_blocks: Annotated[bool, "Include basic block CFG info"] = True,
    expr: Annotated[Optional[str], "Expression for eval_expr"] = None,
    **kwargs
) -> dict:
    """
    Tracing and dynamic execution utilities.

    Actions:
    - static_trace: Follow control flow from `addr` statically (no register changes).
    - appcall: Call a function with arguments (requires active debugger).
    - decrypt_strings: Heuristic search for string decryption calls.
    - eval_expr: Evaluate value/name at address or an expression.
    """
    try:
        if action == "static_trace":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err

            func = ida_funcs.get_func(ea)
            trace = []
            visited = set()
            queue = [(ea, 0)]
            edges = []

            while queue and len(trace) < max_steps:
                curr, depth = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, curr) <= 0:
                    continue

                disasm = idc.generate_disasm_line(curr, 0)
                trace.append({"addr": hex(curr), "disasm": ida_lines.tag_remove(disasm) if disasm else ""})

                is_ret_fn = getattr(idaapi, 'is_ret_insn', None) or getattr(__import__('ida_idp'), 'is_ret_insn', None)
                if is_ret_fn and is_ret_fn(insn):
                    continue

                next_heads = []
                for xref in idautils.XrefsFrom(curr, 0):
                    if not xref.iscode:
                        continue
                    if not follow_calls and xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        continue
                    next_heads.append(xref.to)
                    edges.append({"from": hex(curr), "to": hex(xref.to)})

                if not next_heads:
                    fall = idc.next_head(curr)
                    if fall != idaapi.BADADDR:
                        next_heads.append(fall)
                        edges.append({"from": hex(curr), "to": hex(fall)})

                for n in next_heads:
                    if n != idaapi.BADADDR:
                        if func and not (func.start_ea <= n < func.end_ea):
                            if follow_calls and depth < max_depth:
                                queue.append((n, depth + 1))
                            continue
                        queue.append((n, depth))

            blocks = []
            if include_blocks and func:
                try:
                    fc = idaapi.FlowChart(func)
                    for b in fc:
                        blocks.append({
                            "start": hex(b.start_ea),
                            "end": hex(b.end_ea),
                            "succs": [hex(s.start_ea) for s in b.succs()],
                            "preds": [hex(p.start_ea) for p in b.preds()],
                        })
                except Exception:
                    blocks = []

            return {
                "ok": True,
                "start": hex(ea),
                "trace": trace,
                "edges": edges,
                "count": len(trace),
                "blocks": blocks,
            }

        elif action == "appcall":
            if not hasattr(idaapi, 'Appcall'): return make_error(MCPError.NOT_IMPLEMENTED, "Appcall not available")

            import ida_dbg
            if not ida_dbg.is_debugger_on():
                return make_error(MCPError.DEBUGGER_NOT_RUNNING, "Appcall requires a running debug session")

            if not func_name and not addr: return make_error(MCPError.INVALID_ARGS, "func_name or addr required")

            ea = idc.get_name_ea_simple(func_name) if func_name else parse_address(addr)
            if ea == idaapi.BADADDR: return make_error(MCPError.ADDRESS_INVALID, f"Function not found: {func_name or addr}")

            try:
                result = idaapi.Appcall.func_ptr(ea)(*(args or []))
                return {"ok": True, "function": func_name or hex(ea), "return_value": str(result)}
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Appcall failed: {e}")

        elif action == "decrypt_strings":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err

            calls = []
            for xref in idautils.XrefsTo(ea):
                if xref.iscode:
                    prev = xref.frm
                    for _ in range(12):
                        prev = idc.prev_head(prev)
                        if prev == idaapi.BADADDR:
                            break
                        for op_n in range(2):
                            val = idc.get_operand_value(prev, op_n)
                            if not val:
                                continue
                            s = idc.get_strlit_contents(val)
                            if s:
                                calls.append({
                                    "call_site": hex(xref.frm),
                                    "string_addr": hex(val),
                                    "string": s.decode('utf-8', 'replace'),
                                    "xref": hex(prev),
                                })
                                if len(calls) >= 50:
                                    break
                        if len(calls) >= 50:
                            break
                if len(calls) >= 50:
                    break
            return {"ok": True, "decrypt_function": hex(ea), "potential_calls": calls, "count": len(calls)}

        elif action == "eval_expr":
            if not addr and not expr:
                return make_error(MCPError.INVALID_ARGS, "addr or expr required")

            if expr:
                try:
                    val = idc.eval_idc(expr)
                    return {"ok": True, "expr": expr, "value": val}
                except Exception as e:
                    return make_error(MCPError.IDA_ERROR, f"Expression eval failed: {e}")

            ea, err = validate_addr(addr)
            if err: return err
            return {
                "ok": True,
                "addr": hex(ea),
                "u8": ida_bytes.get_byte(ea),
                "u16": ida_bytes.get_word(ea),
                "u32": ida_bytes.get_dword(ea),
                "u64": ida_bytes.get_qword(ea),
                "name": idc.get_name(ea)
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================  
# 28. EXPORT - Export Database in Various Formats
# ============================================================================
