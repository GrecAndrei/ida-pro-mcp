
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .memrl import emit_memrl_suggestion
except ImportError:
    try:
        from memrl import emit_memrl_suggestion  # type: ignore[import-not-found]
    except ImportError:
        def emit_memrl_suggestion(*args, **kwargs):  # type: ignore
            return ""

try:
    from .blackboard import BlackboardStore
except ImportError:
    try:
        from blackboard import BlackboardStore  # type: ignore[import-not-found]
    except ImportError:
        BlackboardStore = None  # type: ignore


# ============================================================================
# 16. DATA_OPS - Data creation operations
# ============================================================================

@tool
@idawrite
def data_ops(
    action: Annotated[Literal["make_data", "make_array", "make_string", "undefine", "make_code", "cycle_data", "set_repr", "make_ptr"],
                      "Action: make_data|make_array|make_string|undefine|make_code|cycle_data|set_repr|make_ptr"],
    addr: Annotated[str, "Address"],
    size: Annotated[Optional[int], "Size in bytes"] = None,
    count: Annotated[Optional[int], "Array element count"] = None,
    str_type: Annotated[int, "String type (0=C, 1=Pascal, 2=UTF16)"] = 0,
    repr: Annotated[Optional[Literal["hex", "dec", "bin", "char", "offset"]], "Display representation for set_repr"] = None,
    auto_blackboard: Annotated[bool, "Store firmware-view action note in blackboard"] = True,
    **kwargs
) -> dict:
    """Data creation/editing helpers for firmware triage and quick view fixing.

    Includes lightweight "press D/R-like" operations for LLM workflows:
    - cycle_data: undefine current item and cycle byte->word->dword->qword
    - set_repr: set operand representation (hex/dec/bin/char/offset)
    - make_ptr: create pointer-sized data (uses current IDB bitness)
    """
    try:
        ea, err = validate_addr(addr)
        if err: return err

        def _flag_for_size(sz: int):
            return {
                1: ida_bytes.byte_flag(),
                2: ida_bytes.word_flag(),
                4: ida_bytes.dword_flag(),
                8: ida_bytes.qword_flag(),
                10: ida_bytes.tbyte_flag(),
                16: ida_bytes.oword_flag(),
            }.get(sz, ida_bytes.byte_flag())

        def _item_size_or_default(default: int = 1) -> int:
            try:
                cur = int(ida_bytes.get_item_size(ea) or 0)
                return cur if cur > 0 else default
            except Exception:
                return default

        def _next_steps_for(act: str, target_size: int = 0) -> list[str]:
            if act in ("make_data", "cycle_data", "make_ptr"):
                steps = [
                    f"data(action='lookup', query='{addr}') to inspect symbols at the converted address",
                    f"data_ops(action='set_repr', addr='{addr}', repr='offset') when value is a pointer",
                    f"search(action='semantic', query='xrefs around {addr}', limit=20) to find nearby semantics",
                ]
                if target_size in (4, 8):
                    steps.insert(1, f"search(action='code_ref', pattern='{addr}', include_context=true) to discover callers/users")
                return steps
            if act == "make_code":
                return [
                    f"code(action='disasm', addr='{addr}', limit=40) to verify decode quality",
                    f"ctree(action='get_logic_flow', addr='{addr}') once function boundary is confirmed",
                    f"data_ops(action='undefine', addr='{addr}', size=16) if decode looks misaligned",
                ]
            if act == "set_repr":
                return [
                    f"data_ops(action='set_repr', addr='{addr}', repr='hex') to revert default display",
                    f"search(action='find', pattern='{addr}', include_context=true) to correlate with refs",
                ]
            return [f"blackboard(action='list', category='firmware_view', addr='{addr}') to review prior local decisions"]

        def _attach_ml_context(result: dict, act: str, detail: str = "") -> dict:
            try:
                sug = emit_memrl_suggestion("data_ops", act, addr, detail or act)
                if sug:
                    result["memrl_suggestion_id"] = sug
            except Exception:
                pass
            if auto_blackboard and BlackboardStore is not None:
                try:
                    store = BlackboardStore()
                    title = f"data_ops:{act} at {addr}"
                    content = detail or f"Applied {act} at {addr}"
                    entry_id = store.write(
                        title=title,
                        content=content,
                        category="firmware_view",
                        addr=addr,
                        tags=["firmware", "view-shaping", "data_ops", act],
                        confidence=0.75,
                    )
                    result["blackboard_entry_id"] = entry_id
                except Exception:
                    pass
            result["next_actions"] = _next_steps_for(act, int(result.get("size") or 0))
            result["analysis_hint"] = "Firmware binaries often require iterative data/code reinterpretation; use cycle_data, set_repr, and make_ptr before deep semantic queries."
            return result

        if action == "make_data":
            if size is None:
                size = 1
            flags = _flag_for_size(int(size))
            if ida_bytes.create_data(ea, flags, size, idaapi.BADADDR):
                return _attach_ml_context({"ok": True, "addr": addr, "size": size, "action": action}, action, f"size={size}")
            return make_error(MCPError.IDA_ERROR, "Failed to create data")
        
        elif action == "make_array":
            if count is None:
                return make_error(MCPError.INVALID_ARGS, "count required")
            elem_size = size or 1
            flags = _flag_for_size(int(elem_size))
            if ida_bytes.create_data(ea, flags, elem_size, idaapi.BADADDR):
                # Set array info
                import ida_nalt as nalt
                arr = nalt.array_parameters()
                arr.flags = 0
                arr.lineitems = 0
                arr.alignment = 0
                nalt.set_array_parameters(ea, arr)
                idc.make_array(ea, count)
                return _attach_ml_context({"ok": True, "addr": addr, "count": count, "elem_size": elem_size, "action": action}, action, f"count={count}, elem_size={elem_size}")
            return make_error(MCPError.IDA_ERROR, "Failed to create array")

        elif action == "make_string":
            str_types = {0: idc.STRTYPE_C, 1: idc.STRTYPE_PASCAL, 2: idc.STRTYPE_C_16}
            stype = str_types.get(str_type, idc.STRTYPE_C)
            length = size or idaapi.BADADDR
            try:
                created = idc.create_strlit(ea, length if length != idaapi.BADADDR else idc.BADADDR, stype)
            except TypeError:
                created = idc.create_strlit(ea, length if length != idaapi.BADADDR else idc.BADADDR)
            if created:
                return _attach_ml_context({"ok": True, "addr": addr, "type": str_type, "action": action}, action, f"str_type={str_type}")
            return make_error(MCPError.IDA_ERROR, "Failed to create string")

        elif action == "undefine":
            length = size or ida_bytes.get_item_size(ea)
            if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, length):
                return _attach_ml_context({"ok": True, "addr": addr, "size": length, "action": action}, action, f"size={length}")
            return make_error(MCPError.IDA_ERROR, "Failed to undefine")

        elif action == "make_code":
            # Auto-detect Thumb mode for ARM Cortex-M firmware
            try:
                proc = (_inf_procname() or "").lower()
            except Exception:
                proc = ""
            if "arm" in proc:
                try:
                    sr_auto = getattr(idc, "SR_auto", 2)
                    idc.split_sreg_range(ea, "T", 1, sr_auto)
                except Exception:
                    try:
                        import ida_segregs
                        ida_segregs.split_sreg_range(ea, "T", 1, 2)
                    except Exception:
                        pass
            # Try ida_ua.create_insn first (IDA 9.x), fall back to idc.create_insn
            length = 0
            try:
                import ida_ua
                length = ida_ua.create_insn(ea)
            except Exception:
                length = idc.create_insn(ea)
            if length == 0:
                length = idc.create_insn(ea)
            if length > 0:
                return _attach_ml_context({"ok": True, "addr": addr, "size": length, "action": action}, action, f"insn_size={length}")
            return make_error(MCPError.IDA_ERROR, "Failed to create instruction", "Verify address is valid code. For ARM Thumb, ensure T=1 segment register is set via seg_reg action.")

        elif action == "make_ptr":
            ptr_size = _inf_ptr_size()
            if ida_bytes.create_data(ea, _flag_for_size(ptr_size), ptr_size, idaapi.BADADDR):
                try:
                    idc.op_offset(ea, 0, idc.REF_OFF64 if ptr_size == 8 else idc.REF_OFF32, 0, 0, 0)
                except Exception:
                    pass
                return _attach_ml_context({"ok": True, "addr": addr, "size": ptr_size, "pointer": True, "action": action}, action, f"ptr_size={ptr_size}")
            return make_error(MCPError.IDA_ERROR, "Failed to create pointer data")

        elif action == "cycle_data":
            cur_size = _item_size_or_default(1)
            cycle = [1, 2, 4, 8]
            next_size = cycle[(cycle.index(cur_size) + 1) % len(cycle)] if cur_size in cycle else 1
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(1, cur_size))
            if ida_bytes.create_data(ea, _flag_for_size(next_size), next_size, idaapi.BADADDR):
                return _attach_ml_context({"ok": True, "addr": addr, "previous_size": cur_size, "size": next_size, "action": action}, action, f"previous={cur_size}, next={next_size}")
            return make_error(MCPError.IDA_ERROR, "Failed to cycle data type")

        elif action == "set_repr":
            mode = repr or kwargs.get("mode")
            if not mode:
                return make_error(MCPError.INVALID_ARGS, "repr required (hex|dec|bin|char|offset)")
            m = str(mode).strip().lower()
            ok = False
            if m == "hex":
                ok = bool(idc.op_hex(ea, 0))
            elif m == "dec":
                ok = bool(idc.op_dec(ea, 0))
            elif m == "bin":
                ok = bool(idc.op_bin(ea, 0))
            elif m == "char":
                ok = bool(idc.op_chr(ea, 0))
            elif m == "offset":
                try:
                    reft = idc.REF_OFF64 if _inf_is_64bit() else idc.REF_OFF32
                    ok = bool(idc.op_offset(ea, 0, reft, 0, 0, 0))
                except Exception:
                    ok = False
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown repr mode: {mode}")
            if ok:
                return _attach_ml_context({"ok": True, "addr": addr, "repr": m, "action": action}, action, f"repr={m}")
            return make_error(MCPError.IDA_ERROR, f"Failed to set representation: {m}")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 17. AGENT - High-level analysis helpers
# ============================================================================
