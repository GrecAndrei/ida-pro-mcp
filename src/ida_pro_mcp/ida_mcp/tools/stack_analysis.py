
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    import ida_struct
except Exception:
    ida_struct = None

try:
    import ida_ua
except Exception:
    ida_ua = None


# Canary symbol names across architectures
_CANARY_SYMBOLS = [
    "__stack_chk_guard",       # GCC / ARM / Linux
    "__stack_chk_fail",        # GCC canary check failure handler
    "___stack_chk_guard",      # macOS / iOS (underscore-prefixed)
    "___stack_chk_fail",       # macOS / iOS
    "__security_cookie",       # MSVC x86/x64
    "__security_check_cookie", # MSVC cookie check
    "@__security_check_cookie@4",  # MSVC __fastcall variant
    "__stack_chk_fail_local",  # some GCC builds
]

# Dynamic allocation patterns
_ALLOCA_SYMBOLS = [
    "alloca", "_alloca", "__alloca",
    "__chkstk", "_chkstk", "__chkstk_ms",
    "__alloca_probe", "__alloca_probe_16",
]

# Store-type mnemonics (the destination operand is a memory write). The
# uninitialized heuristic must only count these: instructions like
# 'cmp [rbp-8], 0' are reads, not writes, and must not mark a local as
# initialized.
_STORE_MNEMONICS = {
    "mov", "movzx", "movsx", "movsxd", "movss", "movsd", "movd", "movq",
    "str", "strb", "strh", "strd",
    "sw", "sh", "sb", "sd", "st", "stb", "stw", "std",
    "stosb", "stosw", "stosd", "stosq",
    "fst", "fstp",
}

# Shared buffer/array size heuristic so the `buffers`, `arrays`, and `summary`
# actions agree on the same frame. A member is buffer-like when its type is an
# explicit array (`[...]`), or it is a char/byte block of at least 8 bytes (a
# C fixed buffer), or any other non-pointer member of at least 16 bytes.
_BUFFER_MIN_SIZE = 8
_ARRAY_MIN_SIZE = 16


def _is_buffer_like(type_str: str, size: int) -> bool:
    """Return True when a frame member should be treated as a buffer/array."""
    if "[" in type_str:
        return True
    if size >= _BUFFER_MIN_SIZE and "char" in type_str.lower():
        return True
    return size >= _ARRAY_MIN_SIZE and "*" not in type_str


def _get_func_or_error(addr):
    """Resolve addr to a function object, returning (func, error_dict_or_None)."""
    if addr is not None:
        ea, err = validate_addr(addr)
        if err:
            return None, err
    else:
        ea = idc.get_screen_ea()
        if ea == idaapi.BADADDR:
            return None, make_error(MCPError.INVALID_ARGS, "addr required (no cursor position in headless mode)")
    func = idaapi.get_func(ea)
    if not func:
        return None, make_error(MCPError.INVALID_ARGS,
                                f"No function at {hex(ea)}")
    return func, None


def _get_frame_or_error(func):
    """Get stack frame for a function, returning (frame, error_dict_or_None)."""
    frame = None
    get_frame_fn = getattr(ida_frame, "get_frame", None)
    if callable(get_frame_fn):
        try:
            frame = get_frame_fn(func)
        except Exception:
            frame = None

    if not frame and ida_struct is not None and hasattr(idc, "get_frame_id"):
        try:
            sid = idc.get_frame_id(func.start_ea)
            if sid not in (None, idaapi.BADADDR, -1):
                frame = ida_struct.get_struc(sid)
        except Exception:
            frame = None

    if not frame:
        return None, {"ok": True, "members": [],
                      "note": "No stack frame for this function"}
    return frame, None


def _member_name(frame, member, idx):
    """Get a member name, handling IDA version differences."""
    if hasattr(ida_frame, "get_member_name"):
        name = ida_frame.get_member_name(member.id)
    elif hasattr(idc, "get_member_name"):
        name = idc.get_member_name(frame.id, member.soff)
    else:
        name = None
    return name or f"var_{idx}"


def _member_type_str(member):
    """Get type string for a frame member."""
    tif = ida_typeinf.tinfo_t()
    if hasattr(ida_frame, "get_member_tinfo"):
        try:
            if ida_frame.get_member_tinfo(tif, member):
                return str(tif)
        except Exception:
            pass
    return ""


def _iter_frame_members(frame):
    """Iterate over all frame members, yielding (index, member, name, offset, size, type_str)."""
    for i in range(frame.memqty):
        member = frame.get_member(i)
        if not member:
            continue
        name = _member_name(frame, member, i)
        offset = member.soff
        size = member.eoff - member.soff
        type_str = _member_type_str(member)
        yield i, member, name, offset, size, type_str


def _get_arch_info():
    """Return architecture info dict for context."""
    bits = _inf_bitness()
    is_64 = bits == 64
    proc = _inf_procname()
    ptr_size = 8 if is_64 else 4
    return {
        "proc": proc.strip().upper(),
        "bits": bits,
        "ptr_size": ptr_size,
    }


def _frame_size(frame) -> int:
    """Compute frame size with compatibility fallbacks across IDA builds."""
    if not frame:
        return 0

    if ida_struct is not None and hasattr(ida_struct, "get_struc_size"):
        try:
            return int(ida_struct.get_struc_size(frame))
        except Exception:
            pass

    getter = getattr(ida_frame, "get_struc_size", None)
    if callable(getter):
        try:
            return int(getter(frame))
        except Exception:
            pass

    # Last-resort estimate from member end offsets.
    try:
        max_eoff = 0
        for i in range(getattr(frame, "memqty", 0)):
            member = frame.get_member(i)
            if member and hasattr(member, "eoff"):
                max_eoff = max(max_eoff, int(member.eoff))
        return max_eoff
    except Exception:
        return 0


@tool
@idaread
def stack_analysis(
    action: Annotated[Literal["frame", "buffers", "canary", "alignment", "spills",
                              "usage", "variables", "arrays", "uninitialized", "summary"],
                      "Stack analysis action"],
    addr: Annotated[Optional[str], "Function address to analyze"] = None,
    limit: Annotated[int, "Max results for scanning actions"] = 50,
) -> dict:
    """
    Deep stack frame analysis for LLM-assisted reverse engineering.

    ACTIONS:

    frame - Full stack frame layout (all variables, args, saved regs with offsets/types)
        Returns: {function, frame_size, members[]}
        Example: stack_analysis(action="frame", addr="main")

    buffers - Find stack buffers and their sizes (potential overflow targets)
        Returns: {function, buffers[], count}
        Example: stack_analysis(action="buffers", addr="0x401000")

    canary - Detect stack canary/cookie usage in a function
        Returns: {function, has_canary, canary_type, details}
        Example: stack_analysis(action="canary", addr="main")

    alignment - Analyze stack alignment requirements
        Returns: {function, frame_size, alignment, aligned_to}
        Example: stack_analysis(action="alignment", addr="0x401000")

    spills - Find register spills to stack
        Returns: {function, spills[], count}
        Example: stack_analysis(action="spills", addr="main")

    usage - Stack usage analysis (max depth, dynamic alloca)
        Returns: {function, frame_size, has_dynamic_alloc, max_spd}
        Example: stack_analysis(action="usage", addr="0x401000")

    variables - Enhanced local variable analysis with types and access patterns
        Returns: {function, variables[], count}
        Example: stack_analysis(action="variables", addr="main")

    arrays - Detect array variables on the stack and their element sizes
        Returns: {function, arrays[], count}
        Example: stack_analysis(action="arrays", addr="0x401000")

    uninitialized - Find potentially uninitialized stack variables
        Returns: {function, uninitialized[], count}
        Example: stack_analysis(action="uninitialized", addr="main")

    summary - Quick stack frame summary for LLM context
        Returns: {function, frame_size, local_count, arg_count, has_canary, has_buffers}
        Example: stack_analysis(action="summary", addr="0x401000")
    """
    try:
        func, err = _get_func_or_error(addr)
        if err:
            return err
        func_name = ida_funcs.get_func_name(func.start_ea)
        arch = _get_arch_info()

        # ---- frame: Full stack frame layout ----
        if action == "frame":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _frame_size(frame)
            members = []
            for idx, _member, name, offset, size, type_str in _iter_frame_members(frame):
                members.append({
                    "index": idx,
                    "name": name,
                    "offset": hex(offset),
                    "size": size,
                    "type": type_str,
                })
                if len(members) >= limit:
                    break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "frame_size": frame_size,
                "member_count": len(members),
                "members": "\n".join(str(x) for x in members),
                "arch": arch,
            }

        # ---- buffers: Find stack buffers ----
        elif action == "buffers":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            buffers = []
            for _, _member, name, offset, size, type_str in _iter_frame_members(frame):
                # Arrays are buffers; shared heuristic keeps `summary`/`arrays`
                # in agreement on the same frame.
                if _is_buffer_like(type_str, size):
                    buffers.append({
                        "name": name,
                        "offset": hex(offset),
                        "size": size,
                        "type": type_str,
                    })
                    if len(buffers) >= limit:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "buffers": "\n".join(str(x) for x in buffers),
                "count": len(buffers),
            }

        # ---- canary: Detect stack canary/cookie ----
        elif action == "canary":
            has_canary = False
            canary_type = None
            canary_refs = []
            # Check for xrefs from this function to canary symbols
            for sym in _CANARY_SYMBOLS:
                sym_ea = idc.get_name_ea_simple(sym)
                if sym_ea == idaapi.BADADDR:
                    continue
                xref_count = 0
                for xref in idautils.XrefsTo(sym_ea, 0):
                    ref_func = idaapi.get_func(xref.frm)
                    if ref_func and ref_func.start_ea == func.start_ea:
                        has_canary = True
                        if "security_cookie" in sym.lower():
                            canary_type = "MSVC_security_cookie"
                        elif "stack_chk" in sym.lower():
                            canary_type = "GCC_stack_chk"
                        canary_refs.append({
                            "symbol": sym,
                            "ref_addr": hex_ea(xref.frm),
                        })
                    xref_count += 1
                    if xref_count >= 5000:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "has_canary": has_canary,
                "canary_type": canary_type,
                "references": "\n".join(str(x) for x in canary_refs),
                "arch": arch["proc"],
            }

        # ---- alignment: Stack alignment requirements ----
        elif action == "alignment":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _frame_size(frame)
            # Determine alignment from frame size and architecture
            if frame_size == 0:
                alignment = arch["ptr_size"]
            else:
                alignment = 1
                for a in (32, 16, 8, 4, 2):
                    if frame_size % a == 0:
                        alignment = a
                        break
            # Check member alignments
            max_member_align = 1
            member_details = []
            for _, _member, name, offset, size, _type_str in _iter_frame_members(frame):
                m_align = 1
                for a in (16, 8, 4, 2):
                    if offset % a == 0 and size >= a:
                        m_align = a
                        break
                max_member_align = max(max_member_align, m_align)
                member_details.append({
                    "name": name,
                    "offset": hex(offset),
                    "size": size,
                    "natural_alignment": m_align,
                })
                if len(member_details) >= limit:
                    break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "frame_size": frame_size,
                "frame_alignment": alignment,
                "max_member_alignment": max_member_align,
                "members": "\n".join(str(x) for x in member_details),
                "arch": arch,
            }

        # ---- spills: Find register spills to stack ----
        elif action == "spills":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            spills = []
            # Build a set of callee-saved registers for the current arch
            _arch_name = get_arch()
            callee_saved = get_callee_saved_registers(_arch_name)
            for _, _member, name, offset, size, _type_str in _iter_frame_members(frame):
                is_spill = False
                n = name.lower()
                # Saved register detection (common IDA naming patterns)
                if n.startswith((" s", "__saved")) or n in ("r", "s") or n in callee_saved:
                    is_spill = True
                if is_spill:
                    spills.append({
                        "name": name,
                        "offset": hex(offset),
                        "size": size,
                    })
                    if len(spills) >= limit:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "spills": "\n".join(str(x) for x in spills),
                "count": len(spills),
                "arch": arch["proc"],
            }

        # ---- usage: Stack usage analysis ----
        elif action == "usage":
            frame, _ = _get_frame_or_error(func)
            frame_size = _frame_size(frame) if frame else 0
            # Track stack pointer delta across the function
            max_spd = 0
            min_spd = 0
            ea = func.start_ea
            usage_iter = 0
            while ea < func.end_ea and ea != idaapi.BADADDR:
                spd = ida_frame.get_spd(func, ea)
                if spd is not None:
                    max_spd = max(max_spd, spd)
                    min_spd = min(min_spd, spd)
                ea = idc.next_head(ea)
                usage_iter += 1
                if usage_iter >= 100000:
                    break
            # Check for dynamic allocation (alloca/__chkstk)
            has_dynamic_alloc = False
            alloca_calls = []
            for sym in _ALLOCA_SYMBOLS:
                sym_ea = idc.get_name_ea_simple(sym)
                if sym_ea == idaapi.BADADDR:
                    continue
                xref_count = 0
                for xref in idautils.XrefsTo(sym_ea, 0):
                    ref_func = idaapi.get_func(xref.frm)
                    if ref_func and ref_func.start_ea == func.start_ea:
                        has_dynamic_alloc = True
                        alloca_calls.append({
                            "symbol": sym,
                            "call_addr": hex_ea(xref.frm),
                        })
                    xref_count += 1
                    if xref_count >= 5000:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "frame_size": frame_size,
                "max_spd": max_spd,
                "min_spd": min_spd,
                "has_dynamic_alloc": has_dynamic_alloc,
                "alloca_calls": "\n".join(str(x) for x in alloca_calls),
                "func_size": func.end_ea - func.start_ea,
            }

        # ---- variables: Enhanced local variable analysis ----
        elif action == "variables":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _frame_size(frame)
            variables = []
            for _, _member, name, offset, size, type_str in _iter_frame_members(frame):
                # Classify the variable
                n = name.lower()
                kind = "local"
                if n.startswith(("arg_", "param_")):
                    kind = "argument"
                elif n.startswith((" s", "__saved")):
                    kind = "saved_reg"
                elif n.startswith(" r") or n == "r":
                    kind = "return_addr"
                # Infer type category
                category = "unknown"
                tl = type_str.lower()
                if "*" in type_str or "ptr" in tl:
                    category = "pointer"
                elif "[" in type_str:
                    category = "array"
                elif any(t in tl for t in ("int", "long", "short", "dword", "qword", "word")):
                    category = "integer"
                elif "char" in tl or "byte" in tl:
                    category = "byte"
                elif "float" in tl or "double" in tl:
                    category = "float"
                elif "bool" in tl:
                    category = "boolean"
                elif size in (1, 2, 4, 8) and not type_str:
                    category = "integer"
                variables.append({
                    "name": name,
                    "offset": hex(offset),
                    "size": size,
                    "type": type_str,
                    "kind": kind,
                    "category": category,
                })
                if len(variables) >= limit:
                    break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "frame_size": frame_size,
                "variables": "\n".join(str(x) for x in variables),
                "count": len(variables),
            }

        # ---- arrays: Detect array variables ----
        elif action == "arrays":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            arrays = []
            for _, _member, name, offset, size, type_str in _iter_frame_members(frame):
                is_array = False
                element_size = 0
                element_count = 0
                if "[" in type_str:
                    is_array = True
                    # Parse element count from type like "char[64]"
                    import re
                    m = re.search(r'\[(\d+)\]', type_str)
                    if m:
                        element_count = int(m.group(1))
                        if element_count > 0:
                            element_size = size // element_count
                elif _is_buffer_like(type_str, size):
                    # Heuristic: large non-pointer / char block might be array
                    # (shared with `buffers`/`summary` so actions agree).
                    is_array = True
                    # Guess element size from type
                    tl = type_str.lower()
                    if "char" in tl or "byte" in tl:
                        element_size = 1
                    elif "short" in tl or "word" in tl:
                        element_size = 2
                    elif "int" in tl or "dword" in tl:
                        element_size = 4
                    elif "long" in tl or "qword" in tl:
                        element_size = 8
                    else:
                        element_size = 1  # default to byte array
                    if element_size > 0:
                        element_count = size // element_size
                if is_array:
                    arrays.append({
                        "name": name,
                        "offset": hex(offset),
                        "total_size": size,
                        "element_size": element_size,
                        "element_count": element_count,
                        "type": type_str,
                    })
                    if len(arrays) >= limit:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "arrays": "\n".join(str(x) for x in arrays),
                "count": len(arrays),
            }

        # ---- uninitialized: Find potentially uninitialized stack variables ----
        elif action == "uninitialized":
            frame, err = _get_frame_or_error(func)
            if err:
                return err
            # Collect all local variable offsets
            local_vars = []
            for _, _member, name, offset, size, type_str in _iter_frame_members(frame):
                n = name.lower()
                # Skip saved regs, return addr, and arguments
                if (n.startswith((" s", "__saved", " r", "arg_", "param_")) or n == "r"):
                    continue
                local_vars.append({
                    "name": name,
                    "offset": offset,
                    "size": size,
                    "type": type_str,
                })
            # Scan instructions for writes to stack frame offsets.
            #
            # Two corrections over the naive operand-dump approach:
            #  1. Only store-type instructions count, so reads such as
            #     'cmp [rbp-8], 0' are never recorded as writes.
            #  2. The frame offset is resolved via ida_frame.get_stkvar, which
            #     maps both RBP-relative and RSP-relative (frame-pointer-less)
            #     accesses to the actual frame-member offset, instead of
            #     comparing raw displacements (e.g. +0x10 for [rsp+0x10])
            #     against soffs.
            _arch_name = get_arch()
            _dst_op_index = 0 if is_x86_family(_arch_name) else 1
            written_offsets = set()
            ea = func.start_ea
            uninit_iter = 0
            while ea < func.end_ea and ea != idaapi.BADADDR:
                mnem = (idc.print_insn_mnem(ea) or "").lower()
                if mnem in _STORE_MNEMONICS:
                    try:
                        insn = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn, ea) > 0 and len(insn.ops) > _dst_op_index:
                            op = insn.ops[_dst_op_index]
                            if op.type in (ida_ua.o_displ, ida_ua.o_phrase):
                                try:
                                    member, _delta = ida_frame.get_stkvar(insn, op)
                                except Exception:
                                    member = None
                                if member is not None:
                                    written_offsets.add(member.soff)
                    except Exception:
                        pass
                ea = idc.next_head(ea)
                uninit_iter += 1
                if uninit_iter >= 100000:
                    break
            # Find locals with no detected write
            uninitialized = []
            for var in local_vars:
                off = var["offset"]
                if off not in written_offsets:
                    uninitialized.append({
                        "name": var["name"],
                        "offset": hex(var["offset"]),
                        "size": var["size"],
                        "type": var["type"],
                        "note": "No direct write detected (heuristic)",
                    })
                    if len(uninitialized) >= limit:
                        break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "uninitialized": "\n".join(str(x) for x in uninitialized),
                "count": len(uninitialized),
                "note": "Heuristic analysis; may have false positives",
            }

        # ---- summary: Quick stack frame summary ----
        elif action == "summary":
            frame, _ = _get_frame_or_error(func)
            frame_size = _frame_size(frame) if frame else 0
            local_count = 0
            arg_count = 0
            saved_count = 0
            buffer_count = 0
            has_canary = False
            if frame:
                for _, _member, name, _offset, size, type_str in _iter_frame_members(frame):
                    n = name.lower()
                    if n.startswith(("arg_", "param_")):
                        arg_count += 1
                    elif n.startswith((" s", "__saved")):
                        saved_count += 1
                    elif n.startswith(" r") or n == "r":
                        pass  # return addr
                    else:
                        local_count += 1
                    if _is_buffer_like(type_str, size):
                        buffer_count += 1
            # Quick canary check
            for sym in _CANARY_SYMBOLS:
                sym_ea = idc.get_name_ea_simple(sym)
                if sym_ea == idaapi.BADADDR:
                    continue
                xref_count = 0
                for xref in idautils.XrefsTo(sym_ea, 0):
                    ref_func = idaapi.get_func(xref.frm)
                    if ref_func and ref_func.start_ea == func.start_ea:
                        has_canary = True
                        break
                    xref_count += 1
                    if xref_count >= 5000:
                        break
                if has_canary:
                    break
            return {
                "ok": True,
                "function": func_name,
                "addr": hex_ea(func.start_ea),
                "frame_size": frame_size,
                "local_count": local_count,
                "arg_count": arg_count,
                "saved_reg_count": saved_count,
                "buffer_count": buffer_count,
                "has_canary": has_canary,
                "func_size": func.end_ea - func.start_ea,
                "arch": arch,
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
