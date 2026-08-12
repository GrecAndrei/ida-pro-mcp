
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

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
#
# Extended for opaque device work:
#   - RISC-V compressed C-extension stores (c.sw/c.swsp/c.sd/c.sdsp/c.sh/c.shsp)
#     and single-precision float stores (fsw/fsd/fsh + compressed forms), which
#     bare-metal RISC-V firmware uses heavily.
#   - ARM64 store-pair / store-unprivileged (stp/stnp/sturb/stur).
_STORE_MNEMONICS = {
    "mov", "movzx", "movsx", "movsxd", "movss", "movsd", "movd", "movq",
    "str", "strb", "strh", "strd",
    "sw", "sh", "sb", "sd", "st", "stb", "stw", "std",
    "stosb", "stosw", "stosd", "stosq",
    "fst", "fstp",
    # RISC-V compressed C-extension stores
    "c.sw", "c.swsp", "c.sd", "c.sdsp", "c.sh", "c.shsp",
    # RISC-V/MIPS single-precision float stores (and RISC-V compressed forms)
    "fsw", "fsd", "fsh",
    "c.fsw", "c.fswsp", "c.fsd", "c.fsdsp", "c.fsh", "c.fshsp",
    # ARM64 store-pair / store-unprivileged
    "stp", "stnp", "sturb", "stur",
}


def _is_store_insn(mnem: str, arch=None) -> bool:
    """Return True when ``mnem`` is a memory-store instruction.

    Whitelist-based on purpose: only genuine store mnemonics count, so reads
    that share a mnemonic with a store on some archs (e.g. x86 ``mov``) are
    filtered by the destination-operand scan rather than excluded here.
    """
    m = (mnem or "").lower().strip()
    return bool(m) and m in _STORE_MNEMONICS


def _store_dest_operand_indices(insn, arch) -> list[int]:
    """Return the operand index(es) that can hold the memory destination of a
    store instruction.

    On x86 the store destination is always operand 0 (``mov [mem], reg``) and
    loads of the same mnemonic put memory in operand 1 — so scanning only
    operand 0 keeps ``mov eax, [rbp-8]`` (a read) from marking a local
    initialized. Every other family uses distinct store mnemonics and puts the
    memory destination last (``sw a0, 0(sp)``, ``str x0, [sp]``,
    ``stp x0, x1, [sp]``), so all operands are candidates.
    """
    try:
        n_ops = len(insn.ops)
    except Exception:
        n_ops = 2
    if is_x86_family(arch):
        return [0]
    return list(range(n_ops))

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
    func = _compat.get_func_info(ea)
    if not func:
        return None, make_error(MCPError.INVALID_ARGS,
                                f"No function at {hex(ea)}")
    return func, None


def _get_frame_or_error(func):
    """Return (has_frame, err) for the function at ``func``.

    ``has_frame`` is True when the function has a stack frame; ``err`` is
    None then. When the function has no frame, returns (False, ok-note) so
    callers short-circuit with the same "No stack frame" result as before.
    The frame itself is walked through ``_compat.frame_members`` /
    ``_compat.frame_size``, which use the legacy ``struc_t`` surface on
    <= 9.3 and the 9.4 tinfo/udt surface (``ida_frame.get_func_frame_ea``)
    where ``ida_frame.get_frame`` and the ``ida_struct`` module are gone.
    """
    members = _compat.frame_members(func.start_ea)
    if members:
        return True, None
    if _compat.frame_size(func.start_ea) > 0:
        return True, None
    return False, {"ok": True, "members": [],
                   "note": "No stack frame for this function"}


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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _compat.frame_size(func.start_ea) if has_frame else 0
            members = []
            for idx, name, offset, size, type_str in _compat.frame_members(func.start_ea):
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            buffers = []
            for _, name, offset, size, type_str in _compat.frame_members(func.start_ea):
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
                    ref_func = _compat.get_func_start(xref.frm)
                    if ref_func is not None and ref_func == func.start_ea:
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _compat.frame_size(func.start_ea) if has_frame else 0
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
            for _, name, offset, size, _type_str in _compat.frame_members(func.start_ea):
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            spills = []
            # Build a set of callee-saved registers for the current arch
            _arch_name = get_arch()
            callee_saved = get_callee_saved_registers(_arch_name)
            for _, name, offset, size, _type_str in _compat.frame_members(func.start_ea):
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
            has_frame, _ = _get_frame_or_error(func)
            frame_size = _compat.frame_size(func.start_ea) if has_frame else 0
            # Track stack pointer delta across the function
            max_spd = 0
            min_spd = 0
            ea = func.start_ea
            usage_iter = 0
            while ea < func.end_ea and ea != idaapi.BADADDR:
                spd = _compat.get_spd(func.start_ea, ea)
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
                    ref_func = _compat.get_func_start(xref.frm)
                    if ref_func is not None and ref_func == func.start_ea:
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            frame_size = _compat.frame_size(func.start_ea) if has_frame else 0
            variables = []
            for _, name, offset, size, type_str in _compat.frame_members(func.start_ea):
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            arrays = []
            for _, name, offset, size, type_str in _compat.frame_members(func.start_ea):
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
            has_frame, err = _get_frame_or_error(func)
            if err:
                return err
            # Collect all local variable offsets
            local_vars = []
            for _, name, offset, size, type_str in _compat.frame_members(func.start_ea):
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
            written_offsets = set()
            ea = func.start_ea
            uninit_iter = 0
            while ea < func.end_ea and ea != idaapi.BADADDR:
                mnem = (idc.print_insn_mnem(ea) or "").lower()
                if _is_store_insn(mnem, _arch_name):
                    try:
                        insn = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn, ea) > 0:
                            for idx in _store_dest_operand_indices(insn, _arch_name):
                                if idx >= len(insn.ops):
                                    continue
                                op = insn.ops[idx]
                                if op.type not in (ida_ua.o_displ, ida_ua.o_phrase):
                                    continue
                                try:
                                    member, _delta = ida_frame.get_stkvar(insn, op)
                                except Exception:
                                    member = None
                                if member is not None:
                                    written_offsets.add(member.soff)
                                    break
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
            has_frame, _ = _get_frame_or_error(func)
            frame_size = _compat.frame_size(func.start_ea) if has_frame else 0
            local_count = 0
            arg_count = 0
            saved_count = 0
            buffer_count = 0
            has_canary = False
            if has_frame:
                for _, name, _offset, size, type_str in _compat.frame_members(func.start_ea):
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
                    ref_func = _compat.get_func_start(xref.frm)
                    if ref_func is not None and ref_func == func.start_ea:
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
