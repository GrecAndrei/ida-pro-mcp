
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# ============================================================================
# GADGETS - ROP/JOP/COP Gadget & Exploit Primitive Discovery
# ============================================================================

# Architecture detection helpers

def _get_arch():
    """Return normalized architecture: 'x86', 'x64', 'arm', 'arm64', or 'unknown'."""
    info = idaapi.get_inf_structure()
    proc = info.procname.lower()
    is_64 = info.is_64bit()
    if proc.startswith("arm") or proc.startswith("aarch"):
        return "arm64" if is_64 else "arm"
    if proc.startswith("metapc") or "x86" in proc or "80386" in proc:
        return "x64" if is_64 else "x86"
    return "unknown"


def _is_x86_family(arch):
    return arch in ("x86", "x64")


def _is_arm_family(arch):
    return arch in ("arm", "arm64")


def _get_exec_segments(addr):
    """Yield (start, end) for executable segments. If addr given, only that segment."""
    if addr is not None:
        ea, err = validate_addr(addr)
        if err:
            return
        seg = idaapi.getseg(ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC or seg.type == idaapi.SEG_CODE):
            yield (seg.start_ea, seg.end_ea)
        return
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if (seg.perm & idaapi.SEGPERM_EXEC) or seg.type == idaapi.SEG_CODE:
            yield (seg.start_ea, seg.end_ea)


def _disasm_at(ea):
    """Get clean disassembly line at ea."""
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))


def _decode_backward(end_ea, max_insns):
    """Decode a gadget ending at end_ea (inclusive of the terminator).
    Returns list of (ea, mnemonic, disasm) or None if invalid."""
    insns = []
    # First decode the terminator itself
    length = idc.get_item_size(end_ea)
    if length == 0:
        return None
    mnem = idc.print_insn_mnem(end_ea)
    if not mnem:
        return None
    insns.append((end_ea, mnem.lower(), _disasm_at(end_ea)))

    # Walk backward to find preceding instructions
    ea = end_ea
    for _ in range(max_insns - 1):
        prev = idc.prev_head(ea)
        if prev == idaapi.BADADDR:
            break
        # Verify the previous instruction flows into ea
        next_of_prev = prev + idc.get_item_size(prev)
        if next_of_prev != ea:
            break
        pmnem = idc.print_insn_mnem(prev)
        if not pmnem:
            break
        pm = pmnem.lower()
        # Stop if we hit a control flow instruction (not useful in gadget prefix)
        if pm in ("ret", "retn", "call", "jmp", "int", "syscall", "sysenter",
                   "hlt", "ud2"):
            break
        insns.insert(0, (prev, pm, _disasm_at(prev)))
        ea = prev

    return insns if len(insns) >= 1 else None


def _format_gadget(insns):
    """Format a gadget as a dict."""
    addr = insns[0][0]
    text = " ; ".join(ins[2] for ins in insns)
    return {
        "addr": hex_ea(addr),
        "insns": len(insns),
        "gadget": text,
    }


def _matches_query(insns, query):
    """Check if any instruction matches the query pattern (regex/substring)."""
    if not query:
        return True
    import re
    try:
        pat = re.compile(query, re.IGNORECASE)
        for _, mnem, disasm in insns:
            if pat.search(mnem) or pat.search(disasm):
                return True
    except re.error:
        q = query.lower()
        for _, mnem, disasm in insns:
            if q in mnem or q in disasm.lower():
                return True
    return False


# ---- ROP gadgets ----

def _find_rop_gadgets(addr, limit, max_insns, query):
    """Find ROP gadgets (sequences ending in ret)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            is_ret = False
            if _is_x86_family(arch):
                is_ret = ml in ("ret", "retn")
            elif _is_arm_family(arch):
                # pop {pc} or bx lr
                if ml == "pop":
                    disasm = _disasm_at(ea).lower()
                    if "pc" in disasm:
                        is_ret = True
                elif ml in ("bx",):
                    disasm = _disasm_at(ea).lower()
                    if "lr" in disasm:
                        is_ret = True

            if is_ret:
                insns = _decode_backward(ea, max_insns)
                if insns and len(insns) >= 2 and _matches_query(insns, query):
                    key = tuple(ins[2] for ins in insns)
                    if key not in seen:
                        seen.add(key)
                        gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- JOP gadgets ----

def _find_jop_gadgets(addr, limit, max_insns, query):
    """Find JOP gadgets (sequences ending in indirect jmp)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            is_jop = False
            if _is_x86_family(arch):
                if ml == "jmp":
                    op_type = idc.get_operand_type(ea, 0)
                    # Indirect: register or memory
                    if op_type in (idc.o_reg, idc.o_mem, idc.o_phrase, idc.o_displ):
                        is_jop = True
            elif _is_arm_family(arch):
                if ml in ("bx", "blx", "br"):
                    disasm = _disasm_at(ea).lower()
                    # Exclude bx lr (that's ROP)
                    if "lr" not in disasm:
                        is_jop = True

            if is_jop:
                insns = _decode_backward(ea, max_insns)
                if insns and len(insns) >= 2 and _matches_query(insns, query):
                    key = tuple(ins[2] for ins in insns)
                    if key not in seen:
                        seen.add(key)
                        gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- COP gadgets ----

def _find_cop_gadgets(addr, limit, max_insns, query):
    """Find COP gadgets (sequences ending in indirect call)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            is_cop = False
            if _is_x86_family(arch):
                if ml == "call":
                    op_type = idc.get_operand_type(ea, 0)
                    if op_type in (idc.o_reg, idc.o_mem, idc.o_phrase, idc.o_displ):
                        is_cop = True
            elif _is_arm_family(arch):
                if ml in ("blx", "blr"):
                    disasm = _disasm_at(ea).lower()
                    if "lr" not in disasm:
                        is_cop = True

            if is_cop:
                insns = _decode_backward(ea, max_insns)
                if insns and len(insns) >= 2 and _matches_query(insns, query):
                    key = tuple(ins[2] for ins in insns)
                    if key not in seen:
                        seen.add(key)
                        gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- Syscall gadgets ----

def _find_syscall_gadgets(addr, limit, max_insns, query):
    """Find syscall/sysenter/svc gadgets."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            is_syscall = False
            if _is_x86_family(arch):
                if ml in ("syscall", "sysenter", "int"):
                    if ml == "int":
                        op_val = idc.get_operand_value(ea, 0)
                        if op_val in (0x80, 0x2e):
                            is_syscall = True
                    else:
                        is_syscall = True
            elif _is_arm_family(arch):
                if ml in ("svc", "swi", "hvc"):
                    is_syscall = True

            if is_syscall:
                insns = _decode_backward(ea, max_insns)
                if insns and _matches_query(insns, query):
                    key = tuple(ins[2] for ins in insns)
                    if key not in seen:
                        seen.add(key)
                        gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- Write-what-where primitives ----

def _find_write_what_where(addr, limit, max_insns, query):
    """Find write-what-where primitives (mov [reg], reg patterns)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            is_www = False
            if _is_x86_family(arch):
                # mov [reg], reg  or  mov [reg+off], reg
                if ml == "mov":
                    op0_type = idc.get_operand_type(ea, 0)
                    op1_type = idc.get_operand_type(ea, 1)
                    if op0_type in (idc.o_phrase, idc.o_displ) and op1_type == idc.o_reg:
                        is_www = True
            elif _is_arm_family(arch):
                # str reg, [reg] or str reg, [reg, #off]
                if ml in ("str", "strb", "strh", "strd"):
                    is_www = True

            if is_www:
                # Look for a ret following this to make it a usable gadget
                look_ea = ea
                found_ret = False
                for _ in range(max_insns):
                    look_ea = idc.next_head(look_ea)
                    if look_ea == idaapi.BADADDR:
                        break
                    lm = (idc.print_insn_mnem(look_ea) or "").lower()
                    if _is_x86_family(arch) and lm in ("ret", "retn"):
                        found_ret = True
                        break
                    elif _is_arm_family(arch):
                        if lm == "pop":
                            disasm = _disasm_at(look_ea).lower()
                            if "pc" in disasm:
                                found_ret = True
                                break
                        elif lm == "bx":
                            disasm = _disasm_at(look_ea).lower()
                            if "lr" in disasm:
                                found_ret = True
                                break
                    if lm in ("jmp", "call", "int", "syscall", "b", "bl"):
                        break

                if found_ret:
                    # Build gadget from www insn to ret
                    insns = []
                    cur = ea
                    while cur <= look_ea:
                        m = idc.print_insn_mnem(cur)
                        if m:
                            insns.append((cur, m.lower(), _disasm_at(cur)))
                        cur = idc.next_head(cur)
                        if cur == idaapi.BADADDR:
                            break
                    if insns and _matches_query(insns, query):
                        key = tuple(ins[2] for ins in insns)
                        if key not in seen:
                            seen.add(key)
                            gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- Stack pivot gadgets ----

def _find_stack_pivot(addr, limit, max_insns, query):
    """Find stack pivot gadgets (xchg esp/rsp, mov esp/rsp, etc.)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    sp_regs = {"esp", "rsp"} if _is_x86_family(arch) else {"sp"}

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(gadgets_found) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            ml = mnem.lower()
            disasm = _disasm_at(ea).lower()
            is_pivot = False

            if _is_x86_family(arch):
                if ml == "xchg" and any(sp in disasm for sp in sp_regs):
                    is_pivot = True
                elif ml == "mov" and any(disasm.startswith(f"mov {sp},") or
                                         disasm.startswith(f"mov {sp} ,")
                                         for sp in sp_regs):
                    is_pivot = True
                elif ml == "lea" and any(disasm.startswith(f"lea {sp},") or
                                         disasm.startswith(f"lea {sp} ,")
                                         for sp in sp_regs):
                    is_pivot = True
                elif ml == "add" and any(disasm.startswith(f"add {sp},") or
                                         disasm.startswith(f"add {sp} ,")
                                         for sp in sp_regs):
                    is_pivot = True
                elif ml == "sub" and any(disasm.startswith(f"sub {sp},") or
                                         disasm.startswith(f"sub {sp} ,")
                                         for sp in sp_regs):
                    is_pivot = True
            elif _is_arm_family(arch):
                if ml == "mov" and "sp," in disasm.replace(" ", ""):
                    # mov sp, reg
                    is_pivot = True
                elif ml in ("add", "sub") and disasm.replace(" ", "").startswith(
                        (ml + "sp,",)):
                    is_pivot = True

            if is_pivot:
                # Find a ret within max_insns
                look_ea = ea
                found_ret = False
                for _ in range(max_insns):
                    look_ea = idc.next_head(look_ea)
                    if look_ea == idaapi.BADADDR:
                        break
                    lm = (idc.print_insn_mnem(look_ea) or "").lower()
                    if _is_x86_family(arch) and lm in ("ret", "retn"):
                        found_ret = True
                        break
                    elif _is_arm_family(arch):
                        if lm == "pop" and "pc" in _disasm_at(look_ea).lower():
                            found_ret = True
                            break
                        if lm == "bx" and "lr" in _disasm_at(look_ea).lower():
                            found_ret = True
                            break
                    if lm in ("jmp", "call", "int", "syscall", "b", "bl"):
                        break

                if found_ret:
                    insns = []
                    cur = ea
                    while cur <= look_ea:
                        m = idc.print_insn_mnem(cur)
                        if m:
                            insns.append((cur, m.lower(), _disasm_at(cur)))
                        cur = idc.next_head(cur)
                        if cur == idaapi.BADADDR:
                            break
                    if insns and _matches_query(insns, query):
                        key = tuple(ins[2] for ins in insns)
                        if key not in seen:
                            seen.add(key)
                            gadgets_found.append(_format_gadget(insns))

            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return gadgets_found


# ---- Shellcode space ----

def _find_shellcode_space(addr, limit, _max_insns, _query):
    """Find writable + executable memory regions suitable for shellcode."""
    regions = []
    for seg_ea in idautils.Segments():
        if len(regions) >= limit:
            break
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if addr is not None:
            ea, err = validate_addr(addr)
            if err:
                continue
            if not (seg.start_ea <= ea < seg.end_ea):
                continue
        # Check for both write and execute permissions
        has_write = bool(seg.perm & idaapi.SEGPERM_WRITE)
        has_exec = bool(seg.perm & idaapi.SEGPERM_EXEC)
        # Fallback: check segment type
        if seg.type == idaapi.SEG_CODE:
            has_exec = True
        if has_write and has_exec:
            name = ida_segment.get_segm_name(seg) or ""
            perms = "{}{}{}".format(
                "R" if seg.perm & idaapi.SEGPERM_READ else "-",
                "W" if seg.perm & idaapi.SEGPERM_WRITE else "-",
                "X" if seg.perm & idaapi.SEGPERM_EXEC else "-",
            )
            regions.append(f"{hex_ea(seg.start_ea)}-{hex_ea(seg.end_ea)}  {name}  {perms}  size={hex_size(seg.end_ea - seg.start_ea)}")
    return regions


# ---- Mitigations ----

def _detect_mitigations(addr, _limit, _max_insns, _query):
    """Detect exploit mitigations (ASLR, DEP/NX, CFI, CET, stack cookies)."""
    mitigations = {}
    info = idaapi.get_inf_structure()
    filetype = info.filetype

    # PE mitigations
    if filetype == idaapi.f_PE:
        mitigations["format"] = "PE"
        # Try to read DllCharacteristics from PE header
        try:
            # Get PE header offset
            base = idaapi.get_imagebase()
            pe_off = ida_bytes.get_dword(base + 0x3C)
            pe_hdr = base + pe_off
            # DllCharacteristics at offset 0x5E (PE32) or 0x5E (PE32+)
            magic = ida_bytes.get_word(pe_hdr + 0x18)
            if magic == 0x20b:  # PE32+
                opt_hdr = pe_hdr + 0x18
                dll_chars = ida_bytes.get_word(opt_hdr + 0x46)
            else:  # PE32
                opt_hdr = pe_hdr + 0x18
                dll_chars = ida_bytes.get_word(opt_hdr + 0x46)
            mitigations["ASLR"] = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            mitigations["DEP/NX"] = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            mitigations["high_entropy_ASLR"] = bool(dll_chars & 0x0020)
            mitigations["force_integrity"] = bool(dll_chars & 0x0080)
            mitigations["no_SEH"] = bool(dll_chars & 0x0400)
            mitigations["guard_CF"] = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            mitigations["no_bind"] = bool(dll_chars & 0x0800)
            mitigations["CET_compat"] = bool(dll_chars & 0x2000) if dll_chars else False
        except Exception:
            mitigations["pe_parse_error"] = True

        # Stack cookies: check for __security_cookie / __stack_chk_fail
        for cookie_sym in ("__security_cookie", "__security_check_cookie",
                           "@__security_check_cookie@4", "__stack_chk_fail",
                           "__stack_chk_guard"):
            ea = idc.get_name_ea_simple(cookie_sym)
            if ea != idaapi.BADADDR:
                mitigations["stack_cookies"] = True
                mitigations["stack_cookie_symbol"] = cookie_sym
                break
        else:
            mitigations["stack_cookies"] = False

    elif filetype == idaapi.f_ELF:
        mitigations["format"] = "ELF"
        # Stack cookies
        for cookie_sym in ("__stack_chk_fail", "__stack_chk_guard",
                           "__stack_chk_fail_local"):
            ea = idc.get_name_ea_simple(cookie_sym)
            if ea != idaapi.BADADDR:
                mitigations["stack_cookies"] = True
                mitigations["stack_cookie_symbol"] = cookie_sym
                break
        else:
            mitigations["stack_cookies"] = False

        # RELRO: check for .got.plt vs .got
        got_plt = None
        got = None
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                name = ida_segment.get_segm_name(seg) or ""
                if name == ".got.plt":
                    got_plt = seg
                elif name == ".got":
                    got = seg
        if got_plt:
            if got_plt.perm & 2:  # writable
                mitigations["RELRO"] = "partial"
            else:
                mitigations["RELRO"] = "full"
        elif got:
            mitigations["RELRO"] = "full" if not (got.perm & 2) else "none"
        else:
            mitigations["RELRO"] = "unknown"

        # NX: check if any segment is both writable and executable
        has_wx = False
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg and (seg.perm & 3) == 3:  # write + exec
                has_wx = True
                break
        mitigations["NX"] = not has_wx

        # PIE: heuristic - check if image base is 0 (typical for PIE)
        base = idaapi.get_imagebase()
        mitigations["PIE"] = base == 0

        # FORTIFY: check for _chk variants
        fortified = False
        for name_ea in idautils.Names():
            n = name_ea[1]
            if "_chk" in n and any(f in n for f in ("printf", "memcpy", "strcpy",
                                                     "sprintf", "strcat")):
                fortified = True
                break
        mitigations["FORTIFY_SOURCE"] = fortified

    elif filetype == idaapi.f_MACHO:
        mitigations["format"] = "Mach-O"
        # Stack cookies
        for cookie_sym in ("___stack_chk_fail", "___stack_chk_guard"):
            ea = idc.get_name_ea_simple(cookie_sym)
            if ea != idaapi.BADADDR:
                mitigations["stack_cookies"] = True
                mitigations["stack_cookie_symbol"] = cookie_sym
                break
        else:
            mitigations["stack_cookies"] = False
        # PIE: Mach-O PIE flag
        mitigations["PIE"] = idaapi.get_imagebase() == 0x100000000 or \
                             idaapi.get_imagebase() == 0
    else:
        mitigations["format"] = "unknown"

    mitigations["arch"] = _get_arch()
    return mitigations


# ---- SEH handlers ----

def _find_seh_handlers(addr, limit, _max_insns, _query):
    """Find SEH handler chains (Windows x86)."""
    arch = _get_arch()
    if arch not in ("x86", "x64"):
        return []

    handlers = []
    # Look for typical SEH setup patterns: push handler; push fs:[0]; mov fs:[0], esp
    for seg_start, seg_end in _get_exec_segments(addr):
        if len(handlers) >= limit:
            break
        ea = seg_start
        while ea < seg_end and len(handlers) < limit:
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break
                continue
            # Look for push <handler_addr>; push dword ptr fs:[0]
            if mnem.lower() == "push":
                disasm = _disasm_at(ea).lower()
                if "fs:" in disasm and "0" in disasm:
                    # This is push fs:[0] - check previous instruction for handler
                    prev = idc.prev_head(ea)
                    if prev != idaapi.BADADDR:
                        pm = (idc.print_insn_mnem(prev) or "").lower()
                        if pm == "push":
                            handler_ea = idc.get_operand_value(prev, 0)
                            if handler_ea != idaapi.BADADDR and handler_ea != 0:
                                func = idaapi.get_func(handler_ea)
                                fname = ida_funcs.get_func_name(func.start_ea) \
                                    if func else idc.get_name(handler_ea) or ""
                                func_name = (ida_funcs.get_func_name(
                                    idaapi.get_func(ea).start_ea)
                                    if idaapi.get_func(ea) else "unknown")
                                handlers.append(f"{hex_ea(prev)}  handler={hex_ea(handler_ea)}  {fname}  in={func_name}")
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    return handlers


# ---- Pivot chains ----

def _suggest_pivot_chains(addr, limit, max_insns, query):
    """Suggest ROP chain building blocks for common operations."""
    arch = _get_arch()
    categories = {}

    # Define what we're looking for per category
    if _is_x86_family(arch):
        searches = {
            "pop_reg_ret": {"mnemonics": ["pop"], "desc": "Load register from stack"},
            "mov_reg_reg_ret": {"mnemonics": ["mov"], "desc": "Register-to-register move"},
            "xchg_ret": {"mnemonics": ["xchg"], "desc": "Register exchange"},
            "add_ret": {"mnemonics": ["add"], "desc": "Arithmetic add"},
            "sub_ret": {"mnemonics": ["sub"], "desc": "Arithmetic subtract"},
            "inc_ret": {"mnemonics": ["inc"], "desc": "Increment register"},
            "dec_ret": {"mnemonics": ["dec"], "desc": "Decrement register"},
            "xor_ret": {"mnemonics": ["xor"], "desc": "XOR (zero register or combine)"},
            "neg_ret": {"mnemonics": ["neg"], "desc": "Negate register"},
            "not_ret": {"mnemonics": ["not"], "desc": "Bitwise NOT"},
            "push_ret": {"mnemonics": ["pushad", "pusha"], "desc": "Push all registers"},
            "int80_syscall": {"mnemonics": ["int", "syscall", "sysenter"],
                              "desc": "System call"},
        }
    elif _is_arm_family(arch):
        searches = {
            "pop_reg_pc": {"mnemonics": ["pop"], "desc": "Load register + return"},
            "mov_reg_reg": {"mnemonics": ["mov"], "desc": "Register move"},
            "add_ret": {"mnemonics": ["add"], "desc": "Arithmetic add"},
            "sub_ret": {"mnemonics": ["sub"], "desc": "Arithmetic subtract"},
            "str_ret": {"mnemonics": ["str"], "desc": "Store to memory"},
            "ldr_ret": {"mnemonics": ["ldr"], "desc": "Load from memory"},
            "svc": {"mnemonics": ["svc", "swi"], "desc": "System call"},
        }
    else:
        return {}

    per_cat_limit = max(1, limit // len(searches))

    for cat_name, cat_info in searches.items():
        cat_gadgets = []
        seen = set()
        for seg_start, seg_end in _get_exec_segments(addr):
            if len(cat_gadgets) >= per_cat_limit:
                break
            ea = seg_start
            while ea < seg_end and len(cat_gadgets) < per_cat_limit:
                mnem = idc.print_insn_mnem(ea)
                if not mnem:
                    ea = idc.next_head(ea)
                    if ea == idaapi.BADADDR:
                        break
                    continue
                ml = mnem.lower()
                if ml in cat_info["mnemonics"]:
                    # Check if followed by ret within max_insns
                    look_ea = ea
                    found_ret = False
                    for _ in range(max_insns):
                        look_ea = idc.next_head(look_ea)
                        if look_ea == idaapi.BADADDR:
                            break
                        lm = (idc.print_insn_mnem(look_ea) or "").lower()
                        if _is_x86_family(arch) and lm in ("ret", "retn"):
                            found_ret = True
                            break
                        elif _is_arm_family(arch):
                            if lm == "pop" and "pc" in _disasm_at(look_ea).lower():
                                found_ret = True
                                break
                            if lm == "bx" and "lr" in _disasm_at(look_ea).lower():
                                found_ret = True
                                break
                        if lm in ("jmp", "call", "int", "b", "bl"):
                            break

                    if found_ret or ml in ("syscall", "sysenter", "int", "svc", "swi"):
                        end = look_ea if found_ret else ea
                        insns = []
                        cur = ea
                        target = end
                        while cur <= target:
                            m = idc.print_insn_mnem(cur)
                            if m:
                                insns.append((cur, m.lower(), _disasm_at(cur)))
                            cur = idc.next_head(cur)
                            if cur == idaapi.BADADDR:
                                break
                        if insns and _matches_query(insns, query):
                            key = tuple(ins[2] for ins in insns)
                            if key not in seen:
                                seen.add(key)
                                cat_gadgets.append(_format_gadget(insns))

                ea = idc.next_head(ea)
                if ea == idaapi.BADADDR:
                    break

        if cat_gadgets:
            categories[cat_name] = {
                "description": cat_info["desc"],
                "count": len(cat_gadgets),
                "gadgets": cat_gadgets,
            }

    return categories


# ============================================================================
# Action dispatch
# ============================================================================

_ACTIONS = {
    "rop": _find_rop_gadgets,
    "jop": _find_jop_gadgets,
    "cop": _find_cop_gadgets,
    "syscall": _find_syscall_gadgets,
    "write_what_where": _find_write_what_where,
    "stack_pivot": _find_stack_pivot,
}


@tool
@idaread
def gadgets(
    action: Annotated[Literal["rop", "jop", "cop", "syscall", "write_what_where",
                               "stack_pivot", "shellcode_space", "mitigations",
                               "seh_handlers", "pivot_chains"],
                      "Gadget/exploit primitive action"],
    addr: Annotated[Optional[str], "Segment or address to search in"] = None,
    limit: Annotated[int, "Max gadgets to return"] = 50,
    max_insns: Annotated[int, "Max instructions per gadget"] = 5,
    query: Annotated[Optional[str], "Filter gadgets by mnemonic pattern (regex supported)"] = None,
) -> dict:
    """
    LLM-optimized ROP/JOP/COP gadget and exploit primitive discovery.

    Actions:
    - rop: Find ROP gadgets (instruction sequences ending in ret/pop pc/bx lr)
    - jop: Find JOP gadgets (sequences ending in indirect jmp/bx reg)
    - cop: Find COP gadgets (sequences ending in indirect call/blx reg)
    - syscall: Find syscall/sysenter/svc gadgets
    - write_what_where: Find write-what-where primitives (mov [reg], reg / str reg, [reg])
    - stack_pivot: Find stack pivot gadgets (xchg rsp, mov rsp / mov sp, reg)
    - shellcode_space: Find writable+executable memory regions for shellcode
    - mitigations: Detect exploit mitigations (ASLR, DEP/NX, CFI, CET, stack cookies)
    - seh_handlers: Find SEH handler chains (Windows x86)
    - pivot_chains: Suggest ROP chain building blocks for common operations

    Architecture-aware: supports x86/x64 and ARM/AArch64.
    Each gadget: {addr, insns, gadget}
    """
    try:
        if action == "shellcode_space":
            regions = _find_shellcode_space(addr, limit, max_insns, query)
            return {
                "ok": True,
                "action": "shellcode_space",
                "regions": "\n".join(regions),
                "count": len(regions),
                "arch": _get_arch(),
            }

        if action == "mitigations":
            mits = _detect_mitigations(addr, limit, max_insns, query)
            return {
                "ok": True,
                "action": "mitigations",
                "mitigations": mits,
            }

        if action == "seh_handlers":
            handlers = _find_seh_handlers(addr, limit, max_insns, query)
            return {
                "ok": True,
                "action": "seh_handlers",
                "handlers": "\n".join(handlers),
                "count": len(handlers),
                "arch": _get_arch(),
            }

        if action == "pivot_chains":
            chains = _suggest_pivot_chains(addr, limit, max_insns, query)
            total = sum(c["count"] for c in chains.values()) if chains else 0
            return {
                "ok": True,
                "action": "pivot_chains",
                "categories": chains,
                "total_gadgets": total,
                "arch": _get_arch(),
            }

        handler = _ACTIONS.get(action)
        if not handler:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        results = handler(addr, limit, max_insns, query)
        return {
            "ok": True,
            "action": action,
            "gadgets": results[:limit],
            "count": len(results),
            "truncated": len(results) >= limit,
            "arch": _get_arch(),
        }

    except Exception as e:
        return handle_error(e)
