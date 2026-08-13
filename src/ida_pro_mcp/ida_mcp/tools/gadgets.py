
from ._common import (
    Annotated,
    CALL_MNEMONICS,
    Literal,
    MCPError,
    Optional,
    SYSCALL_MNEMONICS,
    TERMINATOR_MNEMONICS,
    UNCONDITIONAL_JUMP_MNEMONICS,
    _inf_filetype_id,
    compile_smart_pattern,
    get_arch,
    get_stack_pointer_names,
    handle_error,
    hex_ea,
    hex_size,
    ida_bytes,
    ida_funcs,
    ida_lines,
    idaapi,
    idaread,
    idautils,
    idc,
    is_arm_family,
    is_mips_family,
    is_ppc_family,
    is_return_mnemonic,
    is_riscv_family,
    is_sparc_family,
    is_x86_family,
    make_error,
    public_arg,
    run_action,
    tool,
    validate_addr
)

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from .. import compat as _compat

from collections import OrderedDict
from functools import partial

# RISC-V register-operand parsing is owned by support/arch_utils (the canonical
# classifier for jalr/c.jr/c.jalr); import it directly so gadgets never keeps a
# divergent jalr parser.  `is_return_mnemonic` (from _common) already routes the
# return side of every RISC-V register-indirect branch through the same helper.
from ..support.arch_utils import (
        _riscv_operand_parts,
        _riscv_reg_name,
    )

# ============================================================================
# GADGETS - ROP/JOP/COP Gadget & Exploit Primitive Discovery
# ============================================================================

# Architecture detection uses shared arch_utils via _common.
# Local aliases kept for backward compatibility with internal callers.
_get_arch = get_arch
_is_x86_family = is_x86_family
_is_arm_family = is_arm_family


def _get_exec_segments(addr):
    """Yield (start, end) for executable segments. If addr given, only that segment."""
    if addr is not None:
        ea, err = validate_addr(addr)
        if err:
            return
        seg = _compat.get_segment(ea)
        if seg and ((_compat.get_segment_perm(ea) & idaapi.SEGPERM_EXEC)
                    or _compat.get_segment_type(ea) == idaapi.SEG_CODE):
            yield (seg.start_ea, seg.end_ea)
        return
    for seg_ea in idautils.Segments():
        seg = _compat.get_segment(seg_ea)
        if not seg:
            continue
        if (_compat.get_segment_perm(seg_ea) & idaapi.SEGPERM_EXEC) or _compat.get_segment_type(seg_ea) == idaapi.SEG_CODE:
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
        if pm in TERMINATOR_MNEMONICS or pm in CALL_MNEMONICS or pm in SYSCALL_MNEMONICS:
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


# Keep a small LRU cache so repeated gadget filters don't recompile patterns.
_QUERY_MATCHER_CACHE = OrderedDict()
_MAX_MATCHER_CACHE_SIZE = 64


def _matches_query(insns, query):
    """Check if any instruction matches query (regex/glob/substring/semantic auto-detected)."""
    if not query:
        return True
    matcher = _QUERY_MATCHER_CACHE.get(query)
    if matcher is None:
        matcher = compile_smart_pattern(query, case_sensitive=False)
        _QUERY_MATCHER_CACHE[query] = matcher
        if len(_QUERY_MATCHER_CACHE) > _MAX_MATCHER_CACHE_SIZE:
            _QUERY_MATCHER_CACHE.popitem(last=False)
    else:
        _QUERY_MATCHER_CACHE.move_to_end(query)
    return any(matcher(mnem) or matcher(disasm) for _, mnem, disasm in insns)


# ---- RISC-V register-indirect branch classification ----
# RISC-V `jalr rd, imm(rs1)` is overloaded: rd=ra links a return address
# (indirect call), rd=x0 with rs1=ra returns, rd=x0 with rs1!=ra jumps.
# The compressed forms follow the same ABI: `c.jr rs1` is a return only when
# rs1=ra (otherwise a JOP jump), and `c.jalr rs1` always links to ra (a call).
# IDA renders the call form (`jalr ra, 0(t0)`) and the return form
# (`jalr zero, 0(ra)`) with "ra" present, so a bare substring check inverts
# the COP/ROP classification.  Classification is routed through the shared
# arch_utils classifier (is_return_mnemonic + _riscv_operand_parts) so the
# compressed terminators appear in JOP/COP and ROP is not polluted with
# calls/stack-saves.

_RISCV_FP_REGISTERS = frozenset({"fp", "s0", "x8"})


def _riscv_branch_kind(mnem_lower, disasm_lower, arch=None):
    """Three-way classify a RISC-V register-indirect branch.

      jalr   rd == x0/zero AND rs1 == ra  -> "return"  (ROP terminator)
             rd == ra/x1                   -> "call"    (COP terminator)
             otherwise                     -> "jump"    (JOP terminator)
      c.jr   rs1 == ra                     -> "return"  (ROP terminator)
             otherwise                     -> "jump"    (JOP terminator)
      c.jalr                               -> "call"    (COP terminator,
                                                         always links ra)
    Returns "other" for non-register-indirect mnemonics.  An unparseable jalr
    defaults to "call" so a mis-parsed terminator is never silently dropped
    from the COP results.
    """
    if arch is None:
        arch = _get_arch()
    mnem = (mnem_lower or "").lower()
    disasm = disasm_lower or ""
    if mnem == "c.jalr":
        return "call"
    if mnem == "c.jr":
        return "return" if is_return_mnemonic(mnem, disasm, arch) else "jump"
    if mnem == "jalr":
        if is_return_mnemonic(mnem, disasm, arch):
            return "return"
        if _riscv_operand_parts is None or _riscv_reg_name is None:
            return "call"
        parts = _riscv_operand_parts(disasm, mnem)
        if not parts:
            return "call"
        if _riscv_reg_name(parts[0]) == "x1":
            return "call"
        return "jump"
    return "other"


def _riscv_store_base(disasm_lower, mnem):
    """Extract the xN-normalized base register of a RISC-V store's memory
    operand (e.g. ``sw s0, 8(sp)`` -> ``x2``), or None when not parseable."""
    if _riscv_operand_parts is None:
        return None
    parts = _riscv_operand_parts(disasm_lower or "", mnem or "")
    for part in parts[1:]:
        if "(" in part:
            inner = part[part.find("(") + 1:part.find(")")]
            if _riscv_reg_name is not None:
                return _riscv_reg_name(inner)
            return inner
    return None


# ============================================================================
# Shared terminator classification + byte-level linear sweep
# ============================================================================
#
# Every finder below can run two ways:
#   * a head-based scan over IDA-defined instructions (the classic path), and
#   * a byte-level linear sweep that raw-decodes from EVERY offset in the exec
#     region via ida_ua, used for opaque blobs IDA never disassembled (or when
#     the caller opts in with raw=True).
# Both paths share the same per-action terminator predicates so the two modes
# cannot drift apart.

def _is_ret_terminator(ea, ml, disasm, arch):
    """Return mnemonic (ROP gadget terminator) for the current arch."""
    return is_return_mnemonic(ml, disasm, arch)


def _is_jop_terminator(ea, ml, disasm, arch):
    """Indirect-jump mnemonic (JOP gadget terminator) for the current arch."""
    if _is_x86_family(arch):
        if ml == "jmp":
            op_type = idc.get_operand_type(ea, 0)
            return op_type in (idc.o_reg, idc.o_mem, idc.o_phrase, idc.o_displ)
        return False
    if _is_arm_family(arch):
        if ml in ("bx", "blx", "br"):
            return "lr" not in disasm
        return False
    if is_mips_family(arch):
        if ml == "jr":
            return "ra" not in disasm and "$31" not in disasm
        return False
    if is_riscv_family(arch):
        if ml in ("jalr", "c.jr", "c.jalr"):
            return _riscv_branch_kind(ml, disasm, arch) == "jump"
        return False
    if is_ppc_family(arch):
        return ml == "bctr"
    return False


def _is_cop_terminator(ea, ml, disasm, arch):
    """Indirect-call mnemonic (COP gadget terminator) for the current arch."""
    if _is_x86_family(arch):
        if ml == "call":
            op_type = idc.get_operand_type(ea, 0)
            return op_type in (idc.o_reg, idc.o_mem, idc.o_phrase, idc.o_displ)
        return False
    if _is_arm_family(arch):
        if ml in ("blx", "blr"):
            return "lr" not in disasm
        return False
    if is_mips_family(arch):
        return ml == "jalr"
    if is_riscv_family(arch):
        if ml in ("jalr", "c.jr", "c.jalr"):
            return _riscv_branch_kind(ml, disasm, arch) == "call"
        return False
    if is_ppc_family(arch):
        return ml == "bctrl"
    return False


def _is_syscall_terminator(ea, ml, disasm, arch):
    """Syscall/trap mnemonic for the current arch."""
    if _is_x86_family(arch):
        if ml in ("syscall", "sysenter"):
            return True
        if ml == "int":
            op_val = idc.get_operand_value(ea, 0)
            return op_val in (0x80, 0x2e)
        return False
    if _is_arm_family(arch):
        return ml in ("svc", "swi", "hvc", "smc")
    if is_mips_family(arch):
        return ml == "syscall"
    if is_ppc_family(arch):
        return ml == "sc"
    if is_riscv_family(arch):
        return ml == "ecall"
    if is_sparc_family(arch):
        return ml == "ta"
    return False


def _sweep_stop_set():
    """Terminator + syscall mnemonics: instructions with no fall-through that
    can legitimately end a gadget stream.  Built lazily so a bare module load
    without the arch_utils mnemonics still imports cleanly."""
    try:
        return frozenset(TERMINATOR_MNEMONICS) | frozenset(SYSCALL_MNEMONICS)
    except NameError:
        return frozenset()


def _prepare_exec_region(seg_start, seg_end):
    """Best-effort, non-blocking: ask IDA to create code / plan reanalysis over
    an exec region before a head-based scan, so a region IDA never
    auto-disassembled has a chance to gain heads.  Never raises.  Returns True
    when some analysis was scheduled."""
    try:
        import ida_auto as _ida_auto
    except ImportError:
        return False
    try:
        if hasattr(_ida_auto, "plan_range"):
            _ida_auto.plan_range(seg_start, seg_end)
            return True
        if hasattr(_ida_auto, "auto_mark_range"):
            _ida_auto.auto_mark_range(seg_start, seg_end,
                                      getattr(_ida_auto, "AU_FINAL", 0x10))
            return True
        if hasattr(_ida_auto, "auto_make_code"):
            _ida_auto.auto_make_code(seg_start)
            return True
    except Exception:
        pass
    return False


def _region_has_heads(seg_start, seg_end):
    """True when [seg_start, seg_end) contains at least one defined instruction
    head — i.e. IDA actually disassembled something there.

    Probes from seg_start - 1 because idaapi.next_head returns the first head
    with address >= the query; a head exactly at seg_start must count.
    """
    try:
        head = idc.next_head(seg_start - 1)
        return head != idaapi.BADADDR and head < seg_end
    except Exception:
        return False


def _exec_region_has_heads(addr):
    """True when any exec segment targeted by addr has defined instruction heads."""
    for seg_start, seg_end in _get_exec_segments(addr):
        if _region_has_heads(seg_start, seg_end):
            return True
    return False


def _raw_decode_insn(ea):
    """Raw-decode a single instruction at ea via ida_ua (byte-level decode,
    independent of whether IDA created a head there).

    Returns (ea, mnem_lower, disasm, size) or None when the bytes at ea do not
    form a valid instruction.
    """
    try:
        import ida_ua as _ida_ua
    except ImportError:
        return None
    try:
        insn = _ida_ua.insn_t()
        if _ida_ua.decode_insn(insn, ea) <= 0:
            return None
        mnem = insn.get_canon_mnem()
        if not mnem:
            return None
        size = int(getattr(insn, "size", 0) or 0)
        if size <= 0:
            return None
        disasm = _disasm_at(ea) or mnem
        return (ea, mnem.lower(), disasm, size)
    except Exception:
        return None


def _scan_region_terminators(seg_start, seg_end, limit, max_insns, query,
                             arch, term_test, seen, min_insns=2):
    """Head-based scan: walk defined instructions and collect gadgets whose
    terminal instruction satisfies term_test(ea, mnem, disasm)."""
    out = []
    ea = seg_start
    while ea < seg_end and len(out) < limit:
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break
            continue
        ml = mnem.lower()
        disasm = _disasm_at(ea).lower()
        if term_test(ea, ml, disasm):
            insns = _decode_backward(ea, max_insns)
            if insns and len(insns) >= min_insns and _matches_query(insns, query):
                key = tuple(ins[2] for ins in insns)
                if key not in seen:
                    seen.add(key)
                    out.append(_format_gadget(insns))
        ea = idc.next_head(ea)
        if ea == idaapi.BADADDR:
            break
    return out


def _sweep_region_terminators(seg_start, seg_end, limit, max_insns, query,
                              arch, term_test, seen, min_insns=2):
    """Byte-level linear sweep: decode from every offset in [seg_start, seg_end)
    via raw decode (ida_ua, not IDA heads) and collect streams whose terminal
    instruction satisfies term_test(ea, mnem, disasm).  Handles opaque regions
    IDA never disassembled."""
    out = []
    stop = _sweep_stop_set()
    ea = seg_start
    while ea < seg_end and len(out) < limit:
        dec = _raw_decode_insn(ea)
        if dec is None:
            ea += 1
            continue
        _s_ea, mnem, disasm, size = dec
        stream = [(ea, mnem, disasm)]
        if mnem not in stop:
            cur = ea + size
            while len(stream) < max_insns and cur < seg_end:
                dec2 = _raw_decode_insn(cur)
                if dec2 is None:
                    break
                _e2, m2, d2, s2 = dec2
                stream.append((cur, m2, d2))
                cur += s2
                if m2 in stop:
                    break
        if len(stream) >= min_insns and term_test(stream[-1][0], stream[-1][1], stream[-1][2].lower()):
            if _matches_query(stream, query):
                key = tuple(ins[2] for ins in stream)
                if key not in seen:
                    seen.add(key)
                    out.append(_format_gadget(stream))
        ea += 1
    return out


def _region_results(seg_start, seg_end, limit, max_insns, query, arch,
                    term_test, seen, raw, min_insns=2):
    """Run either the head-based scan or the raw linear sweep for one exec
    region, preferring the sweep when raw is set or the region has no heads."""
    _prepare_exec_region(seg_start, seg_end)
    if raw or not _region_has_heads(seg_start, seg_end):
        return _sweep_region_terminators(seg_start, seg_end, limit, max_insns,
                                         query, arch, term_test, seen, min_insns)
    return _scan_region_terminators(seg_start, seg_end, limit, max_insns,
                                    query, arch, term_test, seen, min_insns)


# ---- ROP gadgets ----

def _find_rop_gadgets(addr, limit, max_insns, query, raw=False):
    """Find ROP gadgets (sequences ending in ret / jalr-return / c.jr-return).

    RISC-V register-indirect branches (jalr/c.jr/c.jalr) are classified through
    the shared arch_utils classifier, so calls and jumps never leak into ROP.
    """
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    term_test = partial(_is_ret_terminator, arch=arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        gadgets_found.extend(_region_results(
            seg_start, seg_end, limit - len(gadgets_found), max_insns, query,
            arch, term_test, seen, raw))

    return gadgets_found


# ---- JOP gadgets ----

def _find_jop_gadgets(addr, limit, max_insns, query, raw=False):
    """Find JOP gadgets (sequences ending in indirect jmp / bx reg / jr reg /
    bctr / jalr-jump / c.jr rs1!=ra).

    Compressed RISC-V terminators (c.jr with rs1!=ra) are classified through the
    shared arch_utils classifier and now appear in JOP; the c.jalr call form is
    excluded (it belongs to COP).
    """
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    term_test = partial(_is_jop_terminator, arch=arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        gadgets_found.extend(_region_results(
            seg_start, seg_end, limit - len(gadgets_found), max_insns, query,
            arch, term_test, seen, raw))

    return gadgets_found


# ---- COP gadgets ----

def _find_cop_gadgets(addr, limit, max_insns, query, raw=False):
    """Find COP gadgets (sequences ending in indirect call / blx reg / jalr-call /
    c.jalr).

    Compressed RISC-V terminators (c.jalr, and jalr with rd=ra) are classified
    through the shared arch_utils classifier; plain jumps and returns never
    appear in COP.
    """
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    term_test = partial(_is_cop_terminator, arch=arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        gadgets_found.extend(_region_results(
            seg_start, seg_end, limit - len(gadgets_found), max_insns, query,
            arch, term_test, seen, raw))

    return gadgets_found


# ---- Syscall gadgets ----

def _find_syscall_gadgets(addr, limit, max_insns, query, raw=False):
    """Find syscall/sysenter/svc/ecall/sc gadgets."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    term_test = partial(_is_syscall_terminator, arch=arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        gadgets_found.extend(_region_results(
            seg_start, seg_end, limit - len(gadgets_found), max_insns, query,
            arch, term_test, seen, raw, min_insns=1))

    return gadgets_found


# ---- Write-what-where primitives ----

def _find_write_what_where(addr, limit, max_insns, query, raw=False):
    """Find write-what-where primitives (mov [reg], reg patterns).

    RISC-V stores are narrowed to those whose base register is not the stack or
    frame pointer (a pointer loaded from memory or a register argument), matching
    the x86 operand-shape check — ordinary ``sw s0, 8(sp); ret`` frame saves are
    not write-what-where primitives.
    """
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    sp_regs = get_stack_pointer_names(arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        _prepare_exec_region(seg_start, seg_end)
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
            elif is_mips_family(arch):
                if ml in ("sw", "sh", "sb", "sd"):
                    is_www = True
            elif is_ppc_family(arch):
                if ml in ("stw", "sth", "stb", "std", "stwx", "stdx"):
                    is_www = True
            elif is_riscv_family(arch) and ml in ("sw", "sh", "sb", "sd"):
                # Narrow to stores through a non-sp/non-fp base register
                # (pointer loaded from memory or a register argument).
                disasm = _disasm_at(ea).lower()
                base = _riscv_store_base(disasm, ml)
                if base is not None and base not in sp_regs and base not in _RISCV_FP_REGISTERS:
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
                    if is_return_mnemonic(lm, _disasm_at(look_ea).lower(), arch):
                        found_ret = True
                        break
                    if lm in CALL_MNEMONICS or lm in UNCONDITIONAL_JUMP_MNEMONICS or lm in SYSCALL_MNEMONICS:
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

def _find_stack_pivot(addr, limit, max_insns, query, raw=False):
    """Find stack pivot gadgets (xchg esp/rsp, mov esp/rsp, etc.)."""
    arch = _get_arch()
    gadgets_found = []
    seen = set()
    sp_regs = get_stack_pointer_names(arch)

    for seg_start, seg_end in _get_exec_segments(addr):
        if len(gadgets_found) >= limit:
            break
        _prepare_exec_region(seg_start, seg_end)
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

            # Generic: check if any SP register name appears as a destination
            # in mov/xchg/add/sub/lea instructions
            if ml in ("xchg",) and any(sp in disasm for sp in sp_regs):
                is_pivot = True
            elif ml == "leave":
                # leave == mov esp/rsp, ebp/rbp; pop ebp — the canonical
                # frame-pointer restore is also a valid stack pivot.
                is_pivot = True
            elif ml == "pop":
                # pop rsp/esp loads the new stack pointer from the old one.
                disasm_nospace = disasm.replace(" ", "")
                if any(disasm_nospace.startswith(f"pop{sp}") for sp in sp_regs):
                    is_pivot = True
            elif ml in ("mov", "lea", "add", "sub", "addi", "addiu", "daddiu"):
                disasm_nospace = disasm.replace(" ", "")
                for sp in sp_regs:
                    # Check SP as the first (destination) operand only
                    if disasm_nospace.startswith(f"{ml}{sp},"):
                        is_pivot = True
                        break

            if is_pivot:
                # Find a ret within max_insns
                look_ea = ea
                found_ret = False
                for _ in range(max_insns):
                    look_ea = idc.next_head(look_ea)
                    if look_ea == idaapi.BADADDR:
                        break
                    lm = (idc.print_insn_mnem(look_ea) or "").lower()
                    if is_return_mnemonic(lm, _disasm_at(look_ea).lower(), arch):
                        found_ret = True
                        break
                    if lm in CALL_MNEMONICS or lm in UNCONDITIONAL_JUMP_MNEMONICS or lm in SYSCALL_MNEMONICS:
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
        seg = _compat.get_segment(seg_ea)
        if not seg:
            continue
        if addr is not None:
            ea, err = validate_addr(addr)
            if err:
                continue
            if not (seg.start_ea <= ea < seg.end_ea):
                continue
        # Check for both write and execute permissions
        perm = _compat.get_segment_perm(seg_ea)
        has_write = bool(perm & idaapi.SEGPERM_WRITE)
        has_exec = bool(perm & idaapi.SEGPERM_EXEC)
        # Fallback: check segment type
        if _compat.get_segment_type(seg_ea) == idaapi.SEG_CODE:
            has_exec = True
        if has_write and has_exec:
            name = _compat.get_segment_name(seg_ea) or ""
            perms = "{}{}{}".format(
                "R" if perm & idaapi.SEGPERM_READ else "-",
                "W" if perm & idaapi.SEGPERM_WRITE else "-",
                "X" if perm & idaapi.SEGPERM_EXEC else "-",
            )
            regions.append(f"{hex_ea(seg.start_ea)}-{hex_ea(seg.end_ea)}  {name}  {perms}  size={hex_size(seg.end_ea - seg.start_ea)}")
    return regions


# ---- Mitigations ----

def _detect_mitigations(addr, _limit, _max_insns, _query):
    """Detect exploit mitigations (ASLR, DEP/NX, CFI, CET, stack cookies)."""
    mitigations = {}
    filetype = _inf_filetype_id()

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
            if _compat.get_segment(seg_ea):
                name = _compat.get_segment_name(seg_ea) or ""
                if name == ".got.plt":
                    got_plt = seg_ea
                elif name == ".got":
                    got = seg_ea
        if got_plt is not None:
            if (_compat.get_segment_perm(got_plt) or 0) & 2:  # writable
                mitigations["RELRO"] = "partial"
            else:
                mitigations["RELRO"] = "full"
        elif got is not None:
            mitigations["RELRO"] = "full" if not ((_compat.get_segment_perm(got) or 0) & 2) else "none"
        else:
            mitigations["RELRO"] = "unknown"

        # NX: check if any segment is both writable and executable
        has_wx = False
        wx_mask = idaapi.SEGPERM_WRITE | idaapi.SEGPERM_EXEC
        for seg_ea in idautils.Segments():
            perm = _compat.get_segment_perm(seg_ea)
            if perm is not None and (perm & wx_mask) == wx_mask:
                has_wx = True
                break
        mitigations["NX"] = not has_wx

        # PIE: heuristic - check if image base is 0 (typical for PIE)
        base = idaapi.get_imagebase()
        mitigations["PIE"] = base == 0

        # FORTIFY: check for _chk variants
        fortified = False
        _names_scanned = 0
        _MAX_NAMES_SCAN = 50000
        for name_ea in idautils.Names():
            n = name_ea[1]
            if "_chk" in n and any(f in n for f in ("printf", "memcpy", "strcpy",
                                                      "sprintf", "strcat")):
                fortified = True
                break
            _names_scanned += 1
            if _names_scanned >= _MAX_NAMES_SCAN:
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
                            if handler_ea not in (idaapi.BADADDR, 0):
                                handler_start = _compat.get_func_start(handler_ea)
                                fname = ida_funcs.get_func_name(handler_start) \
                                    if handler_start is not None else idc.get_name(handler_ea) or ""
                                in_start = _compat.get_func_start(ea)
                                func_name = (ida_funcs.get_func_name(in_start)
                                    if in_start is not None else "unknown")
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
    elif is_mips_family(arch):
        searches = {
            "lw_jr": {"mnemonics": ["lw"], "desc": "Load word (reg restore)"},
            "move_jr": {"mnemonics": ["move"], "desc": "Register move"},
            "add_jr": {"mnemonics": ["addu", "addiu"], "desc": "Arithmetic add"},
            "sw_jr": {"mnemonics": ["sw"], "desc": "Store to memory"},
            "syscall": {"mnemonics": ["syscall"], "desc": "System call"},
        }
    elif is_ppc_family(arch):
        searches = {
            "lwz_blr": {"mnemonics": ["lwz", "ld"], "desc": "Load word (reg restore)"},
            "mr_blr": {"mnemonics": ["mr"], "desc": "Register move"},
            "add_blr": {"mnemonics": ["add", "addi"], "desc": "Arithmetic add"},
            "stw_blr": {"mnemonics": ["stw", "std"], "desc": "Store to memory"},
            "sc": {"mnemonics": ["sc"], "desc": "System call"},
        }
    elif is_riscv_family(arch):
        searches = {
            "lw_ret": {"mnemonics": ["lw", "ld"], "desc": "Load word (reg restore)"},
            "mv_ret": {"mnemonics": ["mv"], "desc": "Register move"},
            "add_ret": {"mnemonics": ["add", "addi"], "desc": "Arithmetic add"},
            "sw_ret": {"mnemonics": ["sw", "sd"], "desc": "Store to memory"},
            "ecall": {"mnemonics": ["ecall"], "desc": "System call"},
        }
    else:
        # Generic fallback for unknown architectures
        searches = {
            "mov_ret": {"mnemonics": ["mov"], "desc": "Register move"},
            "add_ret": {"mnemonics": ["add"], "desc": "Arithmetic add"},
        }

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
                        if is_return_mnemonic(lm, _disasm_at(look_ea).lower(), arch):
                            found_ret = True
                            break
                        if lm in CALL_MNEMONICS or lm in UNCONDITIONAL_JUMP_MNEMONICS:
                            break

                    if found_ret or ml in SYSCALL_MNEMONICS:
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
                               "seh_handlers", "pivot_chains", "classify_chain",
                               "semantic_find"],
                      "Gadget/exploit primitive action"],
    addr: Annotated[Optional[str], "Segment or address to search in"] = None,
    limit: Annotated[int, "Max gadgets to return"] = 50,
    max_insns: Annotated[int, "Max instructions per gadget"] = 5,
    query: Annotated[Optional[str], "Filter gadgets by mnemonic pattern (regex/glob/substring/semantic auto-detected)"] = None,
    raw: Annotated[bool, "Force a byte-level linear sweep: raw-decode from every offset in the exec region even when IDA has disassembled heads (auto-enabled when the region has no defined instruction heads)"] = False,
    auto_blackboard: Annotated[bool, "Store mitigation/exploit findings in the blackboard (opt-in; default keeps read actions pure)"] = False,
    **kwargs,
) -> dict:
    """
    LLM-optimized ROP/JOP/COP gadget and exploit primitive discovery.

    Actions:
    - rop: Find ROP gadgets (instruction sequences ending in ret/pop pc/bx lr/jr ra/blr/jalr-return/c.jr ra)
    - jop: Find JOP gadgets (sequences ending in indirect jmp/bx reg/jr reg/bctr/jalr-jump/c.jr rs1!=ra)
    - cop: Find COP gadgets (sequences ending in indirect call/blx reg/jalr-call/c.jalr/bctrl)
    - syscall: Find syscall/sysenter/svc/ecall/sc gadgets
    - write_what_where: Find write-what-where primitives (mov [reg], reg / str reg, [reg])
    - stack_pivot: Find stack pivot gadgets (xchg rsp, mov rsp / mov sp, reg)
    - shellcode_space: Find writable+executable memory regions for shellcode
    - mitigations: Detect exploit mitigations (ASLR, DEP/NX, CFI, CET, stack cookies)
    - seh_handlers: Find SEH handler chains (Windows x86)
    - pivot_chains: Suggest ROP chain building blocks for common operations

    Opaque-region handling: when the exec region has no defined instruction heads
    (a raw blob IDA never disassembled) — or when raw=True is set — rop/jop/cop/
    syscall fall back to a byte-level linear sweep that raw-decodes from every
    offset.  plan_range/auto_make_code is attempted over the segment first, and a
    "region was never disassembled" note is returned when the sweep finds nothing.

    Architecture-aware: supports x86/x64, ARM/AArch64, MIPS, PowerPC, RISC-V, SPARC, and more.
    Each gadget: {addr, insns, gadget}
    """
    try:
        # Public MCP names stay on the wire; accept them beside legacy aliases.
        addr = public_arg(kwargs, 'address', addr)
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
            # Auto-write missing mitigations to blackboard — opt-in only.
            # This is a read-classified operation, so it must not persist
            # findings without an explicit auto_blackboard=True.
            if isinstance(mits, dict):
                missing = [k for k, v in mits.items() if v is False]
                if missing and auto_blackboard:
                    try:
                        from blackboard import BlackboardStore  # type: ignore
                        import time as _time
                        store = BlackboardStore()
                        existing = store.list(category="mitigation_gap", limit=50)
                        if not any("mitigation" in (e.get("title", "").lower()) for e in existing):
                            store.write(
                                title=f"Missing mitigations: {', '.join(missing[:5])}",
                                content=f"Binary lacks: {', '.join(missing)}",
                                category="mitigation_gap",
                                tags=["mitigation"] + missing[:5],
                                confidence=0.9,
                                source="gadgets",
                                source_type="engine_gadgets",
                                evidence=[{
                                    "type": "mitigation_scan",
                                    "value": f"missing: {','.join(missing)}",
                                    "weight": 0.9,
                                    "ts": _time.time(),
                                }],
                            )
                    except Exception:
                        pass
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

        if action == "classify_chain":
            # Semantic exploit primitive classification using BehaviorClassifier.
            # Takes a list of gadget strings (or addresses) and classifies the chain's
            # exploit potential: stack_pivot, write_what_where, code_exec, rop_chain, etc.
            return _classify_gadget_chain(addr, limit, max_insns, query, auto_blackboard)

        if action == "semantic_find":
            # Host-intercepted action (server_dispatch routes it to the host's
            # per-session semantic index before this RPC is reached). The value is
            # admitted by the action Literal for registry contract consistency, but
            # the IDA runtime has no standalone implementation.
            return make_error(
                MCPError.INVALID_ARGS,
                "semantic_find is a host-intercepted gadgets action — route it through "
                "the MCP host (it is served by the host-side semantic index, not the "
                "IDA runtime).",
            )

        handler = _ACTIONS.get(action)
        if not handler:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        # Opaque-region handling: when the exec region has no defined instruction
        # heads (a raw blob IDA never disassembled), or when the caller opts in
        # with raw=True, the terminator finders fall back to a byte-level linear
        # sweep that raw-decodes from every offset.
        region_had_heads = _exec_region_has_heads(addr)
        used_raw = bool(raw) or not region_had_heads
        results = handler(addr, limit, max_insns, query, raw=used_raw)

        # Augment with BehaviorClassifier scoring when available
        behavior_score = _score_gadgets_behavior(results, action)

        resp = {
            "ok": True,
            "action": action,
            "gadgets": results[:limit],
            "count": len(results),
            "truncated": len(results) >= limit,
            "arch": _get_arch(),
            **({"exploit_potential": behavior_score} if behavior_score else {}),
        }
        # Surface the opaque-region reality instead of letting an empty result
        # read as "no gadgets exist in this binary".
        if not results and used_raw:
            if region_had_heads:
                resp["note"] = (
                    "raw=True forced a byte-level linear sweep over the exec "
                    "region; no qualifying gadget terminators were found."
                )
            else:
                resp["note"] = (
                    "Region was never disassembled — no defined instruction heads "
                    "in the exec region; ran a byte-level linear sweep and found "
                    "no qualifying gadget terminators."
                )
        return resp

    except Exception as e:
        return handle_error(e)


def _score_gadgets_behavior(gadgets: list, action: str) -> Optional[dict]:
    """
    Use BehaviorClassifier to score the exploit potential of a gadget set.
    Builds a pseudo-pseudocode description of what the gadgets collectively do,
    then classifies it against exploit-relevant anchors.
    """
    if not gadgets:
        return None
    try:
        from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
    except ImportError:
        try:
            from host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder  # type: ignore
        except ImportError:
            return None
    try:
        # Build a compact description of the gadget set for embedding
        insn_text = " ".join(
            g.get("gadget") or g.get("insns") or ""
            for g in gadgets[:20]
        )
        if not insn_text.strip():
            return None

        # Exploit-specific anchors not in the default BehaviorClassifier
        _EXPLOIT_ANCHORS = {
            "rop_chain": "pop rdi pop rsi pop rdx ret gadget_chain stack_pivot xchg rsp",
            "write_what_where": "mov [reg] reg str reg [reg] arbitrary_write controlled_write",
            "code_exec": "jmp reg call reg shellcode_exec mprotect mmap rwx VirtualProtect",
            "stack_pivot": "xchg rsp mov rsp leave ret pivot_gadget",
        }

        embedder = BgeCodeEmbedder()
        classifier = BehaviorClassifier.instance(embedder)

        # Temporarily add exploit anchors to the classifier
        orig_anchors = dict(classifier.ANCHORS)
        classifier.ANCHORS.update(_EXPLOIT_ANCHORS)
        classifier.clear_cache()

        try:
            hits = classifier.classify(insn_text, threshold=0.0, top_k=6, block=True)
            if hits:
                vals = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in hits)
                q50 = vals[len(vals) // 2]
                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                gate = q50 + max(0.0, q75 - q50)
                hits = [h for h in hits if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate]
        finally:
            # Restore original anchors
            classifier.ANCHORS.clear()
            classifier.ANCHORS.update(orig_anchors)
            classifier.clear_cache()

        if not hits:
            return None

        return {
            "classifications": hits,
            "top_primitive": hits[0]["behavior"] if hits else None,
            "confidence": hits[0]["confidence"] if hits else 0.0,
            "note": f"Semantic exploit primitive analysis of {len(gadgets)} gadgets",
        }
    except Exception:
        return None


def _classify_gadget_chain(addr, limit, max_insns, query, auto_blackboard: bool = False) -> dict:
    """
    Full exploit chain classification: collect all gadget types, embed the
    combined chain, and return a structured exploit primitive assessment.
    """
    try:
        from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
    except ImportError:
        try:
            from host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder  # type: ignore
        except ImportError:
            return make_error(MCPError.IDA_ERROR, "intelligence.py not available")

    # Collect gadgets from all primitive types
    all_gadgets = {}
    for prim_action, handler in _ACTIONS.items():
        try:
            g = handler(addr, min(limit, 20), max_insns, query)
            if g:
                all_gadgets[prim_action] = g[:10]
        except Exception:
            pass

    if not all_gadgets:
        return {"ok": True, "primitives_found": {}, "exploit_assessment": "No gadgets found", "arch": _get_arch()}

    # Build chain description
    chain_text = ""
    for prim, gadgets in all_gadgets.items():
        chain_text += f"{prim}: " + " | ".join(
            g.get("gadget") or g.get("insns") or "" for g in gadgets[:5]
        ) + "\n"

    embedder = BgeCodeEmbedder()
    classifier = BehaviorClassifier.instance(embedder)

    _EXPLOIT_ANCHORS = {
        "rop_chain": "pop rdi pop rsi pop rdx ret gadget_chain stack_pivot xchg rsp",
        "write_what_where": "mov [reg] reg str reg [reg] arbitrary_write controlled_write",
        "code_exec": "jmp reg call reg shellcode_exec mprotect mmap rwx VirtualProtect",
        "stack_pivot": "xchg rsp mov rsp leave ret pivot_gadget",
        "memory_manipulation": BehaviorClassifier.ANCHORS.get("memory_manipulation", ""),
    }
    orig = dict(classifier.ANCHORS)
    classifier.ANCHORS.update(_EXPLOIT_ANCHORS)
    classifier.clear_cache()
    try:
        hits = classifier.classify(chain_text, threshold=0.0, top_k=8, block=True)
        if hits:
            vals = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in hits)
            q50 = vals[len(vals) // 2]
            q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
            gate = q50 + max(0.0, q75 - q50)
            hits = [h for h in hits if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate]
    finally:
        classifier.ANCHORS.clear()
        classifier.ANCHORS.update(orig)
        classifier.clear_cache()

    # Assess exploitability
    has_pivot = bool(all_gadgets.get("stack_pivot"))
    has_www = bool(all_gadgets.get("write_what_where"))
    has_rop = bool(all_gadgets.get("rop"))
    has_syscall = bool(all_gadgets.get("syscall"))

    if has_pivot and has_rop and (has_www or has_syscall):
        assessment = "HIGH: Full ROP chain possible — stack pivot + write primitives + syscall/exec gadgets present"
    elif has_rop and has_pivot:
        assessment = "MEDIUM: Partial ROP chain — pivot and gadgets present, missing write-what-where or syscall"
    elif has_rop:
        assessment = "LOW: ROP gadgets present but no stack pivot found"
    else:
        assessment = "MINIMAL: Limited gadget surface"

    # Auto-write exploit findings to blackboard — opt-in only. This is a
    # read-classified operation, so it must not persist findings without an
    # explicit auto_blackboard=True.
    if (has_rop or has_pivot or has_www) and auto_blackboard:
        try:
            from blackboard import BlackboardStore  # type: ignore
            import time as _time
            store = BlackboardStore()
            prim_names = sorted(all_gadgets.keys())
            confidence = 0.9 if "HIGH" in assessment else (0.7 if "MEDIUM" in assessment else 0.5)
            existing = store.list(category="exploit", limit=50)
            if not any("gadget" in (e.get("title", "").lower()) for e in existing):
                store.write(
                    title=f"Exploit primitives: {', '.join(prim_names)}",
                    content=assessment,
                    category="exploit",
                    tags=["exploit", "gadgets", _get_arch()] + prim_names,
                    confidence=confidence,
                    source="gadgets",
                    source_type="engine_gadgets",
                    evidence=[{
                        "type": "gadget_scan",
                        "value": f"{len(all_gadgets)} primitive types found",
                        "weight": confidence,
                        "ts": _time.time(),
                    }],
                )
        except Exception:
            pass

    return {
        "ok": True,
        "arch": _get_arch(),
        "primitives_found": {k: len(v) for k, v in all_gadgets.items()},
        "exploit_assessment": assessment,
        "behavior_classifications": hits,
        "top_primitive": hits[0]["behavior"] if hits else None,
        "chain_building_blocks": {
            k: [g.get("gadget") or g.get("insns") for g in v[:3]]
            for k, v in all_gadgets.items() if v
        },
        "backend": embedder.backend,
    }
