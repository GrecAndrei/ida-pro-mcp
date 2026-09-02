"""Regression tests for swarm/s02-q05gadgets findings.

Covers:
- RISC-V register-indirect branches (jalr/c.jr/c.jalr) are classified through
  the SHARED support/arch_utils classifier instead of a gadgets-local parser,
  so compressed terminators appear in JOP/COP/ROP correctly (see also
  test_swarm_t10_gadgets.py, extended for the compressed forms).
- write_what_where on RISC-V is narrowed to stores whose base register is NOT
  the stack/frame pointer — ordinary ``sw s0, 8(sp); ret`` frame saves are no
  longer reported as write-what-where primitives.
- A byte-level linear-sweep mode raw-decodes from every offset in the exec
  region (ida_ua, not IDA heads).  It auto-activates when the region has no
  defined instruction heads (an opaque raw blob IDA never disassembled) and can
  be forced with raw=True.  plan_range/auto_make_code is attempted over the
  segment first, and an empty result on a never-disassembled region carries a
  "region was never disassembled" note.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_support_module, load_tool_module


def _arch_overrides() -> dict:
    """Real arch_utils functions/constants injected into the _common stub."""
    au = load_support_module("arch_utils")
    return {
        "get_arch": lambda: "riscv64",
        "is_x86_family": au.is_x86_family,
        "is_arm_family": au.is_arm_family,
        "is_mips_family": au.is_mips_family,
        "is_ppc_family": au.is_ppc_family,
        "is_riscv_family": au.is_riscv_family,
        "is_return_mnemonic": au.is_return_mnemonic,
        "get_stack_pointer_names": au.get_stack_pointer_names,
        "CALL_MNEMONICS": au.CALL_MNEMONICS,
        "TERMINATOR_MNEMONICS": au.TERMINATOR_MNEMONICS,
        "SYSCALL_MNEMONICS": au.SYSCALL_MNEMONICS,
        "UNCONDITIONAL_JUMP_MNEMONICS": au.UNCONDITIONAL_JUMP_MNEMONICS,
    }


class _Seg:
    def __init__(self, start, end, perm, stype):
        self.start_ea = start
        self.end_ea = end
        self.perm = perm
        self.type = stype


class _FakeInsn:
    """insn_t stand-in produced by the fake ida_ua decoder."""

    size = 4
    _mnem = ""

    def get_canon_mnem(self):
        return self._mnem


class _RawRiscvIDB:
    """RISC-V region whose bytes decode only at known instruction starts.

    With with_heads=False the region has NO defined instruction heads (IDA never
    disassembled the blob); with with_heads=True the same stream has heads so a
    caller can force the linear sweep with raw=True.
    """

    START = 0x1000
    END = 0x1010
    BADADDR = -1

    def __init__(self, insns):
        # insns: list of (ea, mnem, disasm, size)
        self._insns = {ea: (mnem, disasm, size) for ea, mnem, disasm, size in insns}
        self._eas = sorted(self._insns)
        self.plan_calls = []

    def install(self, with_heads=False):
        idc_ = sys.modules["idc"]
        if with_heads:
            idc_.print_insn_mnem = lambda ea: self._insns.get(ea, ("", "", 4))[0]
            idc_.next_head = self._next
            idc_.prev_head = self._prev
        else:
            idc_.print_insn_mnem = lambda ea: ""
            idc_.next_head = lambda ea: self.BADADDR
            idc_.prev_head = lambda ea: self.BADADDR
        idc_.generate_disasm_line = lambda ea, flags: self._insns.get(ea, ("", "", 4))[1]
        idc_.get_item_size = lambda ea: self._insns.get(ea, ("", "", 4))[2]

        idaapi = sys.modules["idaapi"]
        idaapi.BADADDR = self.BADADDR
        idaapi.SEGPERM_EXEC = 4
        idaapi.SEG_CODE = 2
        idaapi.getseg = lambda ea: _Seg(self.START, self.END, 4, 2)

        # compat.get_segment_* resolves ida_segment via sys.modules; expose the
        # legacy getseg surface (mirroring idaapi.getseg) plus the 9.4 EA one.
        ida_segment = sys.modules["ida_segment"]
        ida_segment.getseg = idaapi.getseg
        ida_segment.ida_idaapi = types.SimpleNamespace(BADADDR=self.BADADDR)
        ida_segment.segment_info_t = types.SimpleNamespace
        ida_segment.get_segment_info = lambda out, ea, flags=0: False

        autils = sys.modules["idautils"]
        autils.Segments = lambda: iter([self.START])

        lines = sys.modules["ida_lines"]
        lines.tag_remove = lambda s: s

        # Fake ida_ua: raw byte-level decode (only succeeds at instruction starts).
        ua = sys.modules.setdefault("ida_ua", types.ModuleType("ida_ua"))
        ua.insn_t = _FakeInsn
        ua.decode_insn = self._decode_insn

        # Fake ida_auto: records plan_range calls (the exec-region prep step).
        auto = sys.modules.setdefault("ida_auto", types.ModuleType("ida_auto"))
        self.plan_calls = []
        auto.plan_range = lambda s, e: self.plan_calls.append((s, e))

    def _decode_insn(self, insn, ea):
        hit = self._insns.get(ea)
        if hit is None:
            return 0
        mnem, _disasm, size = hit
        insn.size = size
        insn._mnem = mnem
        return 1

    def _next(self, ea):
        for e in self._eas:
            if e > ea:
                return e
        return self.BADADDR

    def _prev(self, ea):
        if ea in self._eas:
            i = self._eas.index(ea)
            if i > 0:
                return self._eas[i - 1]
        return self.BADADDR


def _load_gadgets():
    return load_tool_module("gadgets", common_overrides=_arch_overrides())


def _gadget_texts(gadgets):
    return [g["gadget"] for g in gadgets]


# ---------------------------------------------------------------------------
# Byte-level linear sweep: opaque raw blob with no instruction heads
# ---------------------------------------------------------------------------

def test_raw_sweep_finds_rop_gadget_on_headless_blob():
    """A region IDA never disassembled auto-falls back to the linear sweep."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),   # RISC-V return
    ]).install(with_heads=False)
    res = g._find_rop_gadgets(None, 50, 5, None)
    texts = _gadget_texts(res)
    assert any("jalr zero, 0(ra)" in t for t in texts), texts


def test_raw_sweep_skips_call_on_headless_blob():
    """jalr rd=ra (a call) must not leak into ROP during the linear sweep."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr ra, 0(t0)", 4),   # indirect call, not a return
    ]).install(with_heads=False)
    assert g._find_rop_gadgets(None, 50, 5, None) == []


def test_raw_sweep_finds_compressed_jop_on_headless_blob():
    """c.jr rs1!=ra is a JOP terminator found by the sweep."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "c.jr", "c.jr t0", 2),   # compressed indirect jump
    ]).install(with_heads=False)
    res = g._find_jop_gadgets(None, 50, 5, None)
    assert any("c.jr t0" in t for t in _gadget_texts(res)), res


def test_raw_sweep_finds_compressed_call_on_headless_blob():
    """c.jalr always links ra -> a COP terminator found by the sweep."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "c.jalr", "c.jalr t0", 2),   # compressed indirect call
    ]).install(with_heads=False)
    res = g._find_cop_gadgets(None, 50, 5, None)
    assert any("c.jalr t0" in t for t in _gadget_texts(res)), res


def test_raw_sweep_finds_ecall_syscall_on_headless_blob():
    """ecall is a syscall gadget found by the sweep."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "ecall", "ecall", 4),
    ]).install(with_heads=False)
    res = g._find_syscall_gadgets(None, 50, 5, None)
    assert any("ecall" in t for t in _gadget_texts(res)), res


def test_raw_sweep_opt_in_forces_sweep_even_with_heads():
    """raw=True runs the linear sweep even when IDA has defined heads."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=True)
    res = g._find_rop_gadgets(None, 50, 5, None, raw=True)
    assert any("jalr zero, 0(ra)" in t for t in _gadget_texts(res)), res


def test_exec_region_plan_range_scheduled_first():
    """plan_range is attempted over the exec segment before scanning."""
    g = _load_gadgets()
    idb = _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ])
    idb.install(with_heads=False)
    g._find_rop_gadgets(None, 50, 5, None)
    assert (0x1000, 0x1010) in idb.plan_calls, idb.plan_calls


def test_region_has_heads_detection():
    """_exec_region_has_heads distinguishes disassembled vs opaque regions."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=False)
    assert g._exec_region_has_heads(None) is False
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=True)
    assert g._exec_region_has_heads(None) is True


# ---------------------------------------------------------------------------
# "region was never disassembled" note on the tool response
# ---------------------------------------------------------------------------

def test_tool_notes_never_disassembled_region_on_empty():
    """An empty sweep result on a headless region carries the note."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),   # no qualifying terminator
    ]).install(with_heads=False)
    resp = g.gadgets(action="rop", limit=50, max_insns=5)
    assert resp["ok"] is True
    assert resp["count"] == 0
    assert resp["gadgets"] == []
    assert "never disassembled" in resp["note"]
    assert "byte-level linear sweep" in resp["note"]


def test_tool_notes_raw_opt_in_empty_with_heads():
    """raw=True on a disassembled region yields the raw-sweep note."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),   # no qualifying terminator
    ]).install(with_heads=True)
    resp = g.gadgets(action="jop", limit=50, max_insns=5, raw=True)
    assert resp["ok"] is True
    assert resp["count"] == 0
    assert "raw=True" in resp["note"]


def test_tool_returns_gadgets_without_note_when_found():
    """A successful raw sweep returns gadgets and no note."""
    g = _load_gadgets()
    # Skip the heavy BehaviorClassifier scoring backend for this unit test.
    g._score_gadgets_behavior = lambda *a, **k: None
    _RawRiscvIDB([
        (0x1000, "addi", "addi sp, sp, 16", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=False)
    resp = g.gadgets(action="rop", limit=50, max_insns=5)
    assert resp["count"] == 1
    assert "note" not in resp


# ---------------------------------------------------------------------------
# write_what_where narrowing: RISC-V stores through sp/fp are not W^W
# ---------------------------------------------------------------------------

def test_www_skips_frame_save_via_sp():
    """sw s0, 8(sp); ret is a frame save, not a write-what-where."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "sw", "sw s0, 8(sp)", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=True)
    assert g._find_write_what_where(None, 50, 5, None) == []


def test_www_skips_frame_save_via_fp():
    """sw s0, 0(fp); ret stores via the frame pointer, not a W^W primitive."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "sw", "sw s0, 0(fp)", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=True)
    assert g._find_write_what_where(None, 50, 5, None) == []


def test_www_reports_store_through_non_fp_base():
    """sw a0, 0(t0); ret writes through a register argument -> W^W."""
    g = _load_gadgets()
    _RawRiscvIDB([
        (0x1000, "sw", "sw a0, 0(t0)", 4),
        (0x1004, "jalr", "jalr zero, 0(ra)", 4),
    ]).install(with_heads=True)
    res = g._find_write_what_where(None, 50, 5, None)
    assert any("sw a0, 0(t0)" in t for t in _gadget_texts(res)), res


def test_gadget_arch_terminators_cover_all_supported_families(monkeypatch):
    g = _load_gadgets()
    g.idaapi.SEGPERM_EXEC = 4
    g.idaapi.SEG_CODE = 2
    g.idc.o_reg = 1
    g.idc.o_mem = 2
    g.idc.o_phrase = 3
    g.idc.o_displ = 4
    monkeypatch.setattr(g.idc, "get_operand_type", lambda *_args: g.idc.o_reg, raising=False)
    monkeypatch.setattr(g.idc, "get_operand_value", lambda *_args: 0x80, raising=False)
    monkeypatch.setattr(g, "_is_x86_family", lambda arch: arch in {"x86", "x64"})
    monkeypatch.setattr(g, "_is_arm_family", lambda arch: arch in {"arm", "arm64"})
    monkeypatch.setattr(g, "is_mips_family", lambda arch: arch in {"mips", "mips64"})
    monkeypatch.setattr(g, "is_ppc_family", lambda arch: arch in {"ppc", "ppc64"})
    monkeypatch.setattr(g, "is_riscv_family", lambda arch: arch in {"riscv", "riscv64"})
    monkeypatch.setattr(g, "is_sparc_family", lambda arch: arch in {"sparc"})

    assert g._is_jop_terminator(0, "jmp", "jmp rax", "x64") is True
    monkeypatch.setattr(g.idc, "get_operand_type", lambda *_args: 0)
    assert g._is_jop_terminator(0, "jmp", "jmp", "x64") is False
    monkeypatch.setattr(g.idc, "get_operand_type", lambda *_args: g.idc.o_reg)
    assert g._is_cop_terminator(0, "call", "call rax", "x64") is True
    monkeypatch.setattr(g.idc, "get_operand_type", lambda *_args: 0)
    assert g._is_cop_terminator(0, "call", "call", "x64") is False
    monkeypatch.setattr(g.idc, "get_operand_type", lambda *_args: g.idc.o_reg)
    assert g._is_jop_terminator(0, "bx", "bx r0", "arm") is True
    assert g._is_cop_terminator(0, "blr", "blr x0", "arm64") is True
    assert g._is_cop_terminator(0, "blx", "blx r0", "arm") is True
    assert g._is_jop_terminator(0, "jr", "jr $4", "mips") is True
    assert g._is_jop_terminator(0, "jr", "jr ra", "mips") is False
    assert g._is_cop_terminator(0, "jalr", "jalr $4", "mips") is True
    assert g._is_jop_terminator(0, "bctr", "bctr", "ppc") is True
    assert g._is_cop_terminator(0, "bctrl", "bctrl", "ppc") is True
    assert g._is_jop_terminator(0, "jalr", "jalr t0", "riscv64") is True
    assert g._is_cop_terminator(0, "c.jalr", "c.jalr t0", "riscv64") is True
    assert g._is_syscall_terminator(0, "int", "int 80h", "x86") is True
    monkeypatch.setattr(g.idc, "get_operand_value", lambda *_args: 3)
    assert g._is_syscall_terminator(0, "int", "int 3", "x86") is False
    monkeypatch.setattr(g.idc, "get_operand_value", lambda *_args: 0x80)
    assert g._is_syscall_terminator(0, "svc", "svc 0", "arm64") is True
    assert g._is_syscall_terminator(0, "syscall", "syscall", "mips") is True
    assert g._is_syscall_terminator(0, "sc", "sc", "ppc") is True
    assert g._is_syscall_terminator(0, "ta", "ta 0", "sparc") is True
    assert g._is_syscall_terminator(0, "ecall", "ecall", "riscv64") is True
    assert g._is_syscall_terminator(0, "trap", "trap", "unknown") is False


def test_gadget_helper_scan_paths_and_query_cache(monkeypatch):
    g = _load_gadgets()
    g.idaapi.SEGPERM_EXEC = 4
    g.idaapi.SEG_CODE = 2
    seg = _Seg(0x1000, 0x1010, 4, 2)
    monkeypatch.setattr(g, "_compat", types.SimpleNamespace(
        get_segment=lambda _ea: seg,
        get_segment_perm=lambda _ea: 4,
        get_segment_type=lambda _ea: 2,
    ))
    g.idautils.Segments = lambda: iter([0x1000, 0x2000])
    assert list(g._get_exec_segments(None)) == [(0x1000, 0x1010), (0x1000, 0x1010)]
    monkeypatch.setattr(g, "validate_addr", lambda _addr: (0x1004, None))
    assert list(g._get_exec_segments("0x1004")) == [(0x1000, 0x1010)]

    g._QUERY_MATCHER_CACHE.clear()
    insns = [(0x1000, "mov", "mov rax, rbx")]
    assert g._matches_query(insns, None) is True
    assert g._matches_query(insns, "rax") is True
    assert g._matches_query(insns, "not-present") is False
    assert g._matches_query(insns, "rax") is True

    monkeypatch.setattr(g, "_is_x86_family", lambda arch: arch == "x64")
    g.idc.get_item_size = lambda _ea: 1
    g.idc.print_insn_mnem = lambda ea: {0x1000: "mov", 0x1001: "ret"}.get(ea, "")
    g.idc.prev_head = lambda ea: 0x1000 if ea == 0x1001 else g.idaapi.BADADDR
    g.idc.generate_disasm_line = lambda ea, _flags: {0x1000: "mov rax, rbx", 0x1001: "ret"}.get(ea, "")
    g.ida_lines.tag_remove = lambda text: text
    assert g._decode_backward(0x1001, 3)[-1][1] == "ret"
    assert g._format_gadget(g._decode_backward(0x1001, 3))["insns"] == 2


def test_gadget_region_preparation_and_decode_failures(monkeypatch):
    g = _load_gadgets()
    auto = types.ModuleType("ida_auto")
    monkeypatch.setitem(sys.modules, "ida_auto", auto)
    assert g._prepare_exec_region(1, 2) is False
    auto.auto_mark_range = lambda *_args: True
    auto.AU_FINAL = 9
    assert g._prepare_exec_region(1, 2) is True
    delattr(auto, "auto_mark_range")
    auto.auto_make_code = lambda *_args: True
    assert g._prepare_exec_region(1, 2) is True
    auto.auto_make_code = lambda *_args: (_ for _ in ()).throw(RuntimeError("auto"))
    assert g._prepare_exec_region(1, 2) is False

    g.idc.next_head = lambda *_args: (_ for _ in ()).throw(RuntimeError("heads"))
    assert g._region_has_heads(1, 2) is False
    monkeypatch.setattr(g, "_get_exec_segments", lambda _addr: [(1, 2)])
    assert g._exec_region_has_heads(None) is False
    ua = types.ModuleType("ida_ua")
    monkeypatch.setitem(sys.modules, "ida_ua", ua)
    assert g._raw_decode_insn(1) is None
    ua.insn_t = lambda: types.SimpleNamespace(size=0, get_canon_mnem=lambda: "")
    ua.decode_insn = lambda *_args: 0
    assert g._raw_decode_insn(1) is None


def test_gadget_shellcode_mitigations_and_seh_modes(monkeypatch):
    g = _load_gadgets()
    g.idaapi.f_PE = 10
    g.idaapi.f_ELF = 11
    g.idaapi.f_MACHO = 12
    segments = {
        1: _Seg(0x1000, 0x1100, 6, 2),
        2: _Seg(0x2000, 0x2100, 4, 2),
        3: None,
    }
    monkeypatch.setattr(g, "_compat", types.SimpleNamespace(
        get_segment=segments.get,
        get_segment_perm=lambda ea: {1: 6, 2: 4, 3: 0}.get(ea, 0),
        get_segment_type=lambda ea: 2 if ea == 1 else 0,
        get_segment_name=lambda ea: {1: ".text", 2: ".data"}.get(ea, ""),
        get_func_start=lambda ea: ea,
    ))
    g.idautils.Segments = lambda: iter([1, 2, 3])
    g.idaapi.SEGPERM_WRITE = 2
    g.idaapi.SEGPERM_EXEC = 4
    g.idaapi.SEGPERM_READ = 1
    g.idaapi.SEG_CODE = 2
    assert len(g._find_shellcode_space(None, 10, 5, None)) == 1
    monkeypatch.setattr(g, "validate_addr", lambda _addr: (0x3000, None))
    assert g._find_shellcode_space("0x3000", 10, 5, None) == []
    monkeypatch.setattr(g, "_inf_filetype_id", lambda: 999)
    assert g._detect_mitigations(None, 1, 1, None)["format"] == "unknown"

    monkeypatch.setattr(g, "_inf_filetype_id", lambda: g.idaapi.f_PE)
    g.idaapi.get_imagebase = lambda: 0x400000
    g.ida_bytes.get_dword = lambda _ea: 0x40
    g.ida_bytes.get_word = lambda _ea: 0x20B
    g.idc.get_name_ea_simple = lambda name: 0x5000 if name == "__security_cookie" else g.idaapi.BADADDR
    pe = g._detect_mitigations(None, 1, 1, None)
    assert pe["format"] == "PE" and pe["stack_cookies"] is True
    g.ida_bytes.get_word = lambda _ea: (_ for _ in ()).throw(RuntimeError("header"))
    assert g._detect_mitigations(None, 1, 1, None)["pe_parse_error"] is True

    monkeypatch.setattr(g, "_inf_filetype_id", lambda: g.idaapi.f_ELF)
    monkeypatch.setattr(g, "_compat", types.SimpleNamespace(
        get_segment=lambda ea: _Seg(0, 1, 0, 0),
        get_segment_name=lambda ea: ".got.plt" if ea == 1 else ".text",
        get_segment_perm=lambda ea: 2 if ea == 1 else 4,
    ))
    g.idautils.Segments = lambda: iter([1, 2])
    g.idc.get_name_ea_simple = lambda _name: g.idaapi.BADADDR
    g.idaapi.get_imagebase = lambda: 0
    g.idautils.Names = lambda: iter([(0x1, "__memcpy_chk")])
    elf = g._detect_mitigations(None, 1, 1, None)
    assert elf["format"] == "ELF" and elf["RELRO"] == "partial" and elf["FORTIFY_SOURCE"] is True

    monkeypatch.setattr(g, "_inf_filetype_id", lambda: g.idaapi.f_MACHO)
    g.idautils.Names = lambda: iter([])
    macho = g._detect_mitigations(None, 1, 1, None)
    assert macho["format"] == "Mach-O" and macho["stack_cookies"] is False

    monkeypatch.setattr(g, "_get_arch", lambda: "x86")
    seh_seg = _Seg(0x1000, 0x1010, 4, 2)
    monkeypatch.setattr(g, "_compat", types.SimpleNamespace(
        get_segment=lambda _ea: seh_seg,
        get_segment_perm=lambda _ea: 4,
        get_segment_type=lambda _ea: 2,
        get_func_start=lambda ea: ea,
    ))
    g.idautils.Segments = lambda: iter([0x1000])
    g.idc.print_insn_mnem = lambda _ea: "push"
    g.idc.generate_disasm_line = lambda ea, _flags: "push handler" if ea == 0x1000 else "push dword ptr fs:[0]"
    g.ida_lines.tag_remove = lambda text: text
    g.idc.next_head = lambda ea: 0x1004 if ea == 0x1000 else g.idaapi.BADADDR
    g.idc.prev_head = lambda _ea: 0x1000
    g.idc.get_operand_value = lambda _ea, _op: 0x7000
    g.ida_funcs.get_func_name = lambda _ea: "handler_fn"
    assert g._find_seh_handlers(None, 10, 5, None)
    monkeypatch.setattr(g, "_get_arch", lambda: "arm64")
    assert g._find_seh_handlers(None, 10, 5, None) == []


def test_gadget_pivot_dispatch_and_chain_assessment(monkeypatch):
    g = _load_gadgets()
    monkeypatch.setattr(g, "_get_exec_segments", lambda _addr: [])
    for arch in ("x64", "arm64", "mips", "ppc", "riscv64", "unknown"):
        monkeypatch.setattr(g, "_get_arch", lambda arch=arch: arch)
        assert isinstance(g._suggest_pivot_chains(None, 50, 5, None), dict)

    monkeypatch.setattr(g, "_get_arch", lambda: "x64")
    monkeypatch.setattr(g, "_exec_region_has_heads", lambda _addr: True)
    monkeypatch.setattr(g, "_score_gadgets_behavior", lambda *_args: None)
    monkeypatch.setitem(g._ACTIONS, "rop", lambda *args, **kwargs: [{"gadget": "pop rdi ; ret"}])
    assert g.gadgets("rop", limit=1)["count"] == 1
    g._find_shellcode_space = lambda *_args: ["region"]
    assert g.gadgets("shellcode_space")["regions"] == "region"
    g._detect_mitigations = lambda *_args: {"ASLR": False}
    assert g.gadgets("mitigations")["mitigations"]["ASLR"] is False
    g._find_seh_handlers = lambda *_args: ["handler"]
    assert g.gadgets("seh_handlers")["count"] == 1
    g._suggest_pivot_chains = lambda *_args: {"pop": {"count": 2}}
    assert g.gadgets("pivot_chains")["total_gadgets"] == 2
    g._classify_gadget_chain = lambda *_args: {"ok": True, "assessment": "LOW"}
    assert g.gadgets("classify_chain")["assessment"] == "LOW"
    assert g.gadgets("semantic_find")["code"] == "INVALID_ARGS"
    assert g.gadgets("not-real")["code"] == "INVALID_ARGS"
