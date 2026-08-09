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
