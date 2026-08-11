"""Regression tests for swarm/t10_gadgets findings.

Covers:
- RISC-V jalr operand classification. ``jalr rd, imm(rs1)`` is overloaded:
  rd=ra links a return address (indirect call), rd=x0 with rs1=ra returns,
  rd=x0 with rs1!=ra jumps. The old code tested ``"ra" not in disasm`` which
  inverted COP output (jumps reported, calls missed) and let ``is_return_mnemonic``
  leak ``jalr ra`` calls into the ROP results. The finders now parse the operand
  shapes and classify call/return/jump.
- governance_engine: PII inference regexes must not claim a REDACTED verdict
  the rule cannot actually redact (bare credential word, non-32/40/64 hash),
  and a .text patch with sparse metadata is blocked because
  DangerousCodeSectionPatch fires on its universal axioms alone.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys

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


class _RiscvIDB:
    """Minimal RISC-V instruction stream for the gadget finders.

    Entries are (ea, mnem, disasm) or (ea, mnem, disasm, size); size defaults
    to 4 so the compressed (c.*) forms can be modelled accurately.
    """

    START = 0x1000
    END = 0x1010
    BADADDR = -1

    def __init__(self, insns):
        # insns: list of (ea, mnem, disasm[, size])
        self._insns = {}
        self._sizes = {}
        for entry in insns:
            ea, mnem, disasm = entry[0], entry[1], entry[2]
            size = entry[3] if len(entry) > 3 else 4
            self._insns[ea] = (mnem, disasm)
            self._sizes[ea] = size
        self._eas = sorted(self._insns)

    def install(self):
        idc_ = sys.modules["idc"]
        idc_.print_insn_mnem = lambda ea: self._insns.get(ea, ("", ""))[0]
        idc_.generate_disasm_line = lambda ea, flags: self._insns.get(ea, ("", ""))[1]
        idc_.get_item_size = lambda ea: self._sizes.get(ea, 4)
        idc_.next_head = self._next
        idc_.prev_head = self._prev

        idaapi = sys.modules["idaapi"]
        idaapi.BADADDR = self.BADADDR
        idaapi.SEGPERM_EXEC = 4
        idaapi.SEG_CODE = 2
        idaapi.getseg = lambda ea: _Seg(self.START, self.END, 4, 2)

        autils = sys.modules["idautils"]
        autils.Segments = lambda: iter([self.START])

        lines = sys.modules["ida_lines"]
        lines.tag_remove = lambda s: s

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
# RISC-V register-indirect branch classification (routed through the shared
# arch_utils classifier: _riscv_branch_kind + is_return_mnemonic)
# ---------------------------------------------------------------------------

def test_riscv_branch_kind_classifies_jalr_call_return_jump():
    g = _load_gadgets()
    # rd=ra -> indirect call (COP)
    assert g._riscv_branch_kind("jalr", "jalr ra, 0(t0)") == "call"
    assert g._riscv_branch_kind("jalr", "jalr ra, t0, 0") == "call"
    assert g._riscv_branch_kind("jalr", "jalr ra, 0(ra)") == "call"
    # return requires rd==x0/zero AND rs1==ra (shared arch_utils rule)
    assert g._riscv_branch_kind("jalr", "jalr zero, 0(ra)") == "return"
    assert g._riscv_branch_kind("jalr", "jalr x0, 0(ra)") == "return"
    assert g._riscv_branch_kind("jalr", "jalr x0, ra, 0") == "return"
    # rd!=x0 (e.g. t0) with rs1==ra is NOT a pure return -> JOP jump
    assert g._riscv_branch_kind("jalr", "jalr t0, 0(ra)") == "jump"
    # rd=x0, rs1!=ra -> jump (JOP)
    assert g._riscv_branch_kind("jalr", "jalr zero, 0(t0)") == "jump"
    assert g._riscv_branch_kind("jalr", "jalr x0, 0(t3)") == "jump"
    # unparseable jalr defaults to "call" (never dropped from COP)
    assert g._riscv_branch_kind("jalr", "") == "call"
    # non-branch mnemonics are not classified
    assert g._riscv_branch_kind("addi", "addi sp, sp, 16") == "other"


def test_riscv_branch_kind_compressed_forms():
    g = _load_gadgets()
    # c.jr rs1==ra -> return (ROP); c.jr rs1!=ra -> JOP jump
    assert g._riscv_branch_kind("c.jr", "c.jr ra") == "return"
    assert g._riscv_branch_kind("c.jr", "c.jr x1") == "return"
    assert g._riscv_branch_kind("c.jr", "c.jr t0") == "jump"
    assert g._riscv_branch_kind("c.jr", "c.jr a5") == "jump"
    # c.jalr always links to ra -> call (COP), never a return/jump
    assert g._riscv_branch_kind("c.jalr", "c.jalr t0") == "call"
    assert g._riscv_branch_kind("c.jalr", "c.jalr ra") == "call"


# ---------------------------------------------------------------------------
# COP finder: only the rd=ra call form is an indirect call
# ---------------------------------------------------------------------------

def test_cop_finder_reports_riscv_indirect_call():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr ra, 0(t0)"),   # function-pointer call
    ]).install()
    res = g._find_cop_gadgets(None, 50, 5, None)
    texts = _gadget_texts(res)
    assert any("jalr ra, 0(t0)" in t for t in texts), texts


def test_cop_finder_skips_riscv_jump():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr zero, 0(t0)"),   # indirect jump, not a call
    ]).install()
    assert g._find_cop_gadgets(None, 50, 5, None) == []


def test_cop_finder_skips_riscv_return():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr zero, 0(ra)"),   # return, not a call
    ]).install()
    assert g._find_cop_gadgets(None, 50, 5, None) == []


# ---------------------------------------------------------------------------
# ROP finder: only the rs1=ra return form is a return gadget
# ---------------------------------------------------------------------------

def test_rop_finder_does_not_report_riscv_call_as_return():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr ra, 0(t0)"),   # function-pointer call
    ]).install()
    res = g._find_rop_gadgets(None, 50, 5, None)
    assert res == [], _gadget_texts(res)


def test_rop_finder_reports_riscv_return():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr zero, 0(ra)"),   # genuine return
    ]).install()
    res = g._find_rop_gadgets(None, 50, 5, None)
    texts = _gadget_texts(res)
    assert any("jalr zero, 0(ra)" in t for t in texts), texts


# ---------------------------------------------------------------------------
# JOP finder: only the rd=x0, rs1!=ra form is an indirect jump
# ---------------------------------------------------------------------------

def test_jop_finder_reports_jump_not_call():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr zero, 0(t0)"),
    ]).install()
    res = g._find_jop_gadgets(None, 50, 5, None)
    assert any("jalr zero, 0(t0)" in t for t in _gadget_texts(res)), res
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)"),
        (0x1004, "addi", "addi sp, sp, 16"),
        (0x1008, "jalr", "jalr ra, 0(t0)"),   # call, not a jump
    ]).install()
    assert g._find_jop_gadgets(None, 50, 5, None) == []


# ---------------------------------------------------------------------------
# Compressed terminators: c.jr / c.jalr route through the shared classifier
# ---------------------------------------------------------------------------

def test_jop_finder_reports_compressed_jump():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jr", "c.jr t0", 2),   # compressed indirect jump (rs1!=ra)
    ]).install()
    res = g._find_jop_gadgets(None, 50, 5, None)
    assert any("c.jr t0" in t for t in _gadget_texts(res)), res


def test_jop_finder_skips_compressed_call():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jalr", "c.jalr t0", 2),   # compressed call, not a jump
    ]).install()
    assert g._find_jop_gadgets(None, 50, 5, None) == []


def test_cop_finder_reports_compressed_call():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jalr", "c.jalr t0", 2),   # compressed indirect call
    ]).install()
    res = g._find_cop_gadgets(None, 50, 5, None)
    assert any("c.jalr t0" in t for t in _gadget_texts(res)), res


def test_cop_finder_skips_compressed_jump():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jr", "c.jr t0", 2),   # compressed jump, not a call
    ]).install()
    assert g._find_cop_gadgets(None, 50, 5, None) == []


def test_rop_finder_reports_compressed_return():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jr", "c.jr ra", 2),   # compressed return
    ]).install()
    res = g._find_rop_gadgets(None, 50, 5, None)
    assert any("c.jr ra" in t for t in _gadget_texts(res)), res


def test_rop_finder_skips_compressed_call():
    g = _load_gadgets()
    _RiscvIDB([
        (0x1000, "lw", "lw a0, 0(sp)", 4),
        (0x1004, "c.jalr", "c.jalr t0", 2),   # compressed call, not a return
    ]).install()
    assert g._find_rop_gadgets(None, 50, 5, None) == []


# ---------------------------------------------------------------------------
# governance_engine: PII inference must not over-claim redaction
# ---------------------------------------------------------------------------

def _gov():
    return load_tool_module("governance_engine")


def test_governance_bare_credential_word_not_falsely_redacted():
    gov = _gov()
    result = gov.evaluate_operation(
        operation_type="comment", proposed_value="the password is hunter2",
    )
    # No "key: value" form, so the rule cannot redact it — the engine must
    # not return a REDACTED verdict while handing the original text back.
    assert result["verdict"] != "redacted"
    assert result["redacted_content"] == "the password is hunter2"


def test_governance_credential_with_value_is_redacted():
    gov = _gov()
    result = gov.evaluate_operation(
        operation_type="comment", proposed_value="the password=hunter2",
    )
    assert result["verdict"] == "redacted"
    assert "[CREDENTIAL_REDACTED]" in result["redacted_content"]
    assert result["approved"] is True


def test_governance_nonstandard_hash_not_falsely_redacted():
    gov = _gov()
    # 48 hex chars: redaction only covers exact 32/40/64, so inference must
    # not flag a REDACTED verdict with a no-op redact.
    value = "digest " + "0123456789abcdef" * 3
    result = gov.evaluate_operation(operation_type="comment", proposed_value=value)
    assert result["verdict"] != "redacted"
    assert result["redacted_content"] == value


def test_governance_sha256_still_redacted():
    gov = _gov()
    value = "token " + "a" * 64
    result = gov.evaluate_operation(operation_type="comment", proposed_value=value)
    assert result["verdict"] == "redacted"
    assert "[SHA256_REDACTED]" in result["redacted_content"]


def test_governance_domain_still_redacted():
    gov = _gov()
    result = gov.evaluate_operation(
        operation_type="comment", proposed_value="host at example.com",
    )
    assert result["verdict"] == "redacted"
    assert "[DOMAIN_REDACTED]" in result["redacted_content"]


# ---------------------------------------------------------------------------
# governance_engine: .text patches are blocked even with sparse metadata
# ---------------------------------------------------------------------------

def test_governance_code_section_patch_blocked_without_cf_metadata():
    gov = _gov()
    result = gov.evaluate_operation(
        operation_type="patch", proposed_value="", metadata={"section_type": ".text"},
    )
    assert result["approved"] is False
    assert result["verdict"] == "blocked"
    assert result["ontology_class"] == "DangerousCodeSectionPatch"


def test_governance_code_section_patch_still_blocked_with_cf_metadata():
    gov = _gov()
    result = gov.evaluate_operation(
        operation_type="patch", proposed_value="nop",
        metadata={"section_type": ".text", "modifies_control_flow": True},
    )
    assert result["approved"] is False
    assert result["verdict"] == "blocked"
    assert result["ontology_class"] == "DangerousCodeSectionPatch"
