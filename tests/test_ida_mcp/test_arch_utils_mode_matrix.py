"""Architecture and ABI behavior exercised through shared IDA-side helpers."""

from __future__ import annotations

import importlib
import types

import idautils
import idc
import pytest


@pytest.fixture
def arch():
    return importlib.import_module("ida_pro_mcp.ida_mcp.support.arch_utils")


@pytest.mark.parametrize(
    ("proc", "is_64", "expected"),
    [
        ("metapc", True, "x64"), ("i686", False, "x86"),
        ("arm", False, "arm"), ("aarch64", True, "arm64"),
        ("riscv", False, "riscv"), ("riscv64", True, "riscv64"),
        ("mips", False, "mips"), ("mips64", True, "mips64"),
        ("ppc", False, "ppc"), ("powerpc64", True, "ppc64"),
        ("sparc", False, "sparc"), ("sparc64", True, "sparc64"),
        ("sh4", False, "sh"), ("m68k", False, "68k"), ("s390x", True, "s390"),
        ("xtensa", False, "xtensa"), ("tc162", False, "tricore"),
        ("atmega328", False, "avr"), ("msp430", False, "msp430"),
        ("csky", False, "csky"), ("arcompact", False, "arc"),
        ("niosii", False, "nios2"), ("micro-blaze", False, "microblaze"),
        ("v850", False, "v850"), ("rl78", False, "rl78"), ("h8300", False, "h8"),
        ("mcs-51", False, "mcs51"), ("z80", False, "z80"),
        ("pic24", False, "pic24"), ("pic18", False, "pic18"),
        ("mystery", False, "unknown"),
    ],
)
def test_get_arch_normalizes_real_processor_families(monkeypatch, arch, proc, is_64, expected):
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: (proc, is_64))
    assert arch.get_arch() == expected


def test_architecture_detection_falls_back_across_ida_versions(monkeypatch, arch):
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: ("", None))
    assert arch.get_arch() == "unknown"
    assert arch._is_64bit_from_proc("riscv64") is True
    assert arch._is_64bit_from_proc("arm32") is False
    assert arch._is_64bit_from_proc("generic") is None
    assert arch.is_x86_family("x64")
    assert arch.is_arm_family("arm64")
    assert arch.is_mips_family("mips")
    assert arch.is_ppc_family("ppc64")
    assert arch.is_riscv_family("riscv")
    assert arch.is_sparc_family("sparc64")
    assert not arch.is_sparc_family("unknown")


def test_register_abi_and_instruction_classification_are_arch_aware(arch):
    assert arch._riscv_reg_name("$ra") == "x1"
    assert arch._riscv_reg_name("x8") == "x8"
    assert arch._riscv_reg_name("7") == "x7"
    assert arch._riscv_operand_parts("jalr ra, 0(sp)", "jalr") == ["ra", "0(sp)"]
    assert arch.is_return_mnemonic("jalr", "jalr x0, 0(ra)", "riscv")
    assert not arch.is_return_mnemonic("jalr", "jalr ra, 0(sp)", "riscv")
    assert arch.is_return_mnemonic("c.jr", "c.jr ra", "riscv")
    assert not arch.is_return_mnemonic("c.jalr", "c.jalr ra", "riscv")
    assert arch.is_return_mnemonic("bx", "bx lr", "arm")
    assert arch.is_return_mnemonic("pop", "pop {pc}", "arm64")
    assert arch.is_return_mnemonic("jr", "jr $ra", "mips")
    assert arch.is_return_mnemonic("blr", "blr", "ppc")
    assert arch.is_call_mnemonic("call", "x64")
    assert arch.is_syscall_mnemonic("ecall", "riscv")
    assert not arch.is_call_mnemonic("ret", "x64")


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("x64", ["endbr64"], "cet_enabled"),
        ("x64", ["push", "mov"], "standard_frame_setup"),
        ("x64", ["sub"], "stack_alloc"),
        ("arm64", ["stp"], "aarch64_frame_setup"),
        ("arm", ["push"], "arm32_frame_setup"),
        ("mips", ["addiu"], "mips_frame_setup"),
        ("mips", ["sw"], "mips_reg_save"),
        ("ppc", ["mflr"], "ppc_frame_setup"),
        ("ppc", ["stwu"], "ppc_stack_alloc"),
        ("riscv", ["addi"], "riscv_frame_setup"),
        ("riscv", ["c.sw"], "riscv_reg_save"),
        ("unknown", ["nop"], "unknown"),
    ],
)
def test_prologue_patterns_cover_supported_abis(arch, arch_name, mnems, expected):
    assert arch.get_prologue_pattern(mnems, arch_name) == expected


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("x64", ["pop", "ret"], "standard_frame_teardown"),
        ("x64", ["ret"], "simple_ret"),
        ("x64", ["jmp"], "tail_call"),
        ("x64", ["int"], "interrupt"),
        ("arm", ["ldp", "bx"], "arm_frame_teardown"),
        ("arm", ["bx"], "arm_simple_ret"),
        ("arm64", ["ldp"], "aarch64_frame_teardown"),
        ("mips", ["lw", "jr"], "mips_frame_teardown"),
        ("mips", ["jr"], "mips_simple_ret"),
        ("ppc", ["lwz", "blr"], "ppc_frame_teardown"),
        ("ppc", ["blr"], "ppc_simple_ret"),
        ("riscv", ["lw", "ret"], "riscv_frame_teardown"),
        ("riscv", ["ret"], "riscv_simple_ret"),
        ("riscv", ["jal"], "tail_call"),
        ("unknown", ["nop"], "unknown"),
    ],
)
def test_epilogue_patterns_cover_supported_abis(arch, arch_name, mnems, expected):
    assert arch.get_epilogue_pattern(mnems, arch_name) == expected


def test_abi_register_and_tail_call_maps_have_safe_fallbacks(arch):
    for name in ("x86", "x64", "arm", "arm64", "mips", "ppc", "riscv", "sparc", "mcs51", "pic18"):
        assert arch.get_return_register(name)
        assert arch.get_stack_pointer_names(name)
    assert arch.get_return_register("not-real") == "r0"
    assert arch.get_stack_pointer_names("not-real") == {"sp"}
    assert arch.get_callee_saved_registers("x64")
    assert arch.get_callee_saved_registers("not-real") == set()
    assert "jmp" in arch.get_tail_call_mnemonics("x64")
    assert arch.get_tail_call_mnemonics("not-real") == {"jmp", "b", "j"}


def test_riscv_gp_note_and_detection_cover_found_and_missing_paths(monkeypatch, arch):
    assert "reanalysis queued" in arch._riscv_gp_note(0x1000, 0x8000, True, None, True)
    assert "ref-fix" in arch._riscv_gp_note(0x1000, 0x8000, True, None, False, {"fixed": 2})
    assert "already applied" in arch._riscv_gp_note(0x1000, 0x8000, True, None, False)
    assert "failed" in arch._riscv_gp_note(0x1000, 0x8000, False, "nope", False)
    monkeypatch.setattr(idautils, "Entries", lambda: iter([(0, 0x8000, "entry", False)]), raising=False)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda name: 0xFFFFFFFFFFFFFFFF, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda _attr: 0x8000, raising=False)
    mnems = {0x8000: "auipc", 0x8004: "addi"}
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: mnems.get(ea, "nop"), raising=False)
    monkeypatch.setattr(idc, "print_operand", lambda ea, index: "gp" if index == 0 else "1", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: 1 if index in (1, 2) else 0, raising=False)
    monkeypatch.setattr(idc, "next_head", lambda ea, _end=0xFFFFFFFFFFFFFFFF: ea + 4, raising=False)
    monkeypatch.setattr(arch, "_apply_riscv_gp", lambda _gp: (True, None, False, {"fixed": 1}), raising=False)
    found = arch.detect_riscv_gp()
    assert found["found"] is True
    assert found["gp_hex"] == "0x9001"

    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "nop", raising=False)
    missing = arch.detect_riscv_gp()
    assert missing["found"] is False
    assert "GP not found" in missing["note"]


def test_processor_detection_walks_ida_and_legacy_fallbacks(monkeypatch, arch):
    """The helper must work with both modern and pre-9.4 IDA APIs."""
    modern = importlib.import_module("ida_ida")
    legacy_idc = importlib.import_module("idc")
    monkeypatch.setattr(modern, "inf_get_procname", lambda: "ARM", raising=False)
    monkeypatch.setattr(modern, "inf_get_app_bitness", lambda: 64, raising=False)
    assert arch._proc_name_and_bitness() == ("arm", True)

    monkeypatch.setattr(modern, "inf_get_procname", lambda: (_ for _ in ()).throw(RuntimeError("old IDA")), raising=False)
    info = types.SimpleNamespace(procname="metapc", is_64bit=lambda: True)
    monkeypatch.setattr(arch, "idaapi", types.SimpleNamespace(get_inf_structure=lambda: info), raising=False)
    assert arch._proc_name_and_bitness() == ("metapc", True)

    info = types.SimpleNamespace(procname="mips")
    monkeypatch.setattr(arch, "idaapi", types.SimpleNamespace(get_inf_structure=lambda: info), raising=False)
    assert arch._proc_name_and_bitness() == ("mips", None)

    monkeypatch.setattr(arch, "idaapi", types.SimpleNamespace(get_inf_structure=lambda: (_ for _ in ()).throw(OSError("gone"))), raising=False)
    monkeypatch.setattr(legacy_idc, "get_inf_attr", lambda _attr: "riscv", raising=False)
    assert arch._proc_name_and_bitness() == ("riscv", None)

    monkeypatch.setattr(legacy_idc, "get_inf_attr", lambda _attr: None, raising=False)
    assert arch._proc_name_and_bitness() == ("", None)


def test_arch_helpers_cover_unknown_ida_and_extra_processor_spellings(monkeypatch, arch):
    monkeypatch.setattr(arch, "idaapi", None)
    assert arch.get_arch() == "unknown"
    monkeypatch.setattr(arch, "idaapi", object())
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: ("thumb-v8", None))
    assert arch.get_arch() == "arm"
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: ("rv32imac", None))
    assert arch.get_arch() == "riscv"
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: ("dspic33", None))
    assert arch.get_arch() == "pic24"
    monkeypatch.setattr(arch, "_proc_name_and_bitness", lambda: ("8051", None))
    assert arch.get_arch() == "mcs51"


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("x86", [], "unknown"),
        ("arm", ["sub"], "stack_alloc"),
        ("arm", ["stmdb"], "arm32_frame_setup"),
        ("mips", ["daddiu"], "mips_frame_setup"),
        ("mips", ["sd"], "mips_reg_save"),
        ("ppc", ["stdu"], "ppc_stack_alloc"),
        ("riscv", ["c.addi16sp"], "riscv_frame_setup"),
        ("riscv", ["c.sd"], "riscv_reg_save"),
    ],
)
def test_prologue_alternate_instruction_forms(arch, arch_name, mnems, expected):
    assert arch.get_prologue_pattern(mnems, arch_name) == expected


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("arm", ["ldm", "bx"], "arm_frame_teardown"),
        ("arm", ["pop", "pc"], "arm_pop_pc"),
        ("arm64", ["ldp"], "aarch64_frame_teardown"),
        ("arm64", ["b"], "tail_call"),
        ("mips", ["ld", "jr"], "mips_frame_teardown"),
        ("mips", ["j"], "tail_call"),
        ("ppc", ["mtlr", "blr"], "ppc_frame_teardown"),
        ("ppc", ["b"], "tail_call"),
        ("riscv", ["mret"], "riscv_simple_ret"),
        ("riscv", ["ld", "mret"], "riscv_frame_teardown"),
        ("riscv", ["c.j"], "tail_call"),
    ],
)
def test_epilogue_alternate_instruction_forms(arch, arch_name, mnems, expected):
    assert arch.get_epilogue_pattern(mnems, arch_name) == expected


@pytest.mark.parametrize(
    ("arch_name", "mnem", "disasm", "expected"),
    [
        ("arm", "bx", "bx r0", False),
        ("arm", "ldr", "ldr r0, [pc]", True),
        ("arm", "ldmia", "ldmia sp!, {r4, pc}", True),
        ("mips", "jr", "jr $31", True),
        ("mips", "jr", "jr $t9", False),
        ("riscv", "jalr", "jalr x0, x5, 0", False),
        ("riscv", "c.jr", "c.jr x1", True),
        ("riscv", "c.jr", "c.jr x5", False),
        ("sparc", "ret", "ret", True),
        ("unknown", "return", "return", True),
    ],
)
def test_return_classification_covers_operand_and_family_fallbacks(arch, arch_name, mnem, disasm, expected):
    assert arch.is_return_mnemonic(mnem, disasm, arch_name) is expected


def test_riscv_operand_parser_handles_empty_and_alias_forms(arch):
    assert arch._riscv_operand_parts("jalr", "jalr") == []
    assert arch._riscv_operand_parts("c.jr $ra", "c.jr") == ["$ra"]
    assert arch._classify_riscv_ret("jalr", "jalr x0, ra, 0") is True
    assert arch._classify_riscv_ret("jalr", "jalr x0, 0(x1)") is True
    assert arch._classify_riscv_ret("jalr", "jalr ra, 0(sp)") is False
    assert arch._classify_riscv_ret("c.jalr", "c.jalr ra") is False


def test_riscv_apply_cache_short_circuits_reanalysis(monkeypatch, arch):
    monkeypatch.setattr(arch, "_APPLIED_RISCV_GP", 0x1234)
    assert arch._apply_riscv_gp(0x1234) == (True, None, False, {})


def test_family_helpers_use_detected_architecture_when_unspecified(monkeypatch, arch):
    monkeypatch.setattr(arch, "get_arch", lambda: "arm64")
    assert arch.is_arm_family()
    assert not arch.is_x86_family()
    assert arch.get_return_register() == "x0"
    assert arch.get_stack_pointer_names() == {"sp"}
    assert "b" in arch.get_tail_call_mnemonics()


def test_riscv_gp_reference_repair_handles_stale_and_unmapped_targets(monkeypatch, arch):
    import ida_ida
    import ida_idp
    import ida_segment
    import ida_ua

    ida_xref = types.ModuleType("ida_xref")
    monkeypatch.setitem(__import__("sys").modules, "ida_xref", ida_xref)

    segment = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
    ops = [types.SimpleNamespace(type=2, reg=3, addr=0x20)] + [types.SimpleNamespace(type=0, reg=0, addr=0)] * 5
    insn = types.SimpleNamespace(ops=ops, get_canon_mnem=lambda: "sw")
    added = []
    removed = []
    monkeypatch.setattr(arch, "is_riscv_family", lambda: True)
    monkeypatch.setattr(ida_idp, "str2reg", lambda _name: 3, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: 32, raising=False)
    monkeypatch.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
    monkeypatch.setattr(ida_segment, "get_next_segment_ea", lambda _ea: idc.BADADDR, raising=False)
    monkeypatch.setattr(ida_segment, "getseg", lambda ea: segment if segment.start_ea <= ea < segment.end_ea else None, raising=False)
    monkeypatch.setattr(ida_ua, "insn_t", lambda: insn, raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, _ea: True, raising=False)
    monkeypatch.setattr(idc, "next_head", lambda *_args: idc.BADADDR, raising=False)
    monkeypatch.setattr(ida_xref, "get_first_dref_from", lambda *_args: 0x20, raising=False)
    monkeypatch.setattr(ida_xref, "get_next_dref_from", lambda *_args: idc.BADADDR, raising=False)
    monkeypatch.setattr(ida_xref, "del_dref", lambda ea, target: removed.append((ea, target)), raising=False)
    monkeypatch.setattr(ida_xref, "add_dref", lambda ea, target, kind: added.append((ea, target, kind)), raising=False)
    monkeypatch.setattr(ida_xref, "dr_W", 7, raising=False)
    monkeypatch.setattr(ida_xref, "dr_R", 8, raising=False)
    monkeypatch.setattr(idc, "BADADDR", 0xFFFFFFFFFFFFFFFF, raising=False)

    repaired = arch._riscv_gp_fix_refs(0x1000, old_gp=0x2000)
    assert repaired == {"fixed": 1, "skipped": 0}
    assert removed == [(0x1000, 0x20)]
    assert added == [(0x1000, 0x1020, 7)]

    ops[0].addr = 0x2000
    assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 1}
    monkeypatch.setattr(arch, "is_riscv_family", lambda: False)
    assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 0}


def test_riscv_gp_apply_directive_queues_reanalysis_and_detects_signed_lui(monkeypatch, arch):
    import ida_auto
    import ida_ida
    import ida_idp

    monkeypatch.setattr(arch, "_APPLIED_RISCV_GP", None)
    monkeypatch.setattr(arch, "_riscv_gp_fix_refs", lambda *_args, **_kwargs: {"fixed": 0, "skipped": 0})
    monkeypatch.setattr(idc, "set_processor_options", lambda _value: None, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda attr: 0x1000 if attr == idc.INF_MIN_EA else 0x2000, raising=False)
    monkeypatch.setattr(ida_auto, "plan_range", lambda *_args: None, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: 32, raising=False)
    queued = arch._apply_riscv_gp(0x1234)
    assert queued[:3] == (True, None, True)
    assert arch._apply_riscv_gp(0x1234) == (True, None, False, {})

    monkeypatch.setattr(arch, "_APPLIED_RISCV_GP", None)
    monkeypatch.delattr(idc, "set_processor_options", raising=False)
    monkeypatch.setattr(ida_idp, "process_config_directive", lambda _value: None, raising=False)
    monkeypatch.setattr(arch, "_riscv_gp_fix_refs", lambda *_args, **_kwargs: {"fixed": 0, "skipped": 1})
    applied = arch._apply_riscv_gp(0x1235)
    assert applied[0] is True and applied[2] is True

    monkeypatch.setattr(arch, "_apply_riscv_gp", lambda _value: (False, "no", False, {}))
    monkeypatch.setattr(idautils, "Entries", lambda: iter([(1, 0x1000, "entry", False)]), raising=False)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: idc.BADADDR, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda _attr: 0x1000, raising=False)
    mnems = {0x1000: "lui", 0x1004: "addi"}
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: mnems.get(ea, "nop"), raising=False)
    monkeypatch.setattr(idc, "print_operand", lambda _ea, index: "gp" if index == 0 else "0x80000", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: 0x80000 if index == 1 else 0xFFF, raising=False)
    monkeypatch.setattr(idc, "next_head", lambda ea, _end: ea + 4 if ea == 0x1000 else idc.BADADDR, raising=False)
    result = arch.detect_riscv_gp()
    assert result["found"] is True and result["gp"] == 0xFFFFFFFF7FFFFFFF
