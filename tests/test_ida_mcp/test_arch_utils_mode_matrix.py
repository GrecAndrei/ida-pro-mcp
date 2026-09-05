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


def test_arch_utils_edge_branches(monkeypatch, arch):
    import builtins
    import sys

    import ida_auto
    import ida_ida
    import ida_idp
    import ida_segment
    import ida_ua
    import idc

    ida_xref = types.ModuleType("ida_xref")
    ida_xref.dr_W = 7
    ida_xref.dr_R = 8
    monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)

    # 1. Lines 64-65, 74-75: _proc_name_and_bitness exception fallbacks
    class FakeInfo:
        procname = "metapc"

        def is_64bit(self):
            raise RuntimeError("bitness failure")

    fake_api = types.SimpleNamespace(get_inf_structure=FakeInfo)
    with monkeypatch.context() as m:
        m.setattr(arch, "idaapi", fake_api)
        m.setattr(ida_ida, "inf_get_procname", lambda: None, raising=False)
        proc, bitness = arch._proc_name_and_bitness()
        assert proc == "metapc" and bitness is None

    with monkeypatch.context() as m:
        m.setattr(arch, "idaapi", types.SimpleNamespace(get_inf_structure=lambda: None))
        m.setattr(ida_ida, "inf_get_procname", lambda: None, raising=False)
        m.setattr(idc, "get_inf_attr", lambda _attr: (_ for _ in ()).throw(RuntimeError("idc fail")), raising=False)
        proc, bitness = arch._proc_name_and_bitness()
        assert proc == "" and bitness is None

    # 2. Lines 201, 208, 222: Family checks with arch=None
    with monkeypatch.context() as m:
        m.setattr(arch, "get_arch", lambda: "mips")
        assert arch.is_mips_family() is True
        m.setattr(arch, "get_arch", lambda: "ppc")
        assert arch.is_ppc_family() is True
        m.setattr(arch, "get_arch", lambda: "sparc")
        assert arch.is_sparc_family() is True

    # 3. Line 575: Callee-saved registers with arch=None
    with monkeypatch.context() as m:
        m.setattr(arch, "get_arch", lambda: "x86")
        assert "ebp" in arch.get_callee_saved_registers()

    # 4. Lines 663, 675: _classify_riscv_ret edge cases
    assert arch._classify_riscv_ret("jalr", "jalr ra") is False
    assert arch._classify_riscv_ret("c.jr", "c.jr") is False

    # 5. Lines 688, 694, 702, 718, 722: is_return_mnemonic branches
    with monkeypatch.context() as m:
        m.setattr(arch, "get_arch", lambda: "x64")
        assert arch.is_return_mnemonic("ret") is True
    assert arch.is_return_mnemonic("nop", arch="x86") is False
    assert arch.is_return_mnemonic("ldp", disasm_lower="ldp x29, pc, [sp]", arch="arm") is True
    assert arch.is_return_mnemonic("mret", arch="riscv") is True
    assert arch.is_return_mnemonic("sret", arch="riscv") is True
    assert arch.is_return_mnemonic("nop", arch="sparc") is False

    # 6. Lines 731, 738, 748, 802: is_call/syscall/prologue/epilogue with arch=None
    with monkeypatch.context() as m:
        m.setattr(arch, "get_arch", lambda: "x64")
        assert arch.is_call_mnemonic("call") is True
        assert arch.is_syscall_mnemonic("syscall") is True
        assert arch.get_prologue_pattern(["push", "mov"]) == "standard_frame_setup"
        assert arch.get_epilogue_pattern(["pop", "ret"]) == "standard_frame_teardown"

    # 7. Lines 926-927, 929, 933-934, 948-949, 954-955, 957, 975, 979, 994-995, 1001-1002, 1007-1008, 1012-1013: _riscv_gp_fix_refs branches
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        m.setattr(ida_idp, "str2reg", lambda _name: (_ for _ in ()).throw(RuntimeError("no reg")), raising=False)
        m.setattr(ida_ida, "inf_get_app_bitness", lambda: (_ for _ in ()).throw(RuntimeError("no bitness")), raising=False)
        m.delattr(ida_segment, "get_first_segment_ea", raising=False)
        m.setattr(idc, "get_first_seg", lambda: 0x1000, raising=False)

        class BrokenSeg:
            start_ea = 0x1000
            end_ea = 0x1010

        # test getseg returning None to break
        m.setattr(ida_segment, "getseg", lambda ea: None if ea == 0x1000 else BrokenSeg(), raising=False)
        res_none = arch._riscv_gp_fix_refs(0x1000)
        assert res_none == {"fixed": 0, "skipped": 0}

    # test seen_targets, disp 0, and exception in decode
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: seg if ea == 0x1000 else None, raising=False)
        m.delattr(ida_segment, "get_next_segment_ea", raising=False)

        # instruction with two ops targeting the same address, then disp 0 with GP 0
        op1 = types.SimpleNamespace(type=2, reg=3, addr=0x20)
        op2 = types.SimpleNamespace(type=2, reg=3, addr=0x20)
        op3 = types.SimpleNamespace(type=2, reg=3, addr=0)
        dummy_ops = [op1, op2, op3, types.SimpleNamespace(type=0, reg=0, addr=0), types.SimpleNamespace(type=0, reg=0, addr=0), types.SimpleNamespace(type=0, reg=0, addr=0)]

        class TestInsn:
            ops = dummy_ops
            def get_canon_mnem(self):
                return "lw"

        m.setattr(ida_ua, "insn_t", TestInsn, raising=False)
        m.setattr(ida_ua, "decode_insn", lambda insn, ea: True, raising=False)
        m.setattr(ida_xref, "get_first_dref_from", lambda ea: 0x20, raising=False)
        m.setattr(ida_xref, "get_next_dref_from", lambda ea, r: idc.BADADDR, raising=False)
        m.setattr(ida_xref, "del_dref", lambda ea, target: (_ for _ in ()).throw(RuntimeError("del fail")), raising=False)
        m.setattr(ida_xref, "add_dref", lambda ea, target, dtp: None, raising=False)
        m.setattr(idc, "next_head", lambda ea: 0x1008, raising=False)

        res_fixed = arch._riscv_gp_fix_refs(0, old_gp=0x1000)
        assert res_fixed["fixed"] == 0

    # 8. Lines 1046-1047, 1061-1062, 1071-1072, 1083-1084, 1091-1092, 1109-1110, 1112-1113: _apply_riscv_gp branches
    with monkeypatch.context() as m:
        orig_imp = builtins.__import__
        def fail_imp(name, *args, **kwargs):
            if name == "idaapi":
                raise ImportError("no idaapi")
            return orig_imp(name, *args, **kwargs)
        m.setattr(builtins, "__import__", fail_imp)
        m.setattr(arch, "_APPLIED_RISCV_GP", None)
        applied, err, rean, refs = arch._apply_riscv_gp(0x5555)
        assert applied is False and "IDA not available" in err

    with monkeypatch.context() as m:
        m.setattr(arch, "_APPLIED_RISCV_GP", None)
        m.setattr(idc, "set_processor_options", lambda _val: (_ for _ in ()).throw(RuntimeError("proc option error")), raising=False)
        m.setattr(arch, "_riscv_gp_fix_refs", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("fix ref error")))
        m.setattr(arch.idaapi, "netnode", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("netnode error")))
        applied, err, rean, refs = arch._apply_riscv_gp(0x6666)
        assert applied is False and "fix ref error" in err

    with monkeypatch.context() as m:
        m.setattr(arch, "_APPLIED_RISCV_GP", None)
        m.setattr(idc, "set_processor_options", lambda _val: None, raising=False)
        m.setattr(arch, "_riscv_gp_fix_refs", lambda *_a, **_k: {"fixed": 0})
        m.delattr(ida_auto, "plan_range", raising=False)
        marked = []
        m.setattr(ida_auto, "auto_mark_range", lambda s, e, mnem: marked.append((s, e)), raising=False)
        m.setattr(ida_auto, "AU_FINAL", 0, raising=False)
        applied, err, rean, refs = arch._apply_riscv_gp(0x7777)
        assert applied is True and rean is True and len(marked) == 1

    # 9. Lines 1129, 1157-1158: _riscv_gp_note and set_riscv_gp
    note = arch._riscv_gp_note(0x1000, 0x200, True, None, False, {"fixed": 2, "skipped": 3})
    assert "3 unmapped targets skipped" in note
    set_res = arch.set_riscv_gp(0x8888)
    assert set_res["ok"] is True and set_res["gp"] == 0x8888

    # 10. Lines 1190-1191, 1200-1201, 1205, 1214, 1225-1226, 1249, 1285-1287, 1296-1297: detect_riscv_gp branches
    with monkeypatch.context() as m:
        orig_imp = builtins.__import__
        def no_idautils(name, *args, **kwargs):
            if name == "idautils":
                raise ImportError("no idautils")
            return orig_imp(name, *args, **kwargs)
        m.setattr(builtins, "__import__", no_idautils)
        assert arch.detect_riscv_gp()["found"] is False

    with monkeypatch.context() as m:
        m.setattr(idautils, "Entries", lambda: (_ for _ in ()).throw(RuntimeError("no entries")), raising=False)
        m.setattr(idc, "get_name_ea_simple", lambda sym: 0x1000 if sym in ("_start", "reset_handler") else idc.BADADDR, raising=False)
        m.setattr(idc, "get_inf_attr", lambda _attr: (_ for _ in ()).throw(RuntimeError("inf fail")), raising=False)
        m.setattr(idc, "print_insn_mnem", lambda ea: "auipc" if ea == 0x1000 else ("addi" if ea == 0x1004 else "nop"), raising=False)
        m.setattr(idc, "print_operand", lambda ea, idx: "gp" if idx == 0 else "", raising=False)
        # negative auipc immediate (bit 19 set: 0x80000)
        m.setattr(idc, "get_operand_value", lambda ea, idx: 0x80000 if ea == 0x1000 else 0x10, raising=False)
        m.setattr(idc, "next_head", lambda ea, _b: ea + 4 if ea == 0x1000 else idc.BADADDR, raising=False)
        res_auipc = arch.detect_riscv_gp()
        assert res_auipc["found"] is True

    # 11. Lines 760, 769, 776, 783, 791: Prologue pattern 'unknown' for all archs
    for fam in ("x86", "arm", "mips", "ppc", "riscv"):
        assert arch.get_prologue_pattern(["nop"], arch=fam) == "unknown"

    # 12. Lines 804, 816, 829, 838, 847, 859: Epilogue pattern 'unknown' for all archs
    assert arch.get_epilogue_pattern([], arch="x86") == "unknown"
    for fam in ("x86", "arm", "mips", "ppc", "riscv"):
        assert arch.get_epilogue_pattern(["nop"], arch=fam) == "unknown"

    # 13. Lines 920-921: _riscv_gp_fix_refs import failure
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        orig_imp = builtins.__import__
        def fail_xref(name, *args, **kwargs):
            if name == "ida_xref":
                raise ImportError("no ida_xref")
            return orig_imp(name, *args, **kwargs)
        m.setattr(builtins, "__import__", fail_xref)
        assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 0}

    # 14a. Lines 954-955: getseg raises AttributeError
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: (_ for _ in ()).throw(AttributeError("no seg")), raising=False)
        assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 0}

    # 14b. Lines 929, 965-966, 975, 979, 986, 994-995: _riscv_gp_fix_refs detail paths
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        m.setattr(ida_idp, "str2reg", lambda _name: 0, raising=False)  # triggers gp_reg = 3 fallback (line 929)
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: seg, raising=False)
        m.delattr(ida_segment, "get_next_segment_ea", raising=False)

        decode_calls = 0
        def mock_decode(insn, ea):
            nonlocal decode_calls
            decode_calls += 1
            return decode_calls > 1

        op_zero = types.SimpleNamespace(type=2, reg=3, addr=0)
        insn_zero = types.SimpleNamespace(ops=[op_zero] + [types.SimpleNamespace(type=0, reg=0, addr=0)] * 5, get_canon_mnem=lambda: "lw")
        m.setattr(ida_ua, "insn_t", lambda: insn_zero, raising=False)
        m.setattr(ida_ua, "decode_insn", mock_decode, raising=False)
        m.setattr(ida_xref, "get_first_dref_from", lambda ea: idc.BADADDR, raising=False)
        m.setattr(idc, "next_head", lambda ea: 0x1004 if ea == 0x1000 else 0x1010, raising=False)

        # gp=0, addr=0 triggers line 979 (target == raw and not raw)
        res_zero = arch._riscv_gp_fix_refs(0)
        assert res_zero["fixed"] == 0

    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        m.setattr(ida_idp, "str2reg", lambda _name: 3, raising=False)
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: seg, raising=False)
        m.delattr(ida_segment, "get_next_segment_ea", raising=False)

        op1 = types.SimpleNamespace(type=2, reg=3, addr=0x20)
        op2 = types.SimpleNamespace(type=2, reg=3, addr=0x20)
        op3 = types.SimpleNamespace(type=2, reg=3, addr=0x40)
        dummy_ops = [op1, op2, op3, types.SimpleNamespace(type=0, reg=0, addr=0), types.SimpleNamespace(type=0, reg=0, addr=0), types.SimpleNamespace(type=0, reg=0, addr=0)]

        dummy_insn = types.SimpleNamespace(ops=dummy_ops, get_canon_mnem=lambda: "lw")
        m.setattr(ida_ua, "insn_t", lambda: dummy_insn, raising=False)
        m.setattr(ida_ua, "decode_insn", lambda insn, ea: True, raising=False)

        # target 0x1020 is in existing (line 986)
        # raw 0x40 is in existing and != target (line 994-995)
        m.setattr(ida_xref, "get_first_dref_from", lambda ea: 0x1020, raising=False)
        m.setattr(ida_xref, "get_next_dref_from", lambda ea, r: 0x40 if r == 0x1020 else idc.BADADDR, raising=False)
        m.setattr(ida_xref, "del_dref", lambda ea, target: (_ for _ in ()).throw(RuntimeError("del fail")), raising=False)
        m.setattr(ida_xref, "add_dref", lambda ea, target, dtp: None, raising=False)
        m.setattr(idc, "next_head", lambda ea: 0x1008, raising=False)

        res_detail = arch._riscv_gp_fix_refs(0x1000)
        assert res_detail["fixed"] == 1

    # 14c. Lines 1007-1008: decode loop exception
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: seg, raising=False)
        m.delattr(ida_segment, "get_next_segment_ea", raising=False)
        m.setattr(ida_ua, "insn_t", types.SimpleNamespace, raising=False)
        m.setattr(ida_ua, "decode_insn", lambda _i, _ea: (_ for _ in ()).throw(RuntimeError("decode fail")), raising=False)
        m.setattr(idc, "next_head", lambda ea: 0x1004, raising=False)
        assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 0}

    # 15. Lines 999-1002: old_gp stale deletion in _riscv_gp_fix_refs with exception
    with monkeypatch.context() as m:
        m.setattr(arch, "is_riscv_family", lambda: True)
        m.setattr(ida_idp, "str2reg", lambda _name: 3, raising=False)
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
        m.setattr(ida_segment, "get_first_segment_ea", lambda: 0x1000, raising=False)
        m.setattr(ida_segment, "getseg", lambda ea: seg, raising=False)
        m.delattr(ida_segment, "get_next_segment_ea", raising=False)
        op = types.SimpleNamespace(type=2, reg=3, addr=0x20)
        dummy_insn = types.SimpleNamespace(ops=[op] + [types.SimpleNamespace(type=0, reg=0, addr=0)] * 5, get_canon_mnem=lambda: "lw")
        m.setattr(ida_ua, "insn_t", lambda: dummy_insn, raising=False)
        m.setattr(ida_ua, "decode_insn", lambda insn, ea: True, raising=False)

        # existing refs include the stale old_gp target (0x2000 + 0x20 = 0x2020)
        m.setattr(ida_xref, "get_first_dref_from", lambda ea: 0x2020, raising=False)
        m.setattr(ida_xref, "get_next_dref_from", lambda ea, r: idc.BADADDR, raising=False)
        # del_dref raises to hit lines 1001-1002
        m.setattr(ida_xref, "del_dref", lambda ea, target: (_ for _ in ()).throw(RuntimeError("del stale fail")), raising=False)
        m.setattr(ida_xref, "add_dref", lambda ea, target, dtp: None, raising=False)
        m.setattr(idc, "next_head", lambda ea: 0x1004, raising=False)

        res_stale = arch._riscv_gp_fix_refs(0x1000, old_gp=0x2000)
        assert res_stale["fixed"] == 1

    # 16. Lines 1061-1062, 1081, 1091-1092: _apply_riscv_gp import, clear error, and netnode failure
    with monkeypatch.context() as m:
        orig_imp = builtins.__import__
        def fail_idp(name, *args, **kwargs):
            if name == "ida_idp":
                raise ImportError("no ida_idp")
            return orig_imp(name, *args, **kwargs)
        m.setattr(builtins, "__import__", fail_idp)
        m.setattr(arch, "_APPLIED_RISCV_GP", None)
        # set_processor_options raises so apply_error is set, then cleared at line 1081
        m.setattr(idc, "set_processor_options", lambda _val: (_ for _ in ()).throw(RuntimeError("directive fail")), raising=False)
        m.setattr(arch, "_riscv_gp_fix_refs", lambda *_a, **_k: {"fixed": 0})
        applied, err, rean, refs = arch._apply_riscv_gp(0x9999)
        assert applied is True and err is None

    with monkeypatch.context() as m:
        import idaapi as _idaapi
        m.setattr(arch, "_APPLIED_RISCV_GP", None)
        m.setattr(arch, "_riscv_gp_fix_refs", lambda *_a, **_k: {"fixed": 1})
        m.setattr(_idaapi, "netnode", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("netnode boom")))
        applied, err, rean, refs = arch._apply_riscv_gp(0xAAAA)
        assert applied is True

    # 17. Lines 1206-1207, 1215-1216, 1285-1287, 1295-1297: detect_riscv_gp symbol & loop error paths
    with monkeypatch.context() as m:
        m.setattr(idautils, "Entries", lambda: iter([(1, 0x1000)]), raising=False)
        m.setattr(idc, "get_name_ea_simple", lambda sym: (_ for _ in ()).throw(RuntimeError("sym fail")), raising=False)
        m.setattr(idc, "get_inf_attr", lambda _attr: None, raising=False)
        m.setattr(idc, "print_insn_mnem", lambda ea: (_ for _ in ()).throw(RuntimeError("insn fail")), raising=False)
        res_fail = arch.detect_riscv_gp()
        assert res_fail["found"] is False

    with monkeypatch.context() as m:
        m.setattr(idautils, "Entries", lambda: iter([(1, 0x1000)]), raising=False)
        m.setattr(idc, "get_name_ea_simple", lambda sym: idc.BADADDR, raising=False)
        m.setattr(idc, "get_inf_attr", lambda _attr: (_ for _ in ()).throw(RuntimeError("inf fail")), raising=False)
        m.setattr(idc, "print_insn_mnem", lambda ea: "nop", raising=False)
        m.setattr(idc, "next_head", lambda ea, _b: idc.BADADDR, raising=False)
        res_badaddr = arch.detect_riscv_gp()
        assert res_badaddr["found"] is False
