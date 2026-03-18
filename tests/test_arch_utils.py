#!/usr/bin/env python3
"""
Tests for the multi-architecture helpers in arch_utils.py.
These tests run standalone without IDA Pro by mocking idaapi.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add source path so we can import arch_utils
_tools_dir = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "src", "ida_pro_mcp", "ida_mcp", "tools",
)
if _tools_dir not in sys.path:
    sys.path.insert(0, _tools_dir)

# We need to mock idaapi before importing arch_utils
_mock_idaapi = MagicMock()
sys.modules.setdefault("idaapi", _mock_idaapi)


class _FakeInfo:
    """Minimal mock of idaapi.get_inf_structure() return."""
    def __init__(self, procname="metapc", is_64=False):
        self.procname = procname
        self._is_64 = is_64

    def is_64bit(self):
        return self._is_64


def _setup_arch(procname, is_64=False):
    """Configure the idaapi mock for a specific architecture."""
    info = _FakeInfo(procname, is_64)
    _mock_idaapi.get_inf_structure.return_value = info
    _mock_idaapi.reset_mock(side_effect=True)
    _mock_idaapi.get_inf_structure.return_value = info


# Force-reload arch_utils each time to pick up the mock
import importlib
import arch_utils
importlib.reload(arch_utils)


class TestGetArch(unittest.TestCase):
    """Test architecture detection from processor name."""

    def test_x86(self):
        _setup_arch("metapc", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "x86")

    def test_x64(self):
        _setup_arch("metapc", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "x64")

    def test_arm32(self):
        _setup_arch("ARM", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "arm")

    def test_arm64(self):
        _setup_arch("ARM", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "arm64")

    def test_aarch64(self):
        _setup_arch("AARCH64", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "arm64")

    def test_mips32(self):
        _setup_arch("mipsl", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "mips")

    def test_mips64(self):
        _setup_arch("mipsl", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "mips64")

    def test_ppc32(self):
        _setup_arch("PPC", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "ppc")

    def test_ppc64(self):
        _setup_arch("PPC", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "ppc64")

    def test_riscv32(self):
        _setup_arch("riscv", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "riscv")

    def test_riscv64(self):
        _setup_arch("riscv", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "riscv64")

    def test_sparc(self):
        _setup_arch("sparc", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "sparc")

    def test_sparc64(self):
        _setup_arch("sparc", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "sparc64")

    def test_68k(self):
        _setup_arch("68K", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "68k")

    def test_sh4(self):
        _setup_arch("sh4", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "sh")

    def test_xtensa(self):
        _setup_arch("xtensa", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "xtensa")

    def test_80386(self):
        _setup_arch("80386", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "x86")

    def test_riscv_aliases(self):
        _setup_arch("risc-v", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "riscv")
        _setup_arch("rv32imac", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "riscv")
        _setup_arch("rv64gc", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "riscv64")

    def test_x86_aliases(self):
        _setup_arch("i686", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "x86")
        _setup_arch("amd64", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "x64")

    def test_arm_aliases(self):
        _setup_arch("thumb2", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "arm")
        _setup_arch("armv8-a", is_64=False)
        self.assertEqual(arch_utils.get_arch(), "arm")
        _setup_arch("armv8-a", is_64=True)
        self.assertEqual(arch_utils.get_arch(), "arm64")

    def test_embedded_arches(self):
        for proc, expected in (
            ("tricore", "tricore"),
            ("avr", "avr"),
            ("msp430", "msp430"),
            ("csky", "csky"),
            ("arc", "arc"),
            ("nios2", "nios2"),
            ("microblaze", "microblaze"),
            ("v850", "v850"),
            ("rl78", "rl78"),
            ("h8sx", "h8"),
            ("mcs51", "mcs51"),
            ("8051", "mcs51"),
            ("z80", "z80"),
            ("pic24", "pic24"),
            ("pic18", "pic18"),
        ):
            with self.subTest(proc=proc):
                _setup_arch(proc, is_64=False)
                self.assertEqual(arch_utils.get_arch(), expected)


class TestArchFamilies(unittest.TestCase):
    """Test architecture family detection."""

    def test_x86_family(self):
        self.assertTrue(arch_utils.is_x86_family("x86"))
        self.assertTrue(arch_utils.is_x86_family("x64"))
        self.assertFalse(arch_utils.is_x86_family("arm"))

    def test_arm_family(self):
        self.assertTrue(arch_utils.is_arm_family("arm"))
        self.assertTrue(arch_utils.is_arm_family("arm64"))
        self.assertFalse(arch_utils.is_arm_family("x86"))

    def test_mips_family(self):
        self.assertTrue(arch_utils.is_mips_family("mips"))
        self.assertTrue(arch_utils.is_mips_family("mips64"))
        self.assertFalse(arch_utils.is_mips_family("arm"))

    def test_ppc_family(self):
        self.assertTrue(arch_utils.is_ppc_family("ppc"))
        self.assertTrue(arch_utils.is_ppc_family("ppc64"))
        self.assertFalse(arch_utils.is_ppc_family("x86"))

    def test_riscv_family(self):
        self.assertTrue(arch_utils.is_riscv_family("riscv"))
        self.assertTrue(arch_utils.is_riscv_family("riscv64"))
        self.assertFalse(arch_utils.is_riscv_family("mips"))

    def test_sparc_family(self):
        self.assertTrue(arch_utils.is_sparc_family("sparc"))
        self.assertTrue(arch_utils.is_sparc_family("sparc64"))
        self.assertFalse(arch_utils.is_sparc_family("arm64"))


class TestReturnRegister(unittest.TestCase):
    """Test return register detection per architecture."""

    def test_x86(self):
        self.assertEqual(arch_utils.get_return_register("x86"), "eax")

    def test_x64(self):
        self.assertEqual(arch_utils.get_return_register("x64"), "rax")

    def test_arm(self):
        self.assertEqual(arch_utils.get_return_register("arm"), "r0")

    def test_arm64(self):
        self.assertEqual(arch_utils.get_return_register("arm64"), "x0")

    def test_mips(self):
        self.assertEqual(arch_utils.get_return_register("mips"), "v0")

    def test_ppc(self):
        self.assertEqual(arch_utils.get_return_register("ppc"), "r3")

    def test_riscv(self):
        self.assertEqual(arch_utils.get_return_register("riscv"), "a0")

    def test_sparc(self):
        self.assertEqual(arch_utils.get_return_register("sparc"), "o0")

    def test_68k(self):
        self.assertEqual(arch_utils.get_return_register("68k"), "d0")

    def test_sh(self):
        self.assertEqual(arch_utils.get_return_register("sh"), "r0")

    def test_unknown_default(self):
        self.assertEqual(arch_utils.get_return_register("unknown"), "r0")

    def test_embedded_return_registers(self):
        self.assertEqual(arch_utils.get_return_register("xtensa"), "a2")
        self.assertEqual(arch_utils.get_return_register("tricore"), "d2")
        self.assertEqual(arch_utils.get_return_register("avr"), "r24")
        self.assertEqual(arch_utils.get_return_register("msp430"), "r12")
        self.assertEqual(arch_utils.get_return_register("nios2"), "r2")
        self.assertEqual(arch_utils.get_return_register("microblaze"), "r3")
        self.assertEqual(arch_utils.get_return_register("mcs51"), "dpl")


class TestStackPointerNames(unittest.TestCase):
    """Test stack pointer register name sets."""

    def test_x86(self):
        self.assertEqual(arch_utils.get_stack_pointer_names("x86"), {"esp"})

    def test_x64(self):
        self.assertEqual(arch_utils.get_stack_pointer_names("x64"), {"rsp"})

    def test_arm(self):
        self.assertIn("sp", arch_utils.get_stack_pointer_names("arm"))

    def test_mips(self):
        sp_names = arch_utils.get_stack_pointer_names("mips")
        self.assertIn("sp", sp_names)
        self.assertIn("$sp", sp_names)

    def test_ppc(self):
        self.assertIn("r1", arch_utils.get_stack_pointer_names("ppc"))

    def test_riscv(self):
        sp_names = arch_utils.get_stack_pointer_names("riscv")
        self.assertIn("sp", sp_names)
        self.assertIn("x2", sp_names)

    def test_embedded_stack_pointers(self):
        self.assertIn("a1", arch_utils.get_stack_pointer_names("xtensa"))
        self.assertIn("a10", arch_utils.get_stack_pointer_names("tricore"))
        self.assertIn("r1", arch_utils.get_stack_pointer_names("msp430"))
        self.assertIn("r1", arch_utils.get_stack_pointer_names("microblaze"))
        self.assertIn("w15", arch_utils.get_stack_pointer_names("pic24"))


class TestCalleeSavedRegisters(unittest.TestCase):
    """Test callee-saved register sets."""

    def test_x86_contains_ebx(self):
        regs = arch_utils.get_callee_saved_registers("x86")
        self.assertIn("ebx", regs)
        self.assertIn("ebp", regs)

    def test_x64_contains_r12(self):
        regs = arch_utils.get_callee_saved_registers("x64")
        self.assertIn("r12", regs)
        self.assertIn("rbx", regs)

    def test_arm_contains_r4(self):
        regs = arch_utils.get_callee_saved_registers("arm")
        self.assertIn("r4", regs)
        self.assertIn("lr", regs)

    def test_arm64_contains_x19(self):
        regs = arch_utils.get_callee_saved_registers("arm64")
        self.assertIn("x19", regs)
        self.assertIn("x30", regs)

    def test_mips_contains_s0(self):
        regs = arch_utils.get_callee_saved_registers("mips")
        self.assertIn("s0", regs)
        self.assertIn("ra", regs)

    def test_ppc_contains_r14(self):
        regs = arch_utils.get_callee_saved_registers("ppc")
        self.assertIn("r14", regs)
        self.assertIn("r31", regs)

    def test_riscv_contains_s0(self):
        regs = arch_utils.get_callee_saved_registers("riscv")
        self.assertIn("s0", regs)
        self.assertIn("ra", regs)

    def test_unknown_returns_empty(self):
        self.assertEqual(arch_utils.get_callee_saved_registers("unknown"), set())

    def test_embedded_callee_saved_sets(self):
        self.assertIn("a15", arch_utils.get_callee_saved_registers("xtensa"))
        self.assertIn("d15", arch_utils.get_callee_saved_registers("tricore"))
        self.assertIn("r16", arch_utils.get_callee_saved_registers("avr"))
        self.assertIn("r10", arch_utils.get_callee_saved_registers("msp430"))
        self.assertIn("r23", arch_utils.get_callee_saved_registers("nios2"))
        self.assertIn("r31", arch_utils.get_callee_saved_registers("microblaze"))


class TestIsReturnMnemonic(unittest.TestCase):
    """Test return mnemonic detection across architectures."""

    def test_x86_ret(self):
        self.assertTrue(arch_utils.is_return_mnemonic("ret", "", "x86"))
        self.assertTrue(arch_utils.is_return_mnemonic("retn", "", "x86"))
        self.assertFalse(arch_utils.is_return_mnemonic("call", "", "x86"))

    def test_arm_bx_lr(self):
        self.assertTrue(arch_utils.is_return_mnemonic("bx", "bx lr", "arm"))
        self.assertFalse(arch_utils.is_return_mnemonic("bx", "bx r3", "arm"))

    def test_arm_pop_pc(self):
        self.assertTrue(arch_utils.is_return_mnemonic("pop", "pop {r4, pc}", "arm"))
        self.assertFalse(arch_utils.is_return_mnemonic("pop", "pop {r4, r5}", "arm"))

    def test_mips_jr_ra(self):
        self.assertTrue(arch_utils.is_return_mnemonic("jr", "jr $ra", "mips"))
        self.assertFalse(arch_utils.is_return_mnemonic("jr", "jr $t0", "mips"))

    def test_ppc_blr(self):
        self.assertTrue(arch_utils.is_return_mnemonic("blr", "", "ppc"))
        self.assertFalse(arch_utils.is_return_mnemonic("bl", "", "ppc"))

    def test_riscv_ret(self):
        self.assertTrue(arch_utils.is_return_mnemonic("ret", "", "riscv"))
        self.assertTrue(arch_utils.is_return_mnemonic("jalr", "jalr x0, ra, 0", "riscv"))
        self.assertFalse(arch_utils.is_return_mnemonic("jal", "", "riscv"))

    def test_sparc_ret(self):
        self.assertTrue(arch_utils.is_return_mnemonic("ret", "", "sparc"))
        self.assertTrue(arch_utils.is_return_mnemonic("retl", "", "sparc"))

    def test_generic_ret(self):
        self.assertTrue(arch_utils.is_return_mnemonic("ret", "", "unknown"))
        self.assertTrue(arch_utils.is_return_mnemonic("rts", "", "unknown"))


class TestIsSyscallMnemonic(unittest.TestCase):
    """Test syscall mnemonic detection."""

    def test_x86_syscall(self):
        self.assertTrue(arch_utils.is_syscall_mnemonic("syscall"))
        self.assertTrue(arch_utils.is_syscall_mnemonic("sysenter"))
        self.assertTrue(arch_utils.is_syscall_mnemonic("int"))

    def test_arm_svc(self):
        self.assertTrue(arch_utils.is_syscall_mnemonic("svc"))
        self.assertTrue(arch_utils.is_syscall_mnemonic("swi"))

    def test_mips_syscall(self):
        self.assertTrue(arch_utils.is_syscall_mnemonic("syscall"))

    def test_ppc_sc(self):
        self.assertTrue(arch_utils.is_syscall_mnemonic("sc"))

    def test_riscv_ecall(self):
        self.assertTrue(arch_utils.is_syscall_mnemonic("ecall"))


class TestIsCallMnemonic(unittest.TestCase):
    """Test call mnemonic detection."""

    def test_x86_call(self):
        self.assertTrue(arch_utils.is_call_mnemonic("call"))

    def test_arm_bl(self):
        self.assertTrue(arch_utils.is_call_mnemonic("bl"))
        self.assertTrue(arch_utils.is_call_mnemonic("blx"))

    def test_mips_jal(self):
        self.assertTrue(arch_utils.is_call_mnemonic("jal"))
        self.assertTrue(arch_utils.is_call_mnemonic("jalr"))

    def test_not_call(self):
        self.assertFalse(arch_utils.is_call_mnemonic("mov"))
        self.assertFalse(arch_utils.is_call_mnemonic("ret"))


class TestProloguePattern(unittest.TestCase):
    """Test prologue pattern classification."""

    def test_x86_standard(self):
        pat = arch_utils.get_prologue_pattern(["push", "mov", "sub"], "x86")
        self.assertEqual(pat, "standard_frame_setup")

    def test_x86_cet(self):
        pat = arch_utils.get_prologue_pattern(["endbr64", "push", "mov"], "x64")
        self.assertEqual(pat, "cet_enabled")

    def test_arm64_stp(self):
        pat = arch_utils.get_prologue_pattern(["stp", "mov", "sub"], "arm64")
        self.assertEqual(pat, "aarch64_frame_setup")

    def test_arm32_push(self):
        pat = arch_utils.get_prologue_pattern(["stmdb", "mov", "sub"], "arm")
        self.assertEqual(pat, "arm32_frame_setup")

    def test_mips_frame(self):
        pat = arch_utils.get_prologue_pattern(["addiu", "sw", "move"], "mips")
        self.assertEqual(pat, "mips_frame_setup")

    def test_ppc_frame(self):
        pat = arch_utils.get_prologue_pattern(["mflr", "stwu", "stw"], "ppc")
        self.assertEqual(pat, "ppc_frame_setup")

    def test_riscv_frame(self):
        pat = arch_utils.get_prologue_pattern(["addi", "sw", "mv"], "riscv")
        self.assertEqual(pat, "riscv_frame_setup")

    def test_empty(self):
        pat = arch_utils.get_prologue_pattern([], "x86")
        self.assertEqual(pat, "unknown")


class TestEpiloguePattern(unittest.TestCase):
    """Test epilogue pattern classification."""

    def test_x86_standard(self):
        pat = arch_utils.get_epilogue_pattern(["pop", "leave", "ret"], "x86")
        self.assertEqual(pat, "standard_frame_teardown")

    def test_x86_simple_ret(self):
        pat = arch_utils.get_epilogue_pattern(["nop", "ret"], "x86")
        self.assertEqual(pat, "simple_ret")

    def test_arm_bx_lr(self):
        pat = arch_utils.get_epilogue_pattern(["ldp", "bx"], "arm")
        self.assertEqual(pat, "arm_frame_teardown")

    def test_mips_jr_ra(self):
        pat = arch_utils.get_epilogue_pattern(["lw", "jr", "nop"], "mips")
        self.assertEqual(pat, "mips_frame_teardown")

    def test_ppc_blr(self):
        pat = arch_utils.get_epilogue_pattern(["lwz", "mtlr", "blr"], "ppc")
        self.assertEqual(pat, "ppc_frame_teardown")

    def test_riscv_ret(self):
        pat = arch_utils.get_epilogue_pattern(["lw", "addi", "ret"], "riscv")
        self.assertEqual(pat, "riscv_frame_teardown")


class TestTailCallMnemonics(unittest.TestCase):
    """Test tail call mnemonic sets."""

    def test_x86(self):
        self.assertIn("jmp", arch_utils.get_tail_call_mnemonics("x86"))

    def test_arm(self):
        self.assertIn("b", arch_utils.get_tail_call_mnemonics("arm"))

    def test_mips(self):
        tc = arch_utils.get_tail_call_mnemonics("mips")
        self.assertIn("j", tc)
        self.assertIn("b", tc)

    def test_riscv(self):
        tc = arch_utils.get_tail_call_mnemonics("riscv")
        self.assertIn("j", tc)

    def test_ppc(self):
        tc = arch_utils.get_tail_call_mnemonics("ppc")
        self.assertIn("b", tc)


class TestConstantSets(unittest.TestCase):
    """Test that the constant instruction sets have expected members."""

    def test_return_mnemonics(self):
        self.assertIn("ret", arch_utils.RETURN_MNEMONICS)
        self.assertIn("bx", arch_utils.RETURN_MNEMONICS)
        self.assertIn("jr", arch_utils.RETURN_MNEMONICS)
        self.assertIn("blr", arch_utils.RETURN_MNEMONICS)
        self.assertIn("rts", arch_utils.RETURN_MNEMONICS)
        self.assertIn("retw", arch_utils.RETURN_MNEMONICS)
        self.assertIn("reti", arch_utils.RETURN_MNEMONICS)
        self.assertIn("retfie", arch_utils.RETURN_MNEMONICS)

    def test_call_mnemonics(self):
        self.assertIn("call", arch_utils.CALL_MNEMONICS)
        self.assertIn("bl", arch_utils.CALL_MNEMONICS)
        self.assertIn("jal", arch_utils.CALL_MNEMONICS)
        self.assertIn("call0", arch_utils.CALL_MNEMONICS)
        self.assertIn("rcall", arch_utils.CALL_MNEMONICS)

    def test_syscall_mnemonics(self):
        self.assertIn("syscall", arch_utils.SYSCALL_MNEMONICS)
        self.assertIn("svc", arch_utils.SYSCALL_MNEMONICS)
        self.assertIn("ecall", arch_utils.SYSCALL_MNEMONICS)
        self.assertIn("sc", arch_utils.SYSCALL_MNEMONICS)
        self.assertIn("swi", arch_utils.SYSCALL_MNEMONICS)

    def test_conditional_branches(self):
        self.assertIn("je", arch_utils.CONDITIONAL_BRANCH_MNEMONICS)
        self.assertIn("beq", arch_utils.CONDITIONAL_BRANCH_MNEMONICS)
        self.assertIn("bne", arch_utils.CONDITIONAL_BRANCH_MNEMONICS)
        self.assertIn("beqz", arch_utils.CONDITIONAL_BRANCH_MNEMONICS)
        self.assertIn("bltu", arch_utils.CONDITIONAL_BRANCH_MNEMONICS)

    def test_mov_mnemonics(self):
        self.assertIn("mov", arch_utils.MOV_MNEMONICS)
        self.assertIn("li", arch_utils.MOV_MNEMONICS)
        self.assertIn("mv", arch_utils.MOV_MNEMONICS)

    def test_xor_mnemonics(self):
        self.assertIn("xor", arch_utils.XOR_MNEMONICS)
        self.assertIn("eor", arch_utils.XOR_MNEMONICS)
        self.assertIn("xori", arch_utils.XOR_MNEMONICS)

    def test_comparison_mnemonics(self):
        self.assertIn("test", arch_utils.COMPARISON_MNEMONICS)
        self.assertIn("cmp", arch_utils.COMPARISON_MNEMONICS)
        self.assertIn("tst", arch_utils.COMPARISON_MNEMONICS)
        self.assertIn("cbz", arch_utils.COMPARISON_MNEMONICS)

    def test_arithmetic_mnemonics(self):
        self.assertIn("add", arch_utils.ARITHMETIC_MNEMONICS)
        self.assertIn("mul", arch_utils.ARITHMETIC_MNEMONICS)
        self.assertIn("slli", arch_utils.ARITHMETIC_MNEMONICS)

    def test_interesting_instructions(self):
        ii = arch_utils.INTERESTING_INSTRUCTIONS
        self.assertEqual(ii["syscall"], "system_call")
        self.assertEqual(ii["svc"], "system_call")
        self.assertEqual(ii["ecall"], "system_call")
        self.assertEqual(ii["ebreak"], "breakpoint")
        self.assertEqual(ii["bkpt"], "breakpoint")


if __name__ == "__main__":
    unittest.main()
