"""
Multi-architecture detection and helpers for IDA MCP tools.

Provides normalized architecture detection and architecture-specific
instruction sets for use across all tool modules. Supports:
  x86/x64, ARM/AArch64, RISC-V, MIPS, PowerPC, SPARC, SuperH, 68k, s390,
  Xtensa, TriCore, AVR, MSP430, C-SKY, ARC, Nios II, MicroBlaze, V850,
  RL78, H8, 8051/MCS-51, Z80 and PIC families.
"""

try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]

_ARCH_TOKEN_STRIP_TABLE = str.maketrans("", "", "-_ ")


def _is_64bit_from_proc(proc):
    """Best-effort bitness inference from processor names."""
    p = proc.lower()
    has_64_marker = any(marker in p for marker in (
        "64", "x64", "amd64", "x86_64", "aarch64", "arm64",
        "mips64", "ppc64", "powerpc64", "sparc64", "riscv64", "rv64",
    ))
    has_32_marker = any(marker in p for marker in (
        "32", "i386", "i486", "i586", "i686", "ia32", "arm32", "rv32", "riscv32",
    ))
    if has_64_marker and not has_32_marker:
        return True
    if has_32_marker and not has_64_marker:
        return False
    return None


# ============================================================================
# Architecture detection
# ============================================================================

def get_arch():
    """Return normalized architecture string.

    Returns one of:
        'x86', 'x64', 'arm', 'arm64',
        'mips', 'mips64', 'ppc', 'ppc64',
        'riscv', 'riscv64', 'sparc', 'sparc64',
        'sh', '68k', 's390',
        'xtensa', 'tricore', 'avr', 'msp430', 'csky',
        'arc', 'nios2', 'microblaze', 'v850', 'rl78',
        'h8', 'mcs51', 'z80', 'pic24', 'pic18',
        'unknown'
    """
    if idaapi is None:
        return "unknown"
    info = idaapi.get_inf_structure() if hasattr(idaapi, 'get_inf_structure') else None
    if info is None:
        return "unknown"
    proc = info.procname.lower().strip() if info.procname else ""
    normalized_proc = proc.translate(_ARCH_TOKEN_STRIP_TABLE)
    if hasattr(info, 'is_64bit'):
        is_64 = info.is_64bit()
    else:
        inferred_is_64 = _is_64bit_from_proc(proc)
        is_64 = inferred_is_64 if inferred_is_64 is not None else False

    # x86 family
    if (
        proc.startswith(("metapc", "i386", "i486", "i586", "i686")) or "x86" in proc or "amd64" in proc or "x64" in proc or "x86_64" in proc or "ia32" in proc or "80386" in proc or "80486" in proc
    ):
        return "x64" if is_64 else "x86"
    # ARM family
    if (
        proc.startswith(("arm", "aarch")) or normalized_proc.startswith(("thumb", "armv"))
    ):
        return "arm64" if is_64 else "arm"
    # RISC-V
    if "riscv" in proc or normalized_proc.startswith(("riscv", "rv")):
        return "riscv64" if is_64 else "riscv"
    # MIPS
    if proc.startswith("mips") or "mips" in proc:
        return "mips64" if is_64 else "mips"
    # PowerPC
    if proc.startswith("ppc") or "powerpc" in proc:
        return "ppc64" if is_64 else "ppc"
    # SPARC
    if "sparc" in proc:
        return "sparc64" if is_64 else "sparc"
    # SuperH (SH-4, etc.)
    if proc.startswith("sh") and proc[2:3].isdigit():
        return "sh"
    # Motorola 68k
    if "68k" in proc or proc.startswith("68") or "680x0" in proc:
        return "68k"
    # IBM S/390
    if "s390" in proc or proc.startswith("s390"):
        return "s390"
    # Xtensa (common in ESP32 and IoT firmware)
    if "xtensa" in proc or normalized_proc.startswith("xtensa"):
        return "xtensa"
    # Infineon TriCore
    if "tricore" in proc or normalized_proc.startswith("tricore") or proc.startswith("tc1"):
        return "tricore"
    # AVR
    if proc.startswith("avr") or "atmega" in proc or "attiny" in proc:
        return "avr"
    # MSP430
    if "msp430" in proc:
        return "msp430"
    # C-SKY
    if "csky" in normalized_proc or "ckcore" in normalized_proc:
        return "csky"
    # ARC
    if normalized_proc.startswith("arc") or "arcompact" in normalized_proc:
        return "arc"
    # Intel Nios II
    if "nios2" in normalized_proc or "niosii" in normalized_proc:
        return "nios2"
    # Xilinx MicroBlaze
    if "microblaze" in normalized_proc:
        return "microblaze"
    # Renesas V850
    if normalized_proc.startswith("v850"):
        return "v850"
    # Renesas RL78
    if normalized_proc.startswith("rl78"):
        return "rl78"
    # Renesas H8
    if normalized_proc.startswith("h8"):
        return "h8"
    # 8051 / MCS-51
    if "8051" in normalized_proc or "mcs51" in normalized_proc:
        return "mcs51"
    # Z80 family
    if normalized_proc.startswith("z80"):
        return "z80"
    # Microchip PIC families frequently found in embedded firmware
    if normalized_proc.startswith(("pic24", "dspic")):
        return "pic24"
    if normalized_proc.startswith("pic18"):
        return "pic18"
    return "unknown"


# ============================================================================
# Architecture family helpers
# ============================================================================

def is_x86_family(arch=None):
    """Check if architecture is x86/x64."""
    if arch is None:
        arch = get_arch()
    return arch in ("x86", "x64")


def is_arm_family(arch=None):
    """Check if architecture is ARM/AArch64 (includes Thumb)."""
    if arch is None:
        arch = get_arch()
    return arch in ("arm", "arm64")


def is_mips_family(arch=None):
    """Check if architecture is MIPS/MIPS64."""
    if arch is None:
        arch = get_arch()
    return arch in ("mips", "mips64")


def is_ppc_family(arch=None):
    """Check if architecture is PowerPC/PPC64."""
    if arch is None:
        arch = get_arch()
    return arch in ("ppc", "ppc64")


def is_riscv_family(arch=None):
    """Check if architecture is RISC-V."""
    if arch is None:
        arch = get_arch()
    return arch in ("riscv", "riscv64")


def is_sparc_family(arch=None):
    """Check if architecture is SPARC."""
    if arch is None:
        arch = get_arch()
    return arch in ("sparc", "sparc64")


# ============================================================================
# Architecture-specific instruction sets
# ============================================================================

# Return / function-exit mnemonics.
#
# Register-indirect branch mnemonics (bx, jr, jalr, c.jr, c.jalr) are NOT in
# this set: they only act as returns for specific target registers (bx lr,
# jr $ra, jalr x0/ra) and otherwise encode indirect calls or jumps.  The
# operand-aware is_return_mnemonic() classifies them correctly; the raw sets
# group them under UNCONDITIONAL_JUMP_MNEMONICS so TERMINATOR_MNEMONICS still
# treats them as block terminators (no fall-through).
RETURN_MNEMONICS = {
    # x86/x64
    "ret", "retn",
    # PowerPC
    "blr",
    # SPARC
    "retl",
    "rts",     # SuperH return (also SPARC's non-leaf return)
    # 68k
    "rte", "rtd",
    # Xtensa
    "retw", "ret.n", "retw.n",
    # TriCore
    "rfe",
    # AVR/MSP430/8051/Z80/PIC
    "reti", "return", "retfie",
    # MicroBlaze
    "rtsd",
}

# Unconditional branch / jump mnemonics.
#
# Register-indirect branches (bx, jr, jalr, br, c.jr, c.jalr) unconditionally
# transfer control to a register; they are grouped here rather than under
# RETURN_MNEMONICS because they only act as returns for specific target
# registers (bx lr, jr $ra, jalr x0/ra).  is_return_mnemonic() applies that
# operand-aware classification.
UNCONDITIONAL_JUMP_MNEMONICS = {
    # x86
    "jmp",
    # ARM (bx rN is a register branch; bx lr is the return form)
    "b",
    "bx",
    # AArch64 (br xN is a register branch; br x30 is the return form)
    "br",
    # MIPS (jr rN is a register branch; jr $ra is the return form)
    "j",
    "jr",
    # PowerPC
    "ba",
    # RISC-V standard + compressed C extension
    "jal",
    "jalr",     # register-indirect: rd=ra is a call, rs1=ra a return
    "c.j",      # compressed unconditional jump
    "c.jr",     # compressed register branch (c.jr ra is the return form)
    "c.jal",    # compressed call (RV32C only; encodes jal ra, offset)
    "c.jalr",   # compressed register link-jump (c.jalr ra is the return form)
    # SPARC
    # SuperH
    "bra",
}

# Call / branch-and-link mnemonics
CALL_MNEMONICS = {
    # x86
    "call",
    # ARM
    "bl", "blx",
    # AArch64
    "blr",
    # MIPS
    "jal", "jalr",
    # PowerPC
    "bla",
    # RISC-V (jal/jalr below via MIPS; compressed C-extension calls are RV32C
    # "jal ra, offset" and RV*C "jalr x1, rs1" — always link to ra, so they are
    # calls, never returns; is_return_mnemonic() classifies jalr/c.jr operand-aware)
    "c.jal",
    "c.jalr",
    # SPARC
    # SuperH
    "bsr", "jsr",
    # 68k
    # Xtensa
    "call0", "call4", "call8", "call12", "callx0", "callx4", "callx8", "callx12",
    # TriCore
    "calla", "calli",
    # AVR
    "rcall", "icall", "eicall",
}

# Conditional branch mnemonics (x86 + ARM + MIPS + PPC + RISC-V + SPARC)
CONDITIONAL_BRANCH_MNEMONICS = {
    # x86
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
    "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
    "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "jrcxz",
    # ARM
    "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
    "bhi", "bls", "bge", "blt", "bgt", "ble",
    "cbz", "cbnz", "tbz", "tbnz",
    # MIPS
    "bgtz", "blez", "bltz", "bgez",
    "beqz", "bnez", "bgezal", "bltzal",
    # PowerPC
    "bdnz", "bdz", "bc",
    # RISC-V standard. beq/bne/blt/bge are shared with ARM and beqz/bnez/bltz/
    # bgez/bgtz are shared with MIPS; each is deliberately re-listed here so the
    # RISC-V instruction set reads complete and self-documenting (membership is
    # unaffected — these sets are only used for `m in ...` checks).
    "beq", "bne", "blt", "bge",  # noqa: B033  # shared with ARM
    "bltu", "bgeu",
    # RISC-V compressed C extension
    "c.beqz", "c.bnez",
    # SPARC
    "be", "bl", "bg",
}

# Terminator mnemonics (instructions that end a basic block with no fall-through)
TERMINATOR_MNEMONICS = (
    RETURN_MNEMONICS | UNCONDITIONAL_JUMP_MNEMONICS |
    {"int3", "hlt", "ud2", "eret", "udf", "break", "trap", "ebreak"}
)

# Syscall / software interrupt mnemonics
SYSCALL_MNEMONICS = {
    # x86
    "syscall", "sysenter", "int",
    # ARM
    "svc", "swi",
    # AArch64
    "hvc", "smc",
    # MIPS
    # PowerPC
    "sc",
    # RISC-V
    "ecall",
    # SPARC
    "ta",
    # SuperH
    "trapa",
    # 68k
    "trap",
}

# MOV-like data transfer mnemonics (used for stack-string detection)
MOV_MNEMONICS = {
    # x86
    "mov", "movabs",
    # ARM
    "movw", "movt", "strb", "movb",
    # MIPS
    "li", "lui", "move", "sb",
    # PowerPC
    "lis", "mr", "stb",
    # RISC-V (li/lui shared with MIPS; re-listed for self-documentation, see
    # the note under CONDITIONAL_BRANCH_MNEMONICS — membership is unaffected)
    "li", "lui",  # noqa: B033  # shared with MIPS
    "mv", "la",
    # Xtensa
    "movi", "movi.n", "s8i",
    # AVR
    "ldi", "sts", "std",
}

# Comparison / test mnemonics (used for null-check heuristics)
COMPARISON_MNEMONICS = {
    # x86
    "test", "cmp",
    # ARM
    "cmn", "tst", "teq",
    # AArch64
    "cbz", "cbnz",
    # MIPS
    "beqz", "bnez", "slti", "sltiu",
    # PowerPC
    "cmpwi", "cmplwi", "cmpdi", "cmpldi",
    # RISC-V (slti/sltiu above via MIPS — same encodings)
    "slt", "sltu",
    # Xtensa
    "bgez", "bltz",
    # AVR
    "cp", "cpc", "cpi",
}

# XOR-like mnemonics (used for obfuscation detection)
XOR_MNEMONICS = {
    # x86 / RISC-V (xor)
    "xor",
    # ARM
    "eor",
    # MIPS / RISC-V (xori)
    "xori",
}

# Arithmetic mnemonics used in integer overflow heuristics
ARITHMETIC_MNEMONICS = {
    # x86
    "add", "mul", "imul", "shl", "shr",
    # ARM
    "adds", "muls", "lsl", "lsr", "madd", "umull", "smull",
    # MIPS
    "addu", "addi", "addiu", "mult", "multu", "sll", "srl",
    # PowerPC
    "mulli", "mullw", "slwi", "srwi",
    # RISC-V (add shared with x86; addi shared with MIPS; mul shared with x86;
    # re-listed for self-documentation — membership is unaffected)
    "sub", "mulhu", "lui", "li", "xori", "andi", "ori",
    "add", "addi", "mul",  # noqa: B033  # add/mul shared with x86, addi with MIPS
    "slli", "srli",
    # Xtensa
    # AVR
    "adiw",
}

# Interesting instructions for triage (architecture-aware)
INTERESTING_INSTRUCTIONS = {
    # x86
    "syscall":  "system_call",
    "sysenter": "system_call",
    "int 3":    "breakpoint",
    "rdtsc":    "timing_check",
    "cpuid":    "environment_check",
    # ARM / AArch64
    "svc":      "system_call",
    "swi":      "system_call",
    "hvc":      "hypervisor_call",
    "smc":      "secure_monitor_call",
    "bkpt":     "breakpoint",
    "brk":      "breakpoint",
    "mrs":      "system_register_read",
    "break":    "breakpoint",
    # PowerPC
    "sc":       "system_call",
    "tw":       "trap",
    # RISC-V — user/supervisor/machine transitions + debug
    "ecall":    "system_call",
    "ebreak":   "breakpoint",
    "mret":     "machine_mode_return",     # M-mode exception return
    "sret":     "supervisor_mode_return",  # S-mode exception return (Linux kernel)
    "uret":     "user_mode_return",        # U-mode return (N extension, rare)
    "wfi":      "wait_for_interrupt",      # power management / idle loop sentinel
    # CSR access — always interesting in firmware/OS analysis
    "csrrw":    "csr_write",
    "csrrs":    "csr_set",
    "csrrc":    "csr_clear",
    "csrrwi":   "csr_write_imm",
    "csrrsi":   "csr_set_imm",
    "csrrci":   "csr_clear_imm",
    "csrr":     "csr_read",               # pseudo: csrrs rd, csr, x0
    "csrw":     "csr_write",              # pseudo: csrrw x0, csr, rs1
    "csrs":     "csr_set",                # pseudo: csrrs x0, csr, rs1
    "csrc":     "csr_clear",              # pseudo: csrrc x0, csr, rs1
    "csrwi":    "csr_write_imm",
    "csrsi":    "csr_set_imm",
    "csrci":    "csr_clear_imm",
    "fence":    "memory_barrier",
    "fence.i":  "instruction_fence",      # I$ invalidation — critical after self-modifying code
    # SPARC
    "ta":       "system_call",
    # SuperH
    "trapa":    "system_call",
    # 68k
    "trap":     "system_call",
}


def get_return_register(arch=None):
    """Return the default integer return register for the architecture."""
    if arch is None:
        arch = get_arch()
    _map = {
        "x86": "eax",
        "x64": "rax",
        "arm": "r0",
        "arm64": "x0",
        "mips": "v0",
        "mips64": "v0",
        "ppc": "r3",
        "ppc64": "r3",
        "riscv": "a0",
        "riscv64": "a0",
        "sparc": "o0",
        "sparc64": "o0",
        "sh": "r0",
        "68k": "d0",
        "s390": "r2",
        "xtensa": "a2",
        "tricore": "d2",
        "avr": "r24",
        "msp430": "r12",
        "csky": "a0",
        "arc": "r0",
        "nios2": "r2",
        "microblaze": "r3",
        "v850": "r10",
        "rl78": "ax",
        "h8": "er0",
        "mcs51": "dpl",
        "z80": "a",
        "pic24": "w0",
        "pic18": "wreg",
    }
    return _map.get(arch, "r0")


def get_stack_pointer_names(arch=None):
    """Return the set of stack pointer register names for the architecture."""
    if arch is None:
        arch = get_arch()
    _map = {
        "x86": {"esp"},
        "x64": {"rsp"},
        "arm": {"sp", "r13"},
        "arm64": {"sp"},
        "mips": {"sp", "$sp", "$29"},
        "mips64": {"sp", "$sp", "$29"},
        "ppc": {"r1"},
        "ppc64": {"r1"},
        "riscv": {"sp", "x2"},
        "riscv64": {"sp", "x2"},
        "sparc": {"sp", "o6"},
        "sparc64": {"sp", "o6"},
        "sh": {"r15"},
        "68k": {"sp", "a7"},
        "xtensa": {"sp", "a1"},
        "tricore": {"sp", "a10"},
        "avr": {"sp"},
        "msp430": {"sp", "r1"},
        "csky": {"sp"},
        "arc": {"sp"},
        "nios2": {"sp"},
        "microblaze": {"r1", "sp"},
        "v850": {"sp"},
        "rl78": {"sp"},
        "h8": {"sp", "er7"},
        "mcs51": {"sp"},
        "z80": {"sp"},
        "pic24": {"w15", "sp"},
        "pic18": {"stkptr"},
    }
    return _map.get(arch, {"sp"})


def get_callee_saved_registers(arch=None):
    """Return the set of callee-saved (non-volatile) register names."""
    if arch is None:
        arch = get_arch()
    _map = {
        "x86": {"ebp", "ebx", "edi", "esi"},
        # x64 assumes the Windows x64 ABI (rdi/rsi are callee-saved there).
        # On the SysV ABI (Linux/macOS/BSD) rdi/rsi are volatile argument
        # registers; callers analyzing SysV binaries should drop them.
        "x64": {"rbp", "rbx", "rdi", "rsi", "r12", "r13", "r14", "r15"},
        "arm": {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "lr", "fp"},
        "arm64": {"x19", "x20", "x21", "x22", "x23", "x24", "x25",
                  "x26", "x27", "x28", "x29", "x30", "fp", "lr"},
        "mips": {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                 "fp", "ra", "gp"},
        "mips64": {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                   "fp", "ra", "gp"},
        "ppc": {"r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21",
                "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
                "r30", "r31"},
        "ppc64": {"r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21",
                  "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
                  "r30", "r31"},
        "riscv": {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                  "s8", "s9", "s10", "s11", "ra"},
        "riscv64": {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                    "s8", "s9", "s10", "s11", "ra"},
        "xtensa": {"a12", "a13", "a14", "a15"},
        "tricore": {"a10", "a11", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"},
        "avr": {"r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17"},
        "msp430": {"r4", "r5", "r6", "r7", "r8", "r9", "r10"},
        "arc": {"r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20",
                "r21", "r22", "r23", "r24", "r25"},
        "nios2": {"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23"},
        "microblaze": {"r19", "r20", "r21", "r22", "r23", "r24", "r25",
                       "r26", "r27", "r28", "r29", "r30", "r31"},
        "v850": {"r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29"},
        "rl78": {"ax", "bc", "de", "hl"},
        "h8": {"er4", "er5", "er6"},
    }
    return _map.get(arch, set())


# RISC-V ABI register aliases -> canonical xN name. Only x0/zero and x1/ra are
# load-bearing for return classification, but the map keeps parsing uniform.
_RISCV_REG_ABI = {
    "zero": "x0", "ra": "x1", "sp": "x2", "gp": "x3", "tp": "x4",
    "fp": "x8", "s0": "x8", "s1": "x9",
}


def _riscv_reg_name(tok: str) -> str:
    """Normalize a RISC-V register operand token to its canonical xN name.

    Accepts ABI names (``zero``, ``ra``) and numeric names (``x0``, ``x1``, or
    a bare ``0``/``1``) with an optional ``$`` prefix.
    """
    t = (tok or "").strip().lower().lstrip("$")
    if t in _RISCV_REG_ABI:
        return _RISCV_REG_ABI[t]
    if t.isdigit():
        return f"x{t}"
    return t


def _riscv_operand_parts(disasm_lower: str, mnem: str) -> list[str]:
    """Return the comma-separated operand list of a RISC-V disasm line.

    IDA renders the full line (mnemonic included) in both ``jalr rd, imm(rs1)``
    and ``jalr rd, rs1, imm`` forms; the leading mnemonic token is stripped.
    """
    txt = (disasm_lower or "").strip()
    if txt.split(" ", 1) and txt.split(" ", 1)[0] == mnem:
        txt = txt.split(" ", 1)[1].strip()
    return [p.strip() for p in txt.split(",") if p.strip()]


def _classify_riscv_ret(mnem_lower: str, disasm_lower: str) -> bool:
    """Operand-aware RISC-V return classification (shared with gadgets).

    * ``jalr  rd, rs1, imm``  — return only when rd is x0/zero AND rs1 is ra/x1.
      ``jalr ra, rs1`` links a return address (a call); ``jalr x0, rs1`` with
      rs1 != ra is an indirect jump.
    * ``c.jr  rs1``           — return only when rs1 is ra/x1 (rd is x0).
    * ``c.jalr rs1``          — always links to ra: a CALL, never a return.
    """
    if mnem_lower == "jalr":
        parts = _riscv_operand_parts(disasm_lower, "jalr")
        if len(parts) < 2:
            return False
        rd = parts[0]
        second = parts[1]
        # offset(rs1) form, e.g. '0(ra)' (also '0(x1)').
        if "(" in second:
            rs1 = second[second.find("(") + 1:second.find(")")].strip()
        else:
            rs1 = second
        return _riscv_reg_name(rd) == "x0" and _riscv_reg_name(rs1) == "x1"
    if mnem_lower == "c.jr":
        parts = _riscv_operand_parts(disasm_lower, "c.jr")
        if not parts:
            return False
        return _riscv_reg_name(parts[0]) == "x1"
    return False


def is_return_mnemonic(mnem_lower, disasm_lower="", arch=None):
    """Check if a mnemonic represents a function return on the given architecture.

    Some architectures use indirect branches as returns (e.g. ARM's ``bx lr``,
    MIPS's ``jr $ra``, RISC-V's ``jalr x0, ra, 0``), so the disasm text is
    checked as well.
    """
    if arch is None:
        arch = get_arch()

    if mnem_lower in ("ret", "retn", "retl", "rts", "rte", "rtd"):
        return True

    if is_x86_family(arch):
        return mnem_lower in ("ret", "retn")

    if is_arm_family(arch):
        if mnem_lower == "bx" and "lr" in disasm_lower:
            return True
        if mnem_lower == "pop" and "pc" in disasm_lower:
            return True
        if mnem_lower == "ldp" and "pc" in disasm_lower:
            return True
        if mnem_lower.startswith("ldm") and "pc" in disasm_lower:
            return True
        return bool(mnem_lower == "ldr" and "pc" in disasm_lower)

    if is_mips_family(arch):
        return bool(mnem_lower == "jr" and ("ra" in disasm_lower or "$31" in disasm_lower))

    if is_ppc_family(arch):
        return mnem_lower == "blr"

    if is_riscv_family(arch):
        # mret/sret/uret are architectural exception returns; 'ret' is the
        # canonical pseudo-instruction for 'jalr x0, 0(ra)'.  Register-indirect
        # branches (jalr, c.jr, c.jalr) are classified operand-aware below.
        if mnem_lower in ("ret", "mret", "sret", "uret"):
            return True
        return _classify_riscv_ret(mnem_lower, disasm_lower)

    if is_sparc_family(arch):
        return mnem_lower in ("ret", "retl")

    # Generic fallback
    return mnem_lower in RETURN_MNEMONICS


def is_call_mnemonic(mnem_lower, arch=None):
    """Check if a mnemonic represents a function call."""
    if arch is None:
        arch = get_arch()
    return mnem_lower in CALL_MNEMONICS


def is_syscall_mnemonic(mnem_lower, arch=None):
    """Check if a mnemonic is a system call instruction."""
    if arch is None:
        arch = get_arch()
    return mnem_lower in SYSCALL_MNEMONICS


def get_prologue_pattern(mnem_list, arch=None):
    """Classify a function prologue pattern from its first few mnemonics.

    Returns a human-readable pattern name.
    """
    if arch is None:
        arch = get_arch()
    if not mnem_list:
        return "unknown"
    mnems = [m.lower() for m in mnem_list[:5]]

    if is_x86_family(arch):
        if "endbr64" in mnems or "endbr32" in mnems:
            return "cet_enabled"
        if "push" in mnems and "mov" in mnems:
            return "standard_frame_setup"
        if "sub" in mnems[:3]:
            return "stack_alloc"
        return "unknown"

    if is_arm_family(arch):
        if "stp" in mnems:
            return "aarch64_frame_setup"
        if any(m in mnems for m in ("stmdb", "stmfd", "push")):
            return "arm32_frame_setup"
        if "sub" in mnems[:3]:
            return "stack_alloc"
        return "unknown"

    if is_mips_family(arch):
        if "addiu" in mnems[:2] or "daddiu" in mnems[:2]:
            return "mips_frame_setup"
        if "sw" in mnems[:4] or "sd" in mnems[:4]:
            return "mips_reg_save"
        return "unknown"

    if is_ppc_family(arch):
        if "mflr" in mnems[:3]:
            return "ppc_frame_setup"
        if "stwu" in mnems[:3] or "stdu" in mnems[:3]:
            return "ppc_stack_alloc"
        return "unknown"

    if is_riscv_family(arch):
        # Standard and compressed SP adjustments
        if "addi" in mnems[:2] or "c.addi16sp" in mnems[:2] or "c.addi4spn" in mnems[:3]:
            return "riscv_frame_setup"
        if "sw" in mnems[:4] or "sd" in mnems[:4] or "c.sw" in mnems[:4] or "c.sd" in mnems[:4]:
            return "riscv_reg_save"
        return "unknown"

    return "unknown"


def get_epilogue_pattern(mnem_list, arch=None):
    """Classify a function epilogue pattern from its last few mnemonics.

    Returns a human-readable pattern name.
    """
    if arch is None:
        arch = get_arch()
    if not mnem_list:
        return "unknown"
    mnems = [m.lower() for m in mnem_list[-5:]]

    if is_x86_family(arch):
        if "ret" in mnems or "retn" in mnems:
            if "pop" in mnems or "leave" in mnems:
                return "standard_frame_teardown"
            return "simple_ret"
        if "jmp" in mnems:
            return "tail_call"
        if "int" in mnems:
            return "interrupt"
        return "unknown"

    if is_arm_family(arch):
        if "bx" in mnems:
            if "ldp" in mnems or "pop" in mnems or "ldm" in mnems:
                return "arm_frame_teardown"
            return "arm_simple_ret"
        if "pop" in mnems and any("pc" in m for m in mnems):
            return "arm_pop_pc"
        if "ldp" in mnems:
            return "aarch64_frame_teardown"
        if "b" in mnems:
            return "tail_call"
        return "unknown"

    if is_mips_family(arch):
        if "jr" in mnems:
            if "lw" in mnems or "ld" in mnems:
                return "mips_frame_teardown"
            return "mips_simple_ret"
        if "j" in mnems:
            return "tail_call"
        return "unknown"

    if is_ppc_family(arch):
        if "blr" in mnems:
            if "mtlr" in mnems or "lwz" in mnems or "ld" in mnems:
                return "ppc_frame_teardown"
            return "ppc_simple_ret"
        if "b" in mnems:
            return "tail_call"
        return "unknown"

    if is_riscv_family(arch):
        ret_mnems = {"ret", "jalr", "c.jr", "c.jalr", "mret", "sret"}
        load_mnems = {"lw", "ld", "c.lw", "c.ld"}
        tail_mnems = {"j", "jal", "c.j", "c.jal"}
        if ret_mnems & set(mnems):
            if load_mnems & set(mnems):
                return "riscv_frame_teardown"
            return "riscv_simple_ret"
        if tail_mnems & set(mnems):
            return "tail_call"
        return "unknown"

    return "unknown"


def get_tail_call_mnemonics(arch=None):
    """Return the set of unconditional branch mnemonics used for tail calls."""
    if arch is None:
        arch = get_arch()
    _map = {
        "x86": {"jmp"},
        "x64": {"jmp"},
        "arm": {"b"},
        "arm64": {"b"},
        "mips": {"j", "b"},
        "mips64": {"j", "b"},
        "ppc": {"b", "ba"},
        "ppc64": {"b", "ba"},
        "riscv": {"j", "jal", "c.j", "c.jal"},
        "riscv64": {"j", "jal", "c.j"},  # c.jal is RV32C only
        "sparc": {"ba", "jmp"},
        "sparc64": {"ba", "jmp"},
    }
    return _map.get(arch, {"jmp", "b", "j"})


# GP value already applied to the RISC-V processor plugin this session.  The
# entry-point probe (_detect_riscv_gp) runs on every disasm call, so memoizing
# here avoids re-setting processor options and re-queueing a full-address-space
# reanalysis on every call.
_APPLIED_RISCV_GP: int | None = None


def _apply_riscv_gp(gp_val: int):
    """Set GP in the RISC-V processor plugin and queue reanalysis.

    Returns (applied: bool, apply_error: str|None, reanalysis_queued: bool).

    The correct API is idc.set_processor_options("gp=0x...") — this tells the
    RISC-V processor plugin the GP base so it can resolve gp-relative operands
    into real data xrefs.  idc.set_reg_value() only sets a hint at a specific
    address and is NOT read by the processor plugin for xref resolution.

    Reanalysis is queued (plan_range) but never awaited: this runs inside an
    MCP RPC request, and blocking on auto_wait() for a full-binary reanalysis
    can exceed the socket timeout.  Once a GP value has been applied this
    session the whole apply + reanalysis is skipped on subsequent calls.
    """
    global _APPLIED_RISCV_GP
    if gp_val == _APPLIED_RISCV_GP:
        return True, None, False

    try:
        import idc as _idc
        import idaapi as _idaapi
    except ImportError:
        return False, "IDA not available", False

    applied = False
    apply_error = None
    reanalysis_queued = False

    # Primary: processor options string — what the RISC-V plugin actually reads
    try:
        _idc.set_processor_options(f"gp=0x{gp_val:x}")
        applied = True
    except Exception as _e:
        apply_error = str(_e)

    # Also persist via netnode so it survives IDB reload
    if applied:
        try:
            nn = _idaapi.netnode("$ risc-v", 0, True)
            nn.altset(1, gp_val)
        except Exception:
            pass

    # Queue reanalysis over the full address space so IDA re-evaluates every
    # gp-relative load/store and creates data xrefs.  Deliberately does NOT
    # call auto_wait() — see docstring.
    if applied:
        try:
            import ida_auto as _ida_auto
            import idc as _idc2
            min_ea = _idc2.get_inf_attr(_idc2.INF_MIN_EA)
            max_ea = _idc2.get_inf_attr(_idc2.INF_MAX_EA)
            if hasattr(_ida_auto, "plan_range"):
                _ida_auto.plan_range(min_ea, max_ea)
            elif hasattr(_ida_auto, "auto_mark_range"):
                _ida_auto.auto_mark_range(min_ea, max_ea, _ida_auto.AU_FINAL)
            reanalysis_queued = True
        except Exception:
            pass

    if applied:
        _APPLIED_RISCV_GP = gp_val

    return applied, apply_error, reanalysis_queued


def _riscv_gp_note(gp_val: int, detected_at: int, applied: bool, apply_error, reanalysis_queued: bool) -> str:
    gp_hex = hex(gp_val)
    at_hex = hex(detected_at)
    if applied and reanalysis_queued:
        return (
            f"RISC-V: GP (x3) = {gp_hex} detected at {at_hex}, applied via "
            f"set_processor_options and reanalysis queued in the background — "
            f"GP-relative xrefs will resolve shortly."
        )
    if applied:
        return (
            f"RISC-V: GP (x3) = {gp_hex} detected at {at_hex}, applied via "
            f"set_processor_options (no reanalysis queued on this call — "
            f'run analysis(action="reanalyze") if GP-relative xrefs are missing).'
        )
    return (
        f"RISC-V: GP (x3) = {gp_hex} detected at {at_hex} but auto-apply failed "
        f"({apply_error}). Run manually: idc.set_processor_options('gp=0x{gp_val:x}')"
    )


def set_riscv_gp(gp_val: int) -> dict:
    """Set GP explicitly (e.g. when the agent already knows the value from
    context) and queue reanalysis.  Returns a result dict suitable for
    returning directly from an MCP tool action.
    """
    applied, apply_error, reanalysis_queued = _apply_riscv_gp(gp_val)
    return {
        "ok": applied,
        "gp": gp_val,
        "gp_hex": hex(gp_val),
        "applied": applied,
        "reanalysis_queued": reanalysis_queued,
        "note": _riscv_gp_note(gp_val, 0, applied, apply_error, reanalysis_queued),
    }


def detect_riscv_gp():
    """Scan the binary entrypoint for the GP-initialization sequence.

    On bare-metal/RTOS RISC-V targets the linker inserts a two-instruction
    prologue near _start that loads the GP register (x3):

        auipc  gp, %pcrel_hi(__global_pointer$)
        addi   gp, gp, %pcrel_lo(__global_pointer$)

    Without GP set, IDA cannot resolve GP-relative data xrefs (lw/sw with gp
    base).  This function tries to recover the GP value by simulating those two
    instructions from the disassembly bytes at the binary's entry point.

    Returns a dict with:
      {"found": True,  "gp": <int>, "at": <hex str>, "note": "..."}  on success
      {"found": False, "note": "..."} if the pattern was not located
    """
    try:
        import idc
        import idautils
    except ImportError:
        return {"found": False, "note": "IDA APIs not available"}

    # Collect candidate start addresses: entry points, then _start symbol
    candidates = []
    try:
        for ep in idautils.Entries():
            # ep is (ordinal, ea, name, fwd)
            if len(ep) >= 2:
                candidates.append(ep[1])
    except Exception:
        pass
    try:
        start_ea = idc.get_name_ea_simple("_start")
        if start_ea != idc.BADADDR:
            candidates.insert(0, start_ea)
    except Exception:
        pass

    # Also try __reset_vector, reset_handler common in embedded RISC-V
    for sym in ("__reset_vector", "reset_handler", "Reset_Handler", "entry"):
        try:
            ea = idc.get_name_ea_simple(sym)
            if ea != idc.BADADDR:
                candidates.append(ea)
        except Exception:
            pass

    # Raw-blob fallback: an opaque .bin has no vector table / entry point, so
    # the reset code usually sits at the image head (INF_MIN_EA).  Also scan
    # the base for common RISC-V link conventions.
    try:
        base = idc.get_inf_attr(idc.INF_MIN_EA)
        if base is not None and base != idc.BADADDR:
            candidates.append(int(base))
    except Exception:
        pass

    seen = set()
    for start_ea in candidates:
        if start_ea in seen:
            continue
        seen.add(start_ea)
        # Scan up to 32 instructions from each candidate
        ea = start_ea
        prev_auipc_val = None  # accumulated upper bits after auipc gp
        prev_lui_val = None    # accumulated upper bits after lui gp
        for _ in range(32):
            try:
                mnem = idc.print_insn_mnem(ea).lower()
                op0 = idc.print_operand(ea, 0).lower()
                if mnem == "auipc" and op0 in ("gp", "x3"):
                    # auipc gp, imm  =>  gp = PC + (imm << 12)
                    imm = idc.get_operand_value(ea, 1)
                    # sign-extend the 20-bit immediate, mirroring the addi
                    # handling below: a %pcrel_hi with bit 19 set (negative
                    # displacement, e.g. __global_pointer$ below _start) must
                    # not be treated as a large positive.
                    if imm & 0x80000:
                        imm -= 0x100000
                    prev_auipc_val = ea + (imm << 12)
                    prev_lui_val = None
                elif mnem == "lui" and op0 in ("gp", "x3"):
                    # lui gp, imm20  =>  gp = sign_extend(imm20) << 12
                    imm = idc.get_operand_value(ea, 1)
                    if imm & 0x80000:
                        imm -= 0x100000
                    prev_lui_val = imm << 12
                    prev_auipc_val = None
                elif mnem == "addi" and op0 in ("gp", "x3") and (prev_auipc_val is not None or prev_lui_val is not None):
                    # addi gp, gp, imm  =>  gp = prev + sign_extend(imm, 12)
                    raw = idc.get_operand_value(ea, 2)
                    # sign-extend 12-bit immediate
                    if raw & 0x800:
                        raw -= 0x1000
                    prev = prev_auipc_val if prev_auipc_val is not None else prev_lui_val
                    gp_val = (prev + raw) & 0xFFFFFFFFFFFFFFFF
                    applied, apply_error, reanalysis_queued = _apply_riscv_gp(gp_val)
                    note = _riscv_gp_note(gp_val, start_ea, applied, apply_error, reanalysis_queued)
                    return {
                        "found": True,
                        "gp": gp_val,
                        "gp_hex": hex(gp_val),
                        "at": hex(start_ea),
                        "applied": applied,
                        "reanalysis_queued": reanalysis_queued,
                        "note": note,
                    }
                else:
                    prev_auipc_val = None
                    prev_lui_val = None
                ea = idc.next_head(ea, idc.BADADDR)
                if ea == idc.BADADDR:
                    break
            except Exception:
                break

    # Opaque raw blob: no prologue found.  Surface a crisp hint instead of the
    # generic "pattern not found near entry points" (there are none on a raw
    # .bin), and propose the common GP conventions derived from the load base.
    try:
        base = idc.get_inf_attr(idc.INF_MIN_EA)
        if base is None or base == idc.BADADDR:
            base = 0
    except Exception:
        base = 0
    candidates_gp = sorted({(int(base) + off) & 0xFFFFFFFFFFFFFFFF
                            for off in (0x0, 0x10000000, 0x80000000)})
    gp_hint = ", ".join(hex(g) for g in candidates_gp)
    return {
        "found": False,
        "note": (
            "GP not found — load base/GP unknown for this raw blob; "
            "GP-relative xrefs (lw/sw via gp) are unresolved. "
            "Run analysis(action='set_gp', gp='0x<value>') with a known GP, "
            f"or try a candidate base (e.g. gp ≈ {gp_hint})."
        ),
    }
