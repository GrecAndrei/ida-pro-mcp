"""
Multi-architecture detection and helpers for IDA MCP tools.

Provides normalized architecture detection and architecture-specific
instruction sets for use across all tool modules. Supports:
  x86/x64, ARM/AArch64, RISC-V, MIPS, PowerPC, SPARC, SuperH, 68k, etc.
"""

try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


# ============================================================================
# Architecture detection
# ============================================================================

def get_arch():
    """Return normalized architecture string.

    Returns one of:
        'x86', 'x64', 'arm', 'arm64',
        'mips', 'mips64', 'ppc', 'ppc64',
        'riscv', 'riscv64', 'sparc', 'sparc64',
        'sh', '68k', 's390', 'unknown'
    """
    if idaapi is None:
        return "unknown"
    info = idaapi.get_inf_structure() if hasattr(idaapi, 'get_inf_structure') else None
    if info is None:
        return "unknown"
    proc = info.procname.lower().strip() if info.procname else ""
    is_64 = info.is_64bit() if hasattr(info, 'is_64bit') else False

    # x86 family
    if proc.startswith("metapc") or "x86" in proc or "80386" in proc or "80486" in proc:
        return "x64" if is_64 else "x86"
    # ARM family
    if proc.startswith("arm") or proc.startswith("aarch"):
        return "arm64" if is_64 else "arm"
    # RISC-V
    if "riscv" in proc or proc.startswith("risc-v") or proc.startswith("riscv"):
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

# Return / function-exit mnemonics
RETURN_MNEMONICS = {
    # x86/x64
    "ret", "retn",
    # ARM / AArch64  (bx lr is handled specially; pop {pc} via disasm)
    "bx",
    # MIPS
    "jr",
    # PowerPC
    "blr",
    # RISC-V
    "jalr",   # jalr x0, ra, 0  is the canonical return
    # SPARC
    "retl", "ret",
    # SuperH
    "rts",
    # 68k
    "rts", "rte", "rtd",
}

# Unconditional branch / jump mnemonics
UNCONDITIONAL_JUMP_MNEMONICS = {
    # x86
    "jmp",
    # ARM
    "b",
    # AArch64
    "b", "br",
    # MIPS
    "j", "b",
    # PowerPC
    "b", "ba",
    # RISC-V
    "j", "jal",
    # SPARC
    "ba", "jmp",
    # SuperH
    "bra", "jmp",
    # 68k
    "jmp", "bra",
}

# Call / branch-and-link mnemonics
CALL_MNEMONICS = {
    # x86
    "call",
    # ARM
    "bl", "blx",
    # AArch64
    "bl", "blr",
    # MIPS
    "jal", "jalr",
    # PowerPC
    "bl", "bla",
    # RISC-V
    "jal", "jalr",
    # SPARC
    "call",
    # SuperH
    "bsr", "jsr",
    # 68k
    "bsr", "jsr",
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
    "beq", "bne", "bgtz", "blez", "bltz", "bgez",
    "beqz", "bnez", "bgezal", "bltzal",
    # PowerPC
    "beq", "bne", "blt", "bgt", "ble", "bge",
    "bdnz", "bdz", "bc",
    # RISC-V
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    # SPARC
    "be", "bne", "bl", "bge", "ble", "bg", "bcs", "bcc",
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
    "svc", "hvc", "smc",
    # MIPS
    "syscall",
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
    "mov", "movw", "movt", "strb", "movb",
    # MIPS
    "li", "lui", "move", "sb",
    # PowerPC
    "li", "lis", "mr", "stb",
    # RISC-V
    "li", "lui", "mv", "sb",
}

# Comparison / test mnemonics (used for null-check heuristics)
COMPARISON_MNEMONICS = {
    # x86
    "test", "cmp",
    # ARM
    "cmp", "cmn", "tst", "teq",
    # AArch64
    "cmp", "cmn", "tst",
    "cbz", "cbnz",
    # MIPS
    "beqz", "bnez", "slti", "sltiu",
    # PowerPC
    "cmpwi", "cmplwi", "cmpdi", "cmpldi",
    # RISC-V
    "beqz", "bnez",
}

# XOR-like mnemonics (used for obfuscation detection)
XOR_MNEMONICS = {
    # x86
    "xor",
    # ARM
    "eor",
    # MIPS
    "xor", "xori",
    # PowerPC
    "xor", "xori",
    # RISC-V
    "xor", "xori",
}

# Arithmetic mnemonics used in integer overflow heuristics
ARITHMETIC_MNEMONICS = {
    # x86
    "add", "mul", "imul", "shl", "shr",
    # ARM
    "add", "adds", "mul", "muls", "lsl", "lsr", "madd", "umull", "smull",
    # MIPS
    "add", "addu", "addi", "addiu", "mul", "mult", "multu", "sll", "srl",
    # PowerPC
    "add", "addi", "mulli", "mullw", "slwi", "srwi",
    # RISC-V
    "add", "addi", "mul", "slli", "srli",
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
    # MIPS
    "syscall":  "system_call",
    "break":    "breakpoint",
    # PowerPC
    "sc":       "system_call",
    "tw":       "trap",
    # RISC-V
    "ecall":    "system_call",
    "ebreak":   "breakpoint",
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
    }
    return _map.get(arch, {"sp"})


def get_callee_saved_registers(arch=None):
    """Return the set of callee-saved (non-volatile) register names."""
    if arch is None:
        arch = get_arch()
    _map = {
        "x86": {"ebp", "ebx", "edi", "esi"},
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
    }
    return _map.get(arch, set())


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
        return False

    if is_mips_family(arch):
        if mnem_lower == "jr" and ("ra" in disasm_lower or "$31" in disasm_lower):
            return True
        return False

    if is_ppc_family(arch):
        return mnem_lower == "blr"

    if is_riscv_family(arch):
        if mnem_lower == "ret":
            return True
        if mnem_lower == "jalr" and "ra" in disasm_lower:
            return True
        return False

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
        if "addi" in mnems[:2]:
            return "riscv_frame_setup"
        if "sw" in mnems[:4] or "sd" in mnems[:4]:
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
        if "ret" in mnems or "jalr" in mnems:
            if "lw" in mnems or "ld" in mnems:
                return "riscv_frame_teardown"
            return "riscv_simple_ret"
        if "j" in mnems or "jal" in mnems:
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
        "riscv": {"j", "jal"},
        "riscv64": {"j", "jal"},
        "sparc": {"ba", "jmp"},
        "sparc64": {"ba", "jmp"},
    }
    return _map.get(arch, {"jmp", "b", "j"})
