import contextlib

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# EMULATE - Unicorn-backed emulation sandbox for function execution
# ============================================================================

_UNICORN_AVAILABLE = False
try:
    import unicorn
    import unicorn.arm64_const as uc_arm64
    import unicorn.arm_const as uc_arm
    import unicorn.mips_const as uc_mips
    import unicorn.x86_const as uc_x86
    _UNICORN_AVAILABLE = True
except ImportError:
    pass

STACK_ADDR = 0x7F000000
STACK_SIZE = 0x100000
MAX_INSTRUCTIONS = 100000


def _require_unicorn():
    if not _UNICORN_AVAILABLE:
        return make_error(
            MCPError.NOT_IMPLEMENTED,
            "Unicorn emulator not available",
            hint="Install unicorn on the IDA runtime: pip install unicorn",
        )
    return None


def _get_uc_arch():
    """Map IDA arch to Unicorn constants. Returns (arch, mode) or (None, None)."""
    arch = get_arch()
    if is_x86_family(arch):
        if '64' in arch:
            return unicorn.UC_ARCH_X86, unicorn.UC_MODE_64
        return unicorn.UC_ARCH_X86, unicorn.UC_MODE_32
    if is_arm_family(arch):
        if '64' in arch or 'aarch64' in arch.lower():
            return unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM
        return unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM
    if is_mips_family(arch):
        return unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_LITTLE_ENDIAN
    return None, None


def _sp_reg(uc_arch, uc_mode):
    """Return the stack pointer register constant for the arch."""
    if uc_arch == unicorn.UC_ARCH_X86:
        if uc_mode == unicorn.UC_MODE_64:
            return uc_x86.UC_X86_REG_RSP
        return uc_x86.UC_X86_REG_ESP
    if uc_arch == unicorn.UC_ARCH_ARM64:
        return uc_arm64.UC_ARM64_REG_SP
    if uc_arch == unicorn.UC_ARCH_ARM:
        return uc_arm.UC_ARM_REG_SP
    if uc_arch == unicorn.UC_ARCH_MIPS:
        return uc_mips.UC_MIPS_REG_SP
    return None


def _ip_reg(uc_arch, uc_mode):
    """Return the instruction pointer register constant."""
    if uc_arch == unicorn.UC_ARCH_X86:
        if uc_mode == unicorn.UC_MODE_64:
            return uc_x86.UC_X86_REG_RIP
        return uc_x86.UC_X86_REG_EIP
    if uc_arch == unicorn.UC_ARCH_ARM64:
        return uc_arm64.UC_ARM64_REG_PC
    if uc_arch == unicorn.UC_ARCH_ARM:
        return uc_arm.UC_ARM_REG_PC
    if uc_arch == unicorn.UC_ARCH_MIPS:
        return uc_mips.UC_MIPS_REG_PC
    return None


def _ret_reg(uc_arch, uc_mode):
    """Return the return value register constant."""
    if uc_arch == unicorn.UC_ARCH_X86:
        if uc_mode == unicorn.UC_MODE_64:
            return uc_x86.UC_X86_REG_RAX
        return uc_x86.UC_X86_REG_EAX
    if uc_arch == unicorn.UC_ARCH_ARM64:
        return uc_arm64.UC_ARM64_REG_X0
    if uc_arch == unicorn.UC_ARCH_ARM:
        return uc_arm.UC_ARM_REG_R0
    if uc_arch == unicorn.UC_ARCH_MIPS:
        return uc_mips.UC_MIPS_REG_V0
    return None


def _gpr_map(uc_arch, uc_mode):
    """Return {name: uc_reg_const} for general purpose registers."""
    if uc_arch == unicorn.UC_ARCH_X86 and uc_mode == unicorn.UC_MODE_64:
        return {
            "rax": uc_x86.UC_X86_REG_RAX, "rbx": uc_x86.UC_X86_REG_RBX,
            "rcx": uc_x86.UC_X86_REG_RCX, "rdx": uc_x86.UC_X86_REG_RDX,
            "rsi": uc_x86.UC_X86_REG_RSI, "rdi": uc_x86.UC_X86_REG_RDI,
            "rbp": uc_x86.UC_X86_REG_RBP, "rsp": uc_x86.UC_X86_REG_RSP,
            "r8": uc_x86.UC_X86_REG_R8, "r9": uc_x86.UC_X86_REG_R9,
            "r10": uc_x86.UC_X86_REG_R10, "r11": uc_x86.UC_X86_REG_R11,
            "r12": uc_x86.UC_X86_REG_R12, "r13": uc_x86.UC_X86_REG_R13,
            "r14": uc_x86.UC_X86_REG_R14, "r15": uc_x86.UC_X86_REG_R15,
            "rip": uc_x86.UC_X86_REG_RIP,
        }
    if uc_arch == unicorn.UC_ARCH_X86 and uc_mode == unicorn.UC_MODE_32:
        return {
            "eax": uc_x86.UC_X86_REG_EAX, "ebx": uc_x86.UC_X86_REG_EBX,
            "ecx": uc_x86.UC_X86_REG_ECX, "edx": uc_x86.UC_X86_REG_EDX,
            "esi": uc_x86.UC_X86_REG_ESI, "edi": uc_x86.UC_X86_REG_EDI,
            "ebp": uc_x86.UC_X86_REG_EBP, "esp": uc_x86.UC_X86_REG_ESP,
            "eip": uc_x86.UC_X86_REG_EIP,
        }
    if uc_arch == unicorn.UC_ARCH_ARM64:
        m = {"sp": uc_arm64.UC_ARM64_REG_SP, "pc": uc_arm64.UC_ARM64_REG_PC,
             "lr": uc_arm64.UC_ARM64_REG_LR}
        for i in range(31):
            m[f"x{i}"] = uc_arm64.UC_ARM64_REG_X0 + i
        return m
    if uc_arch == unicorn.UC_ARCH_ARM:
        m = {"sp": uc_arm.UC_ARM_REG_SP, "pc": uc_arm.UC_ARM_REG_PC,
             "lr": uc_arm.UC_ARM_REG_LR}
        for i in range(16):
            m[f"r{i}"] = uc_arm.UC_ARM_REG_R0 + i
        return m
    if uc_arch == unicorn.UC_ARCH_MIPS:
        m = {"sp": uc_mips.UC_MIPS_REG_SP, "pc": uc_mips.UC_MIPS_REG_PC,
             "ra": uc_mips.UC_MIPS_REG_RA, "v0": uc_mips.UC_MIPS_REG_V0,
             "v1": uc_mips.UC_MIPS_REG_V1, "a0": uc_mips.UC_MIPS_REG_A0,
             "a1": uc_mips.UC_MIPS_REG_A1, "a2": uc_mips.UC_MIPS_REG_A2,
             "a3": uc_mips.UC_MIPS_REG_A3}
        return m
    return {}


def _arg_regs(uc_arch, uc_mode):
    """Return ordered list of argument register constants for the calling convention."""
    if uc_arch == unicorn.UC_ARCH_X86 and uc_mode == unicorn.UC_MODE_64:
        # System V AMD64 ABI
        return [uc_x86.UC_X86_REG_RDI, uc_x86.UC_X86_REG_RSI,
                uc_x86.UC_X86_REG_RDX, uc_x86.UC_X86_REG_RCX,
                uc_x86.UC_X86_REG_R8, uc_x86.UC_X86_REG_R9]
    if uc_arch == unicorn.UC_ARCH_ARM64:
        return [uc_arm64.UC_ARM64_REG_X0 + i for i in range(8)]
    if uc_arch == unicorn.UC_ARCH_ARM:
        return [uc_arm.UC_ARM_REG_R0 + i for i in range(4)]
    if uc_arch == unicorn.UC_ARCH_MIPS:
        return [uc_mips.UC_MIPS_REG_A0, uc_mips.UC_MIPS_REG_A1,
                uc_mips.UC_MIPS_REG_A2, uc_mips.UC_MIPS_REG_A3]
    return []


def _setup_uc(uc_arch, uc_mode, start_ea, end_ea, regs=None):
    """Create and configure a Unicorn instance with IDB memory mapped."""
    uc = unicorn.Uc(uc_arch, uc_mode)

    # Map and load segments that overlap [start_ea, end_ea]
    mapped = set()
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        seg_start = seg.start_ea
        seg_size = seg.end_ea - seg.start_ea
        if seg_size <= 0:
            continue
        # Align to 4K pages
        aligned_start = seg_start & ~0xFFF
        aligned_end = (seg.end_ea + 0xFFF) & ~0xFFF
        aligned_size = aligned_end - aligned_start
        page_key = aligned_start
        if page_key in mapped:
            continue
        mapped.add(page_key)
        try:
            uc.mem_map(aligned_start, aligned_size, unicorn.UC_PROT_ALL)
        except unicorn.UcError:
            continue
        data = ida_bytes.get_bytes(seg_start, seg_size)
        if data:
            with contextlib.suppress(unicorn.UcError):
                uc.mem_write(seg_start, data)

    # Map stack
    with contextlib.suppress(unicorn.UcError):
        uc.mem_map(STACK_ADDR, STACK_SIZE, unicorn.UC_PROT_ALL)
    sp_init = STACK_ADDR + STACK_SIZE - 0x1000
    sp_const = _sp_reg(uc_arch, uc_mode)
    if sp_const is not None:
        uc.reg_write(sp_const, sp_init)

    # Write a return-stop address on the stack for x86
    if uc_arch == unicorn.UC_ARCH_X86:
        stop_addr = 0xDEAD0000
        with contextlib.suppress(unicorn.UcError):
            uc.mem_map(stop_addr & ~0xFFF, 0x1000, unicorn.UC_PROT_ALL)
        if uc_mode == unicorn.UC_MODE_64:
            uc.mem_write(sp_init, stop_addr.to_bytes(8, 'little'))
        else:
            uc.mem_write(sp_init, stop_addr.to_bytes(4, 'little'))

    # Set user-provided registers
    if regs:
        gpr = _gpr_map(uc_arch, uc_mode)
        for name, val in regs.items():
            name_lower = name.lower()
            if name_lower in gpr:
                v = int(str(val), 0) if isinstance(val, str) else int(val)
                uc.reg_write(gpr[name_lower], v)

    return uc


def _read_regs(uc, uc_arch, uc_mode):
    """Read all GPRs and return as {name: hex_value}."""
    gpr = _gpr_map(uc_arch, uc_mode)
    result = {}
    for name, const in gpr.items():
        with contextlib.suppress(unicorn.UcError):
            result[name] = hex(uc.reg_read(const))
    return result


def _run_uc(uc, uc_arch, uc_mode, start, end_or_zero, max_steps):
    """Run emulation. Returns (error_msg_or_None, steps_executed)."""
    stop_addr = end_or_zero if end_or_zero else 0xDEAD0000
    steps = [0]
    stop_reason = [None]

    def _hook_code(uc_inst, address, size, user_data):
        steps[0] += 1
        if steps[0] >= max_steps:
            stop_reason[0] = "max_steps"
            uc_inst.emu_stop()
        if address == stop_addr:
            stop_reason[0] = "reached_end"
            uc_inst.emu_stop()

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code)
    try:
        uc.emu_start(start, stop_addr, timeout=10 * 1000000, count=max_steps)
    except unicorn.UcError as e:
        if not stop_reason[0]:
            stop_reason[0] = str(e)
    finally:
        uc.hook_del(hook)
    return stop_reason[0], steps[0]


@tool
@idaread
def emulate(
    action: Annotated[Literal["run", "slice", "call", "decrypt", "trace"],
                      "Emulation action"],
    addr: Annotated[Optional[str], "Function or start address"] = None,
    addr_end: Annotated[Optional[str], "End address (for slice)"] = None,
    args: Annotated[Optional[list], "Function arguments (for call action)"] = None,
    regs: Annotated[Optional[dict], "Initial register values {name: value}"] = None,
    max_steps: Annotated[int, "Max instructions to execute"] = 10000,
    buf_addr: Annotated[Optional[str], "Buffer address (for decrypt)"] = None,
    buf_size: Annotated[int, "Buffer size (for decrypt)"] = 256,
    **kwargs
) -> dict:
    """
    Unicorn-backed emulation sandbox — execute function slices from the IDB.

    ACTIONS:

    run - Execute a function from its entry point to return.
        Params: addr (required), regs (optional), max_steps
        Returns: {registers, stop_reason, steps}

    slice - Execute a specific address range [addr, addr_end).
        Params: addr, addr_end (required), regs, max_steps
        Returns: {registers, stop_reason, steps}

    call - Emulate a function call with arguments (auto-sets calling convention regs).
        Params: addr (required), args (list of int values), max_steps
        Returns: {return_value, registers, steps}

    decrypt - Run a function and diff memory to reveal decrypted output.
        Params: addr (required), buf_addr, buf_size, args, max_steps
        Returns: {before, after, diff, return_value}

    trace - Execute with per-instruction tracing.
        Params: addr, addr_end, regs, max_steps
        Returns: {trace: [{addr, mnem}], steps, registers}

    Requires: pip install unicorn
    Architecture-aware: auto-detects x86/x64, ARM/AArch64, MIPS from IDB.
    """
    try:
        err = _require_unicorn()
        if err:
            return err

        uc_arch, uc_mode = _get_uc_arch()
        if uc_arch is None:
            return make_error(
                MCPError.NOT_IMPLEMENTED,
                f"Unsupported architecture for emulation: {get_arch()}",
                hint="emulate supports x86/x86_64/ARM/ARM64/MIPS only.",
            )

        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err

        # ----------------------------------------------------------------
        # ACTION: run
        # ----------------------------------------------------------------
        if action == "run":
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.INVALID_ARGS, f"No function at {hex(ea)}")
            uc = _setup_uc(uc_arch, uc_mode, fn.start_ea, fn.end_ea, regs)
            reason, steps = _run_uc(uc, uc_arch, uc_mode, fn.start_ea, 0, max_steps)
            return {
                "ok": True,
                "action": "run",
                "function": idc.get_func_name(ea) or hex_ea(ea),
                "start": hex_ea(fn.start_ea),
                "registers": _read_regs(uc, uc_arch, uc_mode),
                "stop_reason": reason or "completed",
                "steps": steps,
                "arch": get_arch(),
            }

        # ----------------------------------------------------------------
        # ACTION: slice
        # ----------------------------------------------------------------
        elif action == "slice":
            if not addr_end:
                return make_error(MCPError.INVALID_ARGS, "addr_end required for slice")
            ea_end, err2 = validate_addr(addr_end)
            if err2:
                return err2
            uc = _setup_uc(uc_arch, uc_mode, ea, ea_end, regs)
            reason, steps = _run_uc(uc, uc_arch, uc_mode, ea, ea_end, max_steps)
            return {
                "ok": True,
                "action": "slice",
                "start": hex_ea(ea),
                "end": hex_ea(ea_end),
                "registers": _read_regs(uc, uc_arch, uc_mode),
                "stop_reason": reason or "completed",
                "steps": steps,
                "arch": get_arch(),
            }

        # ----------------------------------------------------------------
        # ACTION: call
        # ----------------------------------------------------------------
        elif action == "call":
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.INVALID_ARGS, f"No function at {hex(ea)}")
            uc = _setup_uc(uc_arch, uc_mode, fn.start_ea, fn.end_ea, regs)

            # Set arguments via calling convention registers
            if args:
                arg_reg_list = _arg_regs(uc_arch, uc_mode)
                for i, arg_val in enumerate(args):
                    if i >= len(arg_reg_list):
                        break
                    v = int(str(arg_val), 0) if isinstance(arg_val, str) else int(arg_val)
                    uc.reg_write(arg_reg_list[i], v)

            reason, steps = _run_uc(uc, uc_arch, uc_mode, fn.start_ea, 0, max_steps)
            ret_const = _ret_reg(uc_arch, uc_mode)
            ret_val = uc.reg_read(ret_const) if ret_const else 0
            return {
                "ok": True,
                "action": "call",
                "function": idc.get_func_name(ea) or hex_ea(ea),
                "return_value": hex(ret_val),
                "registers": _read_regs(uc, uc_arch, uc_mode),
                "stop_reason": reason or "completed",
                "steps": steps,
                "arch": get_arch(),
            }

        # ----------------------------------------------------------------
        # ACTION: decrypt
        # ----------------------------------------------------------------
        elif action == "decrypt":
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.INVALID_ARGS, f"No function at {hex(ea)}")

            target_addr = ea
            target_size = buf_size
            if buf_addr:
                ba, err3 = validate_addr(buf_addr)
                if err3:
                    return err3
                target_addr = ba

            uc = _setup_uc(uc_arch, uc_mode, fn.start_ea, fn.end_ea, regs)

            # Set arguments if provided
            if args:
                arg_reg_list = _arg_regs(uc_arch, uc_mode)
                for i, arg_val in enumerate(args):
                    if i >= len(arg_reg_list):
                        break
                    v = int(str(arg_val), 0) if isinstance(arg_val, str) else int(arg_val)
                    uc.reg_write(arg_reg_list[i], v)

            # Read memory before
            try:
                before = bytes(uc.mem_read(target_addr, target_size))
            except unicorn.UcError:
                before = b""

            reason, steps = _run_uc(uc, uc_arch, uc_mode, fn.start_ea, 0, max_steps)

            # Read memory after
            try:
                after = bytes(uc.mem_read(target_addr, target_size))
            except unicorn.UcError:
                after = b""

            # Build diff
            diff_bytes = []
            for i in range(min(len(before), len(after))):
                if before[i] != after[i]:
                    diff_bytes.append({"offset": i, "before": hex(before[i]), "after": hex(after[i])})

            # Try to decode after as string
            decoded = None
            try:
                nul = after.index(0)
                decoded = after[:nul].decode("utf-8", errors="replace")
            except (ValueError, UnicodeDecodeError):
                with contextlib.suppress(Exception):
                    decoded = after.rstrip(b"\x00").decode("utf-8", errors="replace")

            ret_const = _ret_reg(uc_arch, uc_mode)
            ret_val = uc.reg_read(ret_const) if ret_const else 0

            return {
                "ok": True,
                "action": "decrypt",
                "function": idc.get_func_name(ea) or hex_ea(ea),
                "buf_addr": hex_ea(target_addr),
                "buf_size": target_size,
                "before_hex": before[:64].hex(),
                "after_hex": after[:64].hex(),
                "decoded_string": decoded,
                "diff_count": len(diff_bytes),
                "diff": diff_bytes[:100],
                "return_value": hex(ret_val),
                "stop_reason": reason or "completed",
                "steps": steps,
            }

        # ----------------------------------------------------------------
        # ACTION: trace
        # ----------------------------------------------------------------
        elif action == "trace":
            end_addr = 0
            if addr_end:
                ea_end, err2 = validate_addr(addr_end)
                if err2:
                    return err2
                end_addr = ea_end
            else:
                fn = ida_funcs.get_func(ea)
                if fn:
                    end_addr = 0  # run until ret

            uc = _setup_uc(uc_arch, uc_mode, ea, end_addr or ea + 0x10000, regs)

            trace_log = []
            max_trace = min(max_steps, 5000)

            def _trace_hook(uc_inst, address, size, user_data):
                if len(trace_log) >= max_trace:
                    uc_inst.emu_stop()
                    return
                mnem = idc.print_insn_mnem(address) or "?"
                trace_log.append({"addr": hex_ea(address), "mnem": mnem})

            hook = uc.hook_add(unicorn.UC_HOOK_CODE, _trace_hook)
            stop_addr = end_addr if end_addr else 0xDEAD0000
            try:
                uc.emu_start(ea, stop_addr, timeout=10 * 1000000, count=max_steps)
            except unicorn.UcError:
                pass
            finally:
                uc.hook_del(hook)

            return {
                "ok": True,
                "action": "trace",
                "start": hex_ea(ea),
                "trace": trace_log,
                "steps": len(trace_log),
                "registers": _read_regs(uc, uc_arch, uc_mode),
                "arch": get_arch(),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
