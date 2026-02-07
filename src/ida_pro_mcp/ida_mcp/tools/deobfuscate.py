
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# DEOBFUSCATE - LLM-Optimized Deobfuscation Analysis
# ============================================================================

# Common API hashing targets
_HASH_RESOLVE_FUNCS = [
    "GetProcAddress", "GetProcAddressA",
    "LdrGetProcedureAddress", "LdrGetProcedureAddressEx",
]

# Known API hash algorithms and sample hashes for detection
_KNOWN_HASH_CONSTANTS = {
    "ror13_additive": 0x0D,   # ROR-13 additive hash (common in shellcode)
    "djb2":          0x1505,  # DJB2 hash initial value
    "sdbm":          0x1003F, # SDBM hash multiplier
    "fnv1a_32":      0x811C9DC5,  # FNV-1a 32-bit offset basis
}

# Stack-string mov mnemonics
_MOV_MNEMONICS = {"mov", "movabs"}

# Conditional jump mnemonics
_COND_JUMPS = {
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
    "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
    "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "jrcxz",
}


def _get_func_name_safe(ea):
    """Get function name for an address, or 'unknown'."""
    func = idaapi.get_func(ea)
    if func:
        return ida_funcs.get_func_name(func.start_ea)
    return "unknown"


def _iter_target_functions(addr):
    """Yield function start EAs to scan. If addr given, just that one."""
    if addr is not None:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return
        yield ea
    else:
        for ea in idautils.Functions():
            yield ea


def _is_printable_ascii(data):
    """Check if bytes are printable ASCII (with allowance for null terminator)."""
    for b in data:
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return False
    return True


def _xor_decode(data, key_byte):
    """XOR decode data with a single-byte key."""
    return bytes(b ^ key_byte for b in data)


def _detect_encoding_in_func(func_ea, limit):
    """Detect string encoding/encryption patterns within a function."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    xor_count = 0
    b64_refs = 0
    loop_xor = False

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        # Count XOR instructions (excluding xor reg, reg for zeroing)
        if mnem_l == "xor":
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op0 != op1:
                xor_count += 1

        # Look for base64 charset references
        if mnem_l in ("lea", "mov"):
            for xref in idautils.XrefsFrom(ea, 0):
                contents = idc.get_strlit_contents(xref.to)
                if contents:
                    try:
                        s = contents.decode("utf-8", errors="ignore")
                    except Exception:
                        s = str(contents)
                    if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" in s:
                        b64_refs += 1

    # Heuristic detection of loop-based XOR
    if xor_count >= 3:
        loop_xor = True

    methods = []
    if loop_xor:
        methods.append({"method": "xor_loop", "confidence": "high",
                        "xor_insn_count": xor_count})
    elif xor_count > 0:
        methods.append({"method": "xor_single", "confidence": "medium",
                        "xor_insn_count": xor_count})
    if b64_refs > 0:
        methods.append({"method": "base64", "confidence": "high",
                        "charset_refs": b64_refs})

    if methods:
        findings.append({
            "addr": hex_ea(func_ea),
            "function": _get_func_name_safe(func_ea),
            "methods": methods,
        })

    return findings[:limit]


def _xor_scan_func(func_ea, limit):
    """Scan a function for XOR-encoded data references and attempt decode."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue

        # Look for data references that could be encoded strings
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.iscode:
                continue
            data_ea = xref.to
            flags = ida_bytes.get_flags(data_ea)
            if ida_bytes.is_strlit(flags):
                continue  # already a known string

            raw = ida_bytes.get_bytes(data_ea, 64)
            if not raw or len(raw) < 4:
                continue

            # Try single-byte XOR keys
            for key in range(1, 256):
                decoded = _xor_decode(raw, key)
                # Check for printable result with at least 4 chars before null
                null_pos = decoded.find(b'\x00')
                if null_pos < 4:
                    continue
                segment = decoded[:null_pos]
                if _is_printable_ascii(segment) and len(segment) >= 4:
                    findings.append({
                        "addr": hex_ea(data_ea),
                        "ref_from": hex_ea(ea),
                        "function": _get_func_name_safe(ea),
                        "xor_key": f"0x{key:02x}",
                        "decoded": segment.decode("ascii", errors="replace")[:80],
                        "length": len(segment),
                    })
                    if len(findings) >= limit:
                        return findings
                    break  # found a key for this data, move on

    return findings


def _find_stack_strings(func_ea, limit):
    """Find strings built character-by-character on the stack."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    # Collect mov byte [stack], imm8 sequences
    char_stores = []
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()
        if mnem_l not in _MOV_MNEMONICS:
            continue

        # Check: op0 is memory (stack-relative), op1 is immediate byte value
        op0_type = idc.get_operand_type(ea, 0)
        op1_type = idc.get_operand_type(ea, 1)

        # o_displ (4) = memory displacement (e.g., [rbp-0x10])
        # o_phrase (3) = memory phrase (e.g., [esp])
        if op0_type not in (idc.o_displ, idc.o_phrase):
            continue
        if op1_type != idc.o_imm:
            continue

        imm_val = idc.get_operand_value(ea, 1)
        if 0x20 <= imm_val <= 0x7E:
            char_stores.append((ea, chr(imm_val)))

    # Group consecutive char stores into strings
    if len(char_stores) < 3:
        return findings

    current_str = [char_stores[0]]
    for i in range(1, len(char_stores)):
        prev_ea = char_stores[i - 1][0]
        curr_ea = char_stores[i][0]
        # Consider consecutive if within a small instruction gap
        gap = curr_ea - prev_ea
        if 0 < gap <= 16:
            current_str.append(char_stores[i])
        else:
            if len(current_str) >= 3:
                built = "".join(c for _, c in current_str)
                findings.append({
                    "addr": hex_ea(current_str[0][0]),
                    "function": _get_func_name_safe(func_ea),
                    "string": built,
                    "length": len(built),
                    "insn_count": len(current_str),
                })
                if len(findings) >= limit:
                    return findings
            current_str = [char_stores[i]]

    # Final group
    if len(current_str) >= 3:
        built = "".join(c for _, c in current_str)
        findings.append({
            "addr": hex_ea(current_str[0][0]),
            "function": _get_func_name_safe(func_ea),
            "string": built,
            "length": len(built),
            "insn_count": len(current_str),
        })

    return findings[:limit]


def _detect_opaque_predicates(func_ea, limit):
    """Detect opaque predicates (conditional jumps where one branch is never taken)."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()
        if mnem_l not in _COND_JUMPS:
            continue

        # Get the jump target
        jump_target = idc.get_operand_value(ea, 0)
        if jump_target == idaapi.BADADDR:
            continue

        # Get the fall-through address
        fall_through = idc.next_head(ea)
        if fall_through == idaapi.BADADDR:
            continue

        # Check xrefs to the jump target and fall-through
        # An opaque predicate has one branch with no other incoming xrefs
        jump_xrefs = list(idautils.XrefsTo(jump_target, 0))
        fall_xrefs = list(idautils.XrefsTo(fall_through, 0))

        # Check preceding instruction for suspicious patterns
        prev = idc.prev_head(ea)
        if prev == idaapi.BADADDR:
            continue
        prev_mnem = idc.print_insn_mnem(prev)
        if not prev_mnem:
            continue
        prev_mnem_l = prev_mnem.lower()

        # Pattern: xor reg, reg followed by conditional jump (always zero)
        # Pattern: cmp reg, reg (always equal)
        # Pattern: test reg, reg after xor reg, reg
        is_opaque = False
        pred_type = ""

        if prev_mnem_l == "xor":
            op0 = idc.print_operand(prev, 0)
            op1 = idc.print_operand(prev, 1)
            if op0 == op1:
                is_opaque = True
                pred_type = "xor_self_then_cond"

        elif prev_mnem_l == "cmp":
            op0 = idc.print_operand(prev, 0)
            op1 = idc.print_operand(prev, 1)
            if op0 == op1:
                is_opaque = True
                pred_type = "cmp_self"

        elif prev_mnem_l == "test":
            op0 = idc.print_operand(prev, 0)
            op1 = idc.print_operand(prev, 1)
            if op0 == op1:
                # Check if preceded by xor reg, reg
                prev2 = idc.prev_head(prev)
                if prev2 != idaapi.BADADDR:
                    pm2 = idc.print_insn_mnem(prev2)
                    if pm2 and pm2.lower() == "xor":
                        p2_op0 = idc.print_operand(prev2, 0)
                        p2_op1 = idc.print_operand(prev2, 1)
                        if p2_op0 == p2_op1 and p2_op0 == op0:
                            is_opaque = True
                            pred_type = "xor_test_cond"

        # Also detect: one branch target has zero xrefs from code
        if not is_opaque:
            jump_code_xrefs = [x for x in jump_xrefs if x.iscode]
            fall_code_xrefs = [x for x in fall_xrefs if x.iscode]
            if len(jump_code_xrefs) == 1 and len(fall_code_xrefs) == 0:
                is_opaque = True
                pred_type = "dead_fallthrough"
            elif len(fall_code_xrefs) == 1 and len(jump_code_xrefs) == 0:
                is_opaque = True
                pred_type = "dead_branch"

        if is_opaque:
            findings.append({
                "addr": hex_ea(ea),
                "function": _get_func_name_safe(func_ea),
                "type": pred_type,
                "mnemonic": mnem_l,
                "jump_target": hex_ea(jump_target),
                "fall_through": hex_ea(fall_through),
            })
            if len(findings) >= limit:
                return findings

    return findings


def _detect_cff(func_ea, limit, depth):
    """Detect control flow flattening patterns (dispatcher loops)."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    # Look for patterns: a variable compared repeatedly in a loop
    # with many branches (switch-like dispatcher)
    cmp_targets = {}
    jmp_count = 0
    insn_count = 0

    for ea in idautils.FuncItems(func_ea):
        insn_count += 1
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        if mnem_l == "cmp":
            op0 = idc.print_operand(ea, 0)
            op1_type = idc.get_operand_type(ea, 1)
            if op1_type == idc.o_imm:
                cmp_targets.setdefault(op0, []).append(ea)

        if mnem_l in _COND_JUMPS:
            jmp_count += 1

    # Heuristic: if a single variable is compared against many constants,
    # it's likely a dispatcher
    for var, cmp_eas in cmp_targets.items():
        if len(cmp_eas) >= 4:
            # Ratio of conditional jumps to instructions
            ratio = jmp_count / max(insn_count, 1)
            findings.append({
                "addr": hex_ea(func_ea),
                "function": _get_func_name_safe(func_ea),
                "dispatcher_var": var,
                "case_count": len(cmp_eas),
                "cond_jump_count": jmp_count,
                "jump_ratio": round(ratio, 4),
                "confidence": "high" if len(cmp_eas) >= 8 else "medium",
            })
            if len(findings) >= limit:
                return findings

    return findings


def _find_dead_code(func_ea, limit):
    """Find dead/unreachable code blocks within a function."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    # Collect all addresses that are targets of jumps/calls/fallthrough
    reachable = set()
    reachable.add(func.start_ea)

    for ea in idautils.FuncItems(func_ea):
        for xref in idautils.XrefsTo(ea, 0):
            if func.start_ea <= xref.frm < func.end_ea:
                reachable.add(ea)
                break
        else:
            # Also consider sequential flow from previous instruction
            prev = idc.prev_head(ea)
            if prev != idaapi.BADADDR and prev >= func.start_ea:
                prev_mnem = idc.print_insn_mnem(prev)
                if prev_mnem:
                    pm_l = prev_mnem.lower()
                    # Previous instruction doesn't break flow
                    if pm_l not in ("jmp", "ret", "retn", "int3", "hlt", "ud2"):
                        reachable.add(ea)

    # Find unreachable basic block starts
    prev_was_terminator = False
    for ea in idautils.FuncItems(func_ea):
        if ea == func.start_ea:
            prev_was_terminator = False
            continue

        mnem = idc.print_insn_mnem(ea)
        if prev_was_terminator and ea not in reachable:
            # Check if this address has any code xrefs to it
            has_xref = False
            for xref in idautils.XrefsTo(ea, 0):
                if xref.iscode:
                    has_xref = True
                    break
            if not has_xref:
                # Count consecutive unreachable instructions
                dead_count = 0
                cur = ea
                while cur < func.end_ea and dead_count < 20:
                    dead_count += 1
                    cur = idc.next_head(cur)
                    if cur == idaapi.BADADDR:
                        break
                    # Stop if we reach a referenced address
                    has_ref = False
                    for xref in idautils.XrefsTo(cur, 0):
                        if xref.iscode:
                            has_ref = True
                            break
                    if has_ref:
                        break

                findings.append({
                    "addr": hex_ea(ea),
                    "function": _get_func_name_safe(func_ea),
                    "dead_insn_count": dead_count,
                    "disasm": ida_lines.tag_remove(
                        idc.generate_disasm_line(ea, 0)),
                })
                if len(findings) >= limit:
                    return findings

        if mnem:
            prev_was_terminator = mnem.lower() in (
                "jmp", "ret", "retn", "int3", "hlt", "ud2")
        else:
            prev_was_terminator = False

    return findings


def _detect_api_hashing(func_ea, limit):
    """Detect API hashing patterns (hash computation + GetProcAddress)."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    # Check if function calls GetProcAddress or similar
    calls_resolve = False
    resolve_ea = None
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem or mnem.lower() != "call":
            continue
        for xref in idautils.XrefsFrom(ea, 0):
            name = idc.get_name(xref.to)
            if name and any(r in name for r in _HASH_RESOLVE_FUNCS):
                calls_resolve = True
                resolve_ea = ea
                break
        if calls_resolve:
            break

    if not calls_resolve:
        return findings

    # Look for hash computation patterns before the resolve call
    has_ror = False
    has_hash_const = False
    hash_insns = []

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        # ROR/ROL instructions (common in hash functions)
        if mnem_l in ("ror", "rol"):
            has_ror = True
            imm = idc.get_operand_value(ea, 1)
            if imm == _KNOWN_HASH_CONSTANTS.get("ror13_additive"):
                hash_insns.append(("ror13", hex_ea(ea)))

        # Check for known hash constants
        if mnem_l in ("mov", "add", "xor", "cmp"):
            op1_type = idc.get_operand_type(ea, 1)
            if op1_type == idc.o_imm:
                val = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                for name, const in _KNOWN_HASH_CONSTANTS.items():
                    if val == const:
                        has_hash_const = True
                        hash_insns.append((name, hex_ea(ea)))

    if has_ror or has_hash_const:
        findings.append({
            "addr": hex_ea(func_ea),
            "function": _get_func_name_safe(func_ea),
            "resolve_call": hex_ea(resolve_ea),
            "has_ror": has_ror,
            "hash_constants": hash_insns,
            "confidence": "high" if has_ror and has_hash_const else "medium",
        })

    return findings[:limit]


def _find_dynamic_dispatch(func_ea, limit):
    """Find dynamically resolved function calls (indirect calls via register/memory)."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()
        if mnem_l != "call":
            continue

        op_type = idc.get_operand_type(ea, 0)
        # o_reg (1) = register, o_displ (4) = memory displacement,
        # o_phrase (3) = memory phrase
        if op_type not in (idc.o_reg, idc.o_displ, idc.o_phrase):
            continue

        operand = idc.print_operand(ea, 0)
        # Try to trace what's being called
        dispatch_info = {
            "addr": hex_ea(ea),
            "function": _get_func_name_safe(func_ea),
            "call_target": operand,
            "call_type": "register" if op_type == idc.o_reg else "memory_indirect",
        }

        # Check preceding instructions for context
        prev = idc.prev_head(ea)
        if prev != idaapi.BADADDR:
            prev_disasm = ida_lines.tag_remove(
                idc.generate_disasm_line(prev, 0))
            dispatch_info["preceding_insn"] = prev_disasm

        findings.append(dispatch_info)
        if len(findings) >= limit:
            return findings

    return findings


def _detect_anti_disasm(func_ea, limit):
    """Detect anti-disassembly tricks."""
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        # Pattern 1: Jump into the middle of an instruction
        if mnem_l in ("jmp", "jz", "jnz", "je", "jne", "jb", "ja"):
            target = idc.get_operand_value(ea, 0)
            if target == idaapi.BADADDR:
                continue
            # Check if target is inside another instruction
            prev_of_target = idc.prev_head(target)
            if prev_of_target != idaapi.BADADDR:
                next_after_prev = idc.next_head(prev_of_target)
                if next_after_prev != idaapi.BADADDR and next_after_prev > target:
                    # Target falls within the bytes of prev instruction
                    findings.append({
                        "addr": hex_ea(ea),
                        "function": _get_func_name_safe(func_ea),
                        "type": "jump_into_instruction",
                        "target": hex_ea(target),
                        "overlapping_insn": hex_ea(prev_of_target),
                    })
                    if len(findings) >= limit:
                        return findings

        # Pattern 2: call $+5 (push return address trick)
        if mnem_l == "call":
            target = idc.get_operand_value(ea, 0)
            insn_size = idc.next_head(ea) - ea
            if target == ea + insn_size:
                findings.append({
                    "addr": hex_ea(ea),
                    "function": _get_func_name_safe(func_ea),
                    "type": "call_next_insn",
                    "description": "CALL $+N used to push return address (PIC/anti-disasm)",
                })
                if len(findings) >= limit:
                    return findings

        # Pattern 3: Impossible instructions (int3 / hlt / ud2 in middle of code)
        if mnem_l in ("int3", "hlt", "ud2", "int"):
            # Check if this is genuinely mid-function, not at end
            next_ea = idc.next_head(ea)
            if next_ea != idaapi.BADADDR and next_ea < func.end_ea:
                next_mnem = idc.print_insn_mnem(next_ea)
                if next_mnem:
                    findings.append({
                        "addr": hex_ea(ea),
                        "function": _get_func_name_safe(func_ea),
                        "type": "trap_instruction",
                        "mnemonic": mnem_l,
                        "description": "Trap/undefined instruction mid-function",
                    })
                    if len(findings) >= limit:
                        return findings

    return findings


def _decode_attempt_at(ea, key_hex, limit):
    """Attempt to decode an encoded value at a specific address."""
    raw = ida_bytes.get_bytes(ea, 256)
    if not raw:
        return {"ok": False, "error": f"Cannot read bytes at {hex_ea(ea)}"}

    results = []

    if key_hex:
        # Decode with provided key
        try:
            key_bytes = bytes.fromhex(key_hex.replace("0x", "").replace(" ", ""))
        except ValueError:
            return {"ok": False, "error": "Invalid hex key format"}

        if len(key_bytes) == 1:
            decoded = _xor_decode(raw, key_bytes[0])
        else:
            # Multi-byte XOR key
            decoded = bytes(raw[i] ^ key_bytes[i % len(key_bytes)]
                            for i in range(len(raw)))

        null_pos = decoded.find(b'\x00')
        if null_pos > 0:
            segment = decoded[:null_pos]
        else:
            segment = decoded

        results.append({
            "method": "xor",
            "key": key_hex,
            "decoded_hex": segment[:64].hex(),
            "decoded_ascii": segment[:64].decode("ascii", errors="replace"),
            "is_printable": _is_printable_ascii(segment),
            "length": len(segment),
        })
    else:
        # Auto-detect: try single-byte XOR keys
        for key in range(1, 256):
            decoded = _xor_decode(raw, key)
            null_pos = decoded.find(b'\x00')
            if null_pos < 4:
                continue
            segment = decoded[:null_pos]
            if _is_printable_ascii(segment) and len(segment) >= 4:
                results.append({
                    "method": "xor_single",
                    "key": f"0x{key:02x}",
                    "decoded": segment.decode("ascii", errors="replace")[:80],
                    "length": len(segment),
                })
                if len(results) >= limit:
                    break

        # Try base64 detection
        import base64
        try:
            # Find potential base64 segment (alphanumeric + /+=)
            b64_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            end = 0
            for i, b in enumerate(raw):
                if b in b64_chars:
                    end = i + 1
                else:
                    break
            if end >= 4:
                b64_segment = raw[:end]
                try:
                    decoded_b64 = base64.b64decode(b64_segment, validate=True)
                    results.append({
                        "method": "base64",
                        "encoded": b64_segment.decode("ascii", errors="replace")[:80],
                        "decoded_hex": decoded_b64[:64].hex(),
                        "decoded_ascii": decoded_b64[:64].decode(
                            "ascii", errors="replace"),
                        "length": len(decoded_b64),
                    })
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "ok": True,
        "addr": hex_ea(ea),
        "raw_hex": raw[:32].hex(),
        "results": results,
        "count": len(results),
    }


@tool
@idaread
def deobfuscate(
    action: Annotated[Literal["detect_encoding", "xor_scan", "stack_strings",
                               "opaque_predicates", "control_flow_flatten",
                               "dead_code", "api_hashing", "dynamic_dispatch",
                               "anti_disasm", "decode_attempt"],
                      "Deobfuscation analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    key: Annotated[Optional[str],
                   "Decryption key for decode_attempt (hex string)"] = None,
    depth: Annotated[int, "Analysis depth"] = 2,
) -> dict:
    """
    LLM-optimized deobfuscation analysis for binary reverse engineering.

    Actions:
    - detect_encoding: Detect string encoding/encryption methods (XOR, Base64, RC4, custom).
    - xor_scan: Find XOR-encoded strings and attempt decode with single-byte keys 0x01-0xFF.
    - stack_strings: Find strings built character-by-character on the stack (mov byte sequences).
    - opaque_predicates: Detect opaque predicates (always-true/false conditional jumps).
    - control_flow_flatten: Detect control flow flattening (dispatcher variable with many case comparisons).
    - dead_code: Find dead/unreachable code blocks (no incoming xrefs, follows unconditional terminator).
    - api_hashing: Detect API hashing (ROR/hash constants near GetProcAddress calls).
    - dynamic_dispatch: Find dynamically resolved function calls (indirect call via register/memory).
    - anti_disasm: Detect anti-disassembly tricks (jump-into-instruction, call $+5, mid-function traps).
    - decode_attempt: Attempt to decode an encoded value at addr. Provide key for specific XOR key, or omit for auto-detect.

    Each finding includes addr, function, and action-specific details.
    """
    try:
        if action == "decode_attempt":
            if not addr:
                return make_error(MCPError.INVALID_ARGS,
                                  "addr required for decode_attempt")
            ea, err = validate_addr(addr)
            if err:
                return err
            return _decode_attempt_at(ea, key, limit)

        # All other actions iterate over functions
        all_findings = []

        for func_ea in _iter_target_functions(addr):
            if len(all_findings) >= limit:
                break

            remaining = limit - len(all_findings)

            if action == "detect_encoding":
                hits = _detect_encoding_in_func(func_ea, remaining)
            elif action == "xor_scan":
                hits = _xor_scan_func(func_ea, remaining)
            elif action == "stack_strings":
                hits = _find_stack_strings(func_ea, remaining)
            elif action == "opaque_predicates":
                hits = _detect_opaque_predicates(func_ea, remaining)
            elif action == "control_flow_flatten":
                hits = _detect_cff(func_ea, remaining, depth)
            elif action == "dead_code":
                hits = _find_dead_code(func_ea, remaining)
            elif action == "api_hashing":
                hits = _detect_api_hashing(func_ea, remaining)
            elif action == "dynamic_dispatch":
                hits = _find_dynamic_dispatch(func_ea, remaining)
            elif action == "anti_disasm":
                hits = _detect_anti_disasm(func_ea, remaining)
            else:
                return make_error(MCPError.INVALID_ARGS,
                                  f"Unknown action: {action}")

            all_findings.extend(hits)

        return {
            "ok": True,
            "action": action,
            "findings": all_findings[:limit],
            "count": len(all_findings[:limit]),
            "truncated": len(all_findings) >= limit,
        }

    except Exception as e:
        return handle_error(e)
