try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
except ImportError:
    try:
        from host.intelligence.core import BgeCodeEmbedder, BehaviorClassifier
    except ImportError:
        BehaviorClassifier = None

# ============================================================================
# DEOBFUSCATE - LLM-Optimized Deobfuscation Analysis
# ============================================================================

_HASH_RESOLVE_FUNCS = [
    "GetProcAddress", "GetProcAddressA",
    "LdrGetProcedureAddress", "LdrGetProcedureAddressEx",
]

_KNOWN_HASH_CONSTANTS = {
    "ror13_additive": 0x0D,
    "djb2":          0x1505,
    "sdbm":          0x1003F,
    "fnv1a_32":      0x811C9DC5,
}

_MOV_MNEMONICS = MOV_MNEMONICS
_COND_JUMPS = CONDITIONAL_BRANCH_MNEMONICS
_TERMINATORS = TERMINATOR_MNEMONICS
_CALL_MNEMONICS = CALL_MNEMONICS

# Custom anchors for deobfuscation classification
_DEOBFUSCATE_ANCHORS = {
    "obfuscation_xor": "xor_loop rolling_key encrypted_buffer decode_stub xor_decode cleartext",
    "stack_strings": "mov byte ptr stack_var push_char build_string char_by_char stack_buffer",
    "api_hashing": "hash_api GetProcAddress LdrGetProcedureAddress ror13 djb2 fnv1a resolve_api",
}


def _get_behavior_classifier():
    """Get a BehaviorClassifier instance with deobfuscation anchors injected."""
    if BehaviorClassifier is None:
        return None
    try:
        embedder = BgeCodeEmbedder()
        clf = BehaviorClassifier.instance(embedder)
        for k, v in _DEOBFUSCATE_ANCHORS.items():
            if k not in clf.ANCHORS:
                clf.ANCHORS[k] = v
        return clf
    except Exception:
        return None


def _classify_function(func_ea, clf):
    """Decompile function and classify behavior. Returns list of behavior dicts or None."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return None
        pseudocode = str(cfunc)
        if not pseudocode.strip():
            return None
        hits = clf.classify(pseudocode, threshold=0.0, top_k=8, block=False)
        if hits:
            vals = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0 for h in hits))
            q50 = vals[len(vals) // 2]
            q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
            gate = q50 + max(0.0, q75 - q50)
            hits = [h for h in hits if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate]
        return hits
    except Exception:
        return None


def _write_to_blackboard(addr_str, tags, findings_text):
    """Auto-write high-confidence findings to blackboard."""
    try:
        from .blackboard import BlackboardStore
        store = BlackboardStore()
        store.write(
            title=f"Obfuscation detected at {addr_str}",
            content=findings_text,
            category="obfuscation",
            addr=addr_str,
            tags=tags,
            confidence=0.8,
            source="deobfuscate",
        )
    except Exception:
        pass


def _get_func_name_safe(ea):
    func = idaapi.get_func(ea)
    if func:
        return ida_funcs.get_func_name(func.start_ea)
    return "unknown"


def _iter_target_functions(addr):
    if addr is not None:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return
        yield ea
    else:
        for ea in idautils.Functions():
            yield ea


def _is_printable_ascii(data):
    for b in data:
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return False
    return True


def _xor_decode(data, key_byte):
    return bytes(b ^ key_byte for b in data)


def _detect_encoding_in_func(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    xor_count = 0
    b64_refs = 0

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        if mnem_l in XOR_MNEMONICS:
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op0 != op1:
                xor_count += 1

        if mnem_l in MOV_MNEMONICS or mnem_l in ("lea", "adr", "adrp"):
            for xref in idautils.XrefsFrom(ea, 0):
                contents = idc.get_strlit_contents(xref.to)
                if contents:
                    s = contents.decode("utf-8", errors="ignore") if isinstance(contents, bytes) else str(contents)
                    if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" in s:
                        b64_refs += 1

    methods = []
    if xor_count >= 3:
        methods.append(f"xor_loop(high,{xor_count}xor)")
    elif xor_count > 0:
        methods.append(f"xor_single(medium,{xor_count}xor)")
    if b64_refs > 0:
        methods.append(f"base64(high,{b64_refs}refs)")

    if methods:
        findings.append(f"{hex_ea(func_ea)}  {_get_func_name_safe(func_ea)}  {' '.join(methods)}")

    return findings[:limit]


def _find_stack_strings(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    char_stores = []
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        if mnem.lower() not in _MOV_MNEMONICS:
            continue

        op0_type = idc.get_operand_type(ea, 0)
        op1_type = idc.get_operand_type(ea, 1)

        if op0_type not in (idc.o_displ, idc.o_phrase):
            continue
        if op1_type != idc.o_imm:
            continue

        imm_val = idc.get_operand_value(ea, 1)
        if 0x20 <= imm_val <= 0x7E:
            char_stores.append((ea, chr(imm_val)))

    if len(char_stores) < 3:
        return findings

    current_str = [char_stores[0]]
    for i in range(1, len(char_stores)):
        prev_ea = char_stores[i - 1][0]
        curr_ea = char_stores[i][0]
        gap = curr_ea - prev_ea
        if 0 < gap <= 16:
            current_str.append(char_stores[i])
        else:
            if len(current_str) >= 3:
                built = "".join(c for _, c in current_str)
                findings.append(f"{hex_ea(current_str[0][0])}  {_get_func_name_safe(func_ea)}  len={len(built)}  {built}")
                if len(findings) >= limit:
                    return findings
            current_str = [char_stores[i]]

    if len(current_str) >= 3:
        built = "".join(c for _, c in current_str)
        findings.append(f"{hex_ea(current_str[0][0])}  {_get_func_name_safe(func_ea)}  len={len(built)}  {built}")

    return findings[:limit]


def _find_dead_code(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    reachable = set()
    reachable.add(func.start_ea)

    for ea in idautils.FuncItems(func_ea):
        _matched = False
        for _xi, xref in enumerate(idautils.XrefsTo(ea, 0)):
            if _xi >= 1000:
                break
            if func.start_ea <= xref.frm < func.end_ea:
                reachable.add(ea)
                _matched = True
                break
        if not _matched:
            prev = idc.prev_head(ea)
            if prev != idaapi.BADADDR and prev >= func.start_ea:
                prev_mnem = idc.print_insn_mnem(prev)
                if prev_mnem:
                    if prev_mnem.lower() not in _TERMINATORS:
                        reachable.add(ea)

    prev_was_terminator = False
    for ea in idautils.FuncItems(func_ea):
        if ea == func.start_ea:
            prev_was_terminator = False
            continue

        mnem = idc.print_insn_mnem(ea)
        if prev_was_terminator and ea not in reachable:
            has_xref = False
            for xref in idautils.XrefsTo(ea, 0):
                if xref.iscode:
                    has_xref = True
                    break
            if not has_xref:
                dead_count = 0
                cur = ea
                while cur < func.end_ea and dead_count < 20:
                    dead_count += 1
                    cur = idc.next_head(cur)
                    if cur == idaapi.BADADDR:
                        break
                    has_ref = False
                    for xref in idautils.XrefsTo(cur, 0):
                        if xref.iscode:
                            has_ref = True
                            break
                    if has_ref:
                        break

                disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  dead_insns={dead_count}  {disasm}")
                if len(findings) >= limit:
                    return findings

        if mnem:
            prev_was_terminator = mnem.lower() in _TERMINATORS
        else:
            prev_was_terminator = False

    return findings


def _detect_api_hashing(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    calls_resolve = False
    resolve_ea = None
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem or mnem.lower() not in _CALL_MNEMONICS:
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

    has_ror = False
    has_hash_const = False
    hash_insns = []

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        if mnem_l in ("ror", "rol"):
            has_ror = True
            imm = idc.get_operand_value(ea, 1)
            if imm == _KNOWN_HASH_CONSTANTS.get("ror13_additive"):
                hash_insns.append(("ror13", hex_ea(ea)))

        if mnem_l in ("mov", "add", "xor", "cmp"):
            op1_type = idc.get_operand_type(ea, 1)
            if op1_type == idc.o_imm:
                val = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                for name, const in _KNOWN_HASH_CONSTANTS.items():
                    if val == const:
                        has_hash_const = True
                        hash_insns.append((name, hex_ea(ea)))

    if has_ror or has_hash_const:
        conf = "high" if has_ror and has_hash_const else "medium"
        hash_info = " ".join(f"{n}@{a}" for n, a in hash_insns) if hash_insns else ""
        findings.append(f"{hex_ea(func_ea)}  {_get_func_name_safe(func_ea)}  resolve={hex_ea(resolve_ea)}  [{conf}]  {hash_info}")

    return findings[:limit]


def _find_dynamic_dispatch(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        if mnem.lower() not in _CALL_MNEMONICS:
            continue

        op_type = idc.get_operand_type(ea, 0)
        if op_type not in (idc.o_reg, idc.o_displ, idc.o_phrase):
            continue

        operand = idc.print_operand(ea, 0)
        call_type = "register" if op_type == idc.o_reg else "memory_indirect"
        prev = idc.prev_head(ea)
        prev_info = ""
        if prev != idaapi.BADADDR:
            prev_info = "  prev=" + ida_lines.tag_remove(idc.generate_disasm_line(prev, 0))
        findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  {call_type}  {operand}{prev_info}")
        if len(findings) >= limit:
            return findings

    return findings


def _detect_anti_disasm(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings

    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        mnem_l = mnem.lower()

        if mnem_l in _COND_JUMPS or mnem_l in ("jmp", "b"):
            target = idc.get_operand_value(ea, 0)
            if target == idaapi.BADADDR:
                continue
            prev_of_target = idc.prev_head(target)
            if prev_of_target != idaapi.BADADDR:
                next_after_prev = idc.next_head(prev_of_target)
                if next_after_prev != idaapi.BADADDR and next_after_prev > target:
                    findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  jump_into_instruction  target={hex_ea(target)}  overlap={hex_ea(prev_of_target)}")
                    if len(findings) >= limit:
                        return findings

        if mnem_l in _CALL_MNEMONICS:
            target = idc.get_operand_value(ea, 0)
            insn_size = idc.next_head(ea) - ea
            if target == ea + insn_size:
                findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  call_next_insn  CALL_$+N_push_return_address")
                if len(findings) >= limit:
                    return findings

        if mnem_l in ("int3", "hlt", "ud2", "int"):
            next_ea = idc.next_head(ea)
            if next_ea != idaapi.BADADDR and next_ea < func.end_ea:
                next_mnem = idc.print_insn_mnem(next_ea)
                if next_mnem:
                    findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  trap_instruction  {mnem_l}")
                    if len(findings) >= limit:
                        return findings

    return findings


def _decode_attempt_at(ea, key_hex, limit):
    raw = ida_bytes.get_bytes(ea, 256)
    if not raw:
        return {"ok": False, "error": f"Cannot read bytes at {hex_ea(ea)}"}

    results = []

    if key_hex:
        try:
            key_bytes = bytes.fromhex(key_hex.replace("0x", "").replace(" ", ""))
        except ValueError:
            return {"ok": False, "error": "Invalid hex key format"}

        if len(key_bytes) == 1:
            decoded = _xor_decode(raw, key_bytes[0])
        else:
            decoded = bytes(raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw)))

        null_pos = decoded.find(b'\x00')
        segment = decoded[:null_pos] if null_pos > 0 else decoded
        results.append(f"xor  key={key_hex}  len={len(segment)}  printable={_is_printable_ascii(segment)}  \"{segment[:64].decode('ascii', errors='replace')}\"")
    else:
        for key in range(1, 256):
            decoded = _xor_decode(raw, key)
            null_pos = decoded.find(b'\x00')
            if null_pos < 4:
                continue
            segment = decoded[:null_pos]
            if _is_printable_ascii(segment) and len(segment) >= 4:
                results.append(f"xor_single  key=0x{key:02x}  len={len(segment)}  \"{segment.decode('ascii', errors='replace')[:80]}\"")
                if len(results) >= limit:
                    break

        import base64
        try:
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
                    results.append(f"base64  len={len(decoded_b64)}  \"{decoded_b64[:64].decode('ascii', errors='replace')}\"")
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "ok": True,
        "addr": hex_ea(ea),
        "raw_hex": raw[:32].hex(),
        "results": "\n".join(results),
        "count": len(results),
    }


def _detect_signal_fallback(addr, limit):
    """Deterministic signal fallback when BehaviorClassifier is unavailable."""
    findings = []
    for func_ea in _iter_target_functions(addr):
        if len(findings) >= limit:
            break
        remaining = limit - len(findings)
        hits = _detect_encoding_in_func(func_ea, remaining)
        hits += _find_stack_strings(func_ea, remaining - len(hits))
        hits += _detect_api_hashing(func_ea, remaining - len(hits))
        hits += _detect_anti_disasm(func_ea, remaining - len(hits))
        findings.extend(hits)
    return findings[:limit]


def _detect_with_classifier(addr, limit):
    """Use BehaviorClassifier for semantic obfuscation detection."""
    clf = _get_behavior_classifier()
    if clf is None:
        return None  # signal caller to use fallback

    findings = []
    behavior_tags = []

    for func_ea in _iter_target_functions(addr):
        if len(findings) >= limit:
            break

        tags = _classify_function(func_ea, clf)
        if not tags:
            continue

        # Filter to obfuscation-relevant behaviors
        relevant = [t for t in tags if t["behavior"] in (
            "obfuscation_xor", "stack_strings", "api_hashing",
            "anti_debug", "anti_vm", "evasion", "string_decrypt",
        )]
        if not relevant:
            continue

        func_name = _get_func_name_safe(func_ea)
        tag_strs = [f"{t['behavior']}({t['confidence']:.2f})" for t in relevant]
        findings.append(f"{hex_ea(func_ea)}  {func_name}  {' '.join(tag_strs)}")
        behavior_tags.extend([{
            "addr": hex_ea(func_ea),
            "func": func_name,
            **t,
        } for t in relevant])

        # Auto-write high-confidence findings to blackboard
        scores = sorted(float(t.get("confidence", t.get("score", 0.0)) or 0.0) for t in relevant)
        q50 = scores[len(scores) // 2] if scores else 0.0
        q75 = scores[min(len(scores) - 1, int(round((len(scores) - 1) * 0.75)))] if scores else 0.0
        gate = q50 + max(0.0, q75 - q50)
        high_conf = [t for t in relevant if float(t.get("confidence", t.get("score", 0.0)) or 0.0) >= gate]
        if high_conf:
            _write_to_blackboard(
                hex_ea(func_ea),
                [t["behavior"] for t in high_conf],
                f"{func_name}: {' '.join(tag_strs)}",
            )

    return findings[:limit], behavior_tags


@tool
@idaread
def deobfuscate(
    action: Annotated[Literal["detect", "detect_encoding", "stack_strings",
                               "dead_code", "api_hashing", "dynamic_dispatch",
                               "anti_disasm", "decode_attempt"],
                      "Deobfuscation analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    key: Annotated[Optional[str],
                   "Decryption key for decode_attempt (hex string)"] = None,
    depth: Annotated[int, "Analysis depth"] = 2,
    **kwargs
) -> dict:
    """
    Deobfuscation analysis for binary reverse engineering.

    Actions:
    - detect: Semantic obfuscation detection via BehaviorClassifier (falls back to deterministic signals).
    - detect_encoding: Detect string encoding/encryption methods (XOR, Base64, RC4, custom).
    - stack_strings: Find strings built character-by-character on the stack.
    - dead_code: Find dead/unreachable code blocks.
    - api_hashing: Detect API hashing (ROR/hash constants near GetProcAddress calls).
    - dynamic_dispatch: Find dynamically resolved function calls.
    - anti_disasm: Detect anti-disassembly tricks.
    - decode_attempt: Attempt to decode an encoded value at addr.
    """
    try:
        if action == "decode_attempt":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for decode_attempt")
            ea, err = validate_addr(addr)
            if err:
                return err
            return _decode_attempt_at(ea, key, limit)

        if action == "detect":
            result = _detect_with_classifier(addr, limit)
            if result is None:
                # Fallback to deterministic signal detectors.
                all_findings = _detect_signal_fallback(addr, limit)
                return {
                    "ok": True,
                    "action": action,
                    "classifier": "deterministic_signal_fallback",
                    "findings": "\n".join(all_findings),
                    "count": len(all_findings),
                    "truncated": len(all_findings) >= limit,
                }
            findings, behavior_tags = result
            return {
                "ok": True,
                "action": action,
                "classifier": "BehaviorClassifier",
                "findings": "\n".join(findings),
                "behavior_tags": behavior_tags,
                "count": len(findings),
                "truncated": len(findings) >= limit,
            }

        # All other actions iterate over functions
        all_findings = []
        for func_ea in _iter_target_functions(addr):
            if len(all_findings) >= limit:
                break
            remaining = limit - len(all_findings)

            if action == "detect_encoding":
                hits = _detect_encoding_in_func(func_ea, remaining)
            elif action == "stack_strings":
                hits = _find_stack_strings(func_ea, remaining)
            elif action == "dead_code":
                hits = _find_dead_code(func_ea, remaining)
            elif action == "api_hashing":
                hits = _detect_api_hashing(func_ea, remaining)
            elif action == "dynamic_dispatch":
                hits = _find_dynamic_dispatch(func_ea, remaining)
            elif action == "anti_disasm":
                hits = _detect_anti_disasm(func_ea, remaining)
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

            all_findings.extend(hits)

        return {
            "ok": True,
            "action": action,
            "findings": "\n".join(all_findings[:limit]),
            "count": len(all_findings[:limit]),
            "truncated": len(all_findings) >= limit,
        }

    except Exception as e:
        return handle_error(e)
