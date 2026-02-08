
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import struct


# ============================================================================
# CRYPTO_ID - Cryptographic Algorithm Identification for LLMs
# ============================================================================

# AES S-Box (full 256 bytes)
_AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

# AES inverse S-Box (first 16 bytes for identification)
_AES_INV_SBOX_PREFIX = bytes([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
])

# SHA-256 initial hash values (H0..H7)
_SHA256_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# SHA-256 round constants (first 16 of 64)
_SHA256_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174]

# MD5 T constants (first 16)
_MD5_T = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
          0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
          0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
          0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821]

# MD5 init values
_MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

# SHA-1 constants
_SHA1_H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
_SHA1_K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

# CRC32 table (first 8 entries)
_CRC32_TABLE_PREFIX = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
                       0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3]

# Blowfish P-array (first 8 entries)
_BLOWFISH_P = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
               0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]

# DES initial permutation table (first 16 entries)
_DES_IP = bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4])

# Twofish MDS matrix constants
_TWOFISH_MDS = [0x01, 0xef, 0x5b, 0x5b]

# RC4 identity permutation marker (0x00..0x0F)
_RC4_INIT = bytes(range(16))

# Base64 alphabet
_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_URL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

# Base32 alphabet
_BASE32_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Hex encoding lookup
_HEX_LOWER = b"0123456789abcdef"
_HEX_UPPER = b"0123456789ABCDEF"

# RSA well-known small primes used in primality testing
_RSA_SMALL_PRIMES = [0x10001]  # Common RSA public exponent (65537)

# Adler32 MOD constant
_ADLER32_MOD = 65521

# Known crypto constant database: (name, algorithm, pattern_bytes_or_dwords, is_dword)
_CRYPTO_CONSTANTS = [
    ("AES S-Box", "AES", _AES_SBOX[:16], False),
    ("AES S-Box (full)", "AES", _AES_SBOX, False),
    ("AES Inverse S-Box", "AES", _AES_INV_SBOX_PREFIX, False),
    ("SHA-256 H values", "SHA-256", _SHA256_H[:4], True),
    ("SHA-256 K constants", "SHA-256", _SHA256_K[:4], True),
    ("MD5 T constants", "MD5", _MD5_T[:4], True),
    ("MD5 init values", "MD5", _MD5_INIT, True),
    ("SHA-1 H values", "SHA-1", _SHA1_H[:4], True),
    ("SHA-1 K constants", "SHA-1", _SHA1_K, True),
    ("CRC32 table", "CRC32", _CRC32_TABLE_PREFIX[:4], True),
    ("Blowfish P-array", "Blowfish", _BLOWFISH_P[:4], True),
    ("DES IP table", "DES", _DES_IP, False),
    ("Base64 alphabet", "Base64", _BASE64_ALPHABET, False),
    ("Base64 URL alphabet", "Base64-URL", _BASE64_URL_ALPHABET, False),
    ("Base32 alphabet", "Base32", _BASE32_ALPHABET, False),
]


def _dwords_to_bytes(dwords, endian="little"):
    """Convert a list of 32-bit integers to bytes."""
    fmt = "<I" if endian == "little" else ">I"
    return b"".join(struct.pack(fmt, d) for d in dwords)


def _search_bytes_in_segments(pattern, limit=50):
    """Search for a byte pattern across all segments. Returns list of hit dicts."""
    hits = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        seg_size = seg.size()
        # Cap segment read size for performance
        read_size = min(seg_size, 0x1000000)
        data = ida_bytes.get_bytes(seg.start_ea, read_size)
        if not data:
            continue
        offset = 0
        while len(hits) < limit:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            ea = seg.start_ea + idx
            seg_name = ida_segment.get_segm_name(seg)
            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(func.start_ea) if func else None
            hits.append(f"{hex(ea)}  {seg_name}  {func_name or 'no_func'}")
            offset = idx + len(pattern)
        if len(hits) >= limit:
            break
    return hits


def _search_dwords_in_segments(dwords, limit=50):
    """Search for a sequence of dwords (try both endians)."""
    hits = []
    for endian in ("little", "big"):
        pattern = _dwords_to_bytes(dwords, endian)
        found = _search_bytes_in_segments(pattern, limit - len(hits))
        for h in found:
            hits.append(f"{h}  endian={endian}")
        if len(hits) >= limit:
            break
    return hits


def _get_context_at(ea, count=5):
    """Get disassembly context lines around an address."""
    lines = []
    cur = ea
    for _ in range(count):
        if cur == idaapi.BADADDR:
            break
        lines.append(f"{hex(cur)}  {idc.generate_disasm_line(cur, 0)}")
        cur = idc.next_head(cur, cur + 0x1000)
    return lines


def _scan_for_xor_shift_loops(ea_start, ea_end, limit=50):
    """Scan a range for loops containing XOR+shift/rotate operations."""
    results = []
    ea = ea_start
    while ea < ea_end and ea != idaapi.BADADDR and len(results) < limit:
        mnem = idc.print_insn_mnem(ea)
        if mnem and mnem.lower() in ("xor", "shr", "shl", "ror", "rol"):
            func = ida_funcs.get_func(ea)
            if func:
                # Check if there are xrefs back (loop indicator)
                has_loop = False
                for xref in idautils.XrefsTo(ea, 0):
                    if func.start_ea <= xref.frm < func.end_ea and xref.frm > ea:
                        has_loop = True
                        break
                if not has_loop:
                    for xref in idautils.XrefsFrom(ea, 0):
                        if func.start_ea <= xref.to < ea:
                            has_loop = True
                            break
                if has_loop:
                    disasm = idc.generate_disasm_line(ea, 0)
                    results.append(f"{hex(ea)}  {idc.get_func_name(func.start_ea)}  {mnem}  {disasm}  [loop]")
        ea = idc.next_head(ea, ea_end)
    return results


def _analyze_function_ops(ea):
    """Count crypto-relevant operations in a function."""
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    counts = {"xor": 0, "shift": 0, "rotate": 0, "and": 0, "or": 0, "add": 0, "sub": 0, "mul": 0}
    cur = func.start_ea
    while cur < func.end_ea and cur != idaapi.BADADDR:
        mnem = (idc.print_insn_mnem(cur) or "").lower()
        if mnem == "xor":
            counts["xor"] += 1
        elif mnem in ("shr", "shl"):
            counts["shift"] += 1
        elif mnem in ("ror", "rol"):
            counts["rotate"] += 1
        elif mnem == "and":
            counts["and"] += 1
        elif mnem == "or":
            counts["or"] += 1
        elif mnem == "add":
            counts["add"] += 1
        elif mnem == "sub":
            counts["sub"] += 1
        elif mnem in ("mul", "imul"):
            counts["mul"] += 1
        cur = idc.next_head(cur, func.end_ea)
    return counts


@tool
@idaread
def crypto_id(
    action: Annotated[Literal["identify", "constants", "key_schedule", "block_cipher", "hash_detect", "rng_detect", "asymmetric", "custom_crypto", "encoding", "checksums"],
                      "Crypto identification action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    include_context: Annotated[bool, "Include surrounding code context"] = False,
    **kwargs
) -> dict:
    """
    Identify cryptographic algorithms, constants, and patterns in the binary.

    Actions:
    - identify: Identify crypto algorithms by constants/S-boxes at an address or globally.
    - constants: Find known cryptographic constants (AES S-box, SHA magic numbers, CRC tables, etc.).
    - key_schedule: Detect key schedule patterns (loops with XOR/shift/rotate operations).
    - block_cipher: Detect block cipher patterns (substitution-permutation networks).
    - hash_detect: Detect hash function patterns (Merkle-Damgard construction, round functions).
    - rng_detect: Detect random number generators (PRNG, CSPRNG patterns).
    - asymmetric: Detect asymmetric crypto (RSA modular exponentiation, ECC point ops).
    - custom_crypto: Detect custom/homebrew cryptographic implementations.
    - encoding: Detect encoding algorithms (Base64, Base32, hex encoding/decoding tables).
    - checksums: Detect checksum algorithms (CRC32, Adler32, Fletcher, etc.).
    """
    try:

        if action == "identify":
            # Comprehensive identification: search all known constants
            findings = []
            algos_found = set()
            search_scope = None
            if addr:
                ea, err = validate_addr(addr)
                if err:
                    return err
                search_scope = ea

            for name, algo, pattern, is_dword in _CRYPTO_CONSTANTS:
                if is_dword:
                    hits = _search_dwords_in_segments(pattern, limit)
                else:
                    hits = _search_bytes_in_segments(pattern, limit)
                for h in hits:
                    # h is a string like "0x12345  .text  func_name"
                    hit_addr_str = h.split()[0] if h else "0x0"
                    hit_ea = int(hit_addr_str, 16)
                    if search_scope is not None:
                        func = ida_funcs.get_func(search_scope)
                        if func and not (func.start_ea <= hit_ea < func.end_ea):
                            continue
                        elif not func and abs(hit_ea - search_scope) > 0x10000:
                            continue
                    findings.append(f"{h}  const={name}  algo={algo}")
                    algos_found.add(algo)
                    if len(findings) >= limit:
                        break
                if len(findings) >= limit:
                    break

            return {"ok": True, "findings": "\n".join(findings), "algorithms_found": sorted(algos_found), "count": len(findings)}

        elif action == "constants":
            findings = []
            for name, algo, pattern, is_dword in _CRYPTO_CONSTANTS:
                if is_dword:
                    hits = _search_dwords_in_segments(pattern, limit - len(findings))
                else:
                    hits = _search_bytes_in_segments(pattern, limit - len(findings))
                for h in hits:
                    findings.append(f"{h}  const={name}  algo={algo}")
                if len(findings) >= limit:
                    break
            return {"ok": True, "findings": "\n".join(str(f) for f in findings), "count": len(findings)}

        elif action == "key_schedule":
            results = []
            if addr:
                ea, err = validate_addr(addr)
                if err:
                    return err
                func = ida_funcs.get_func(ea)
                if not func:
                    return make_error(MCPError.ADDRESS_INVALID, "No function at address")
                xsl = _scan_for_xor_shift_loops(func.start_ea, func.end_ea, limit)
                ops = _analyze_function_ops(ea)
                if xsl:
                    entry = {
                        "func": idc.get_func_name(func.start_ea),
                        "addr": hex(func.start_ea),
                        "xor_shift_loops": xsl,
                        "op_counts": ops,
                        "likely_key_schedule": True,
                    }
                    if include_context:
                        entry["context"] = _get_context_at(func.start_ea)
                    results.append(entry)
            else:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    func = ida_funcs.get_func(func_ea)
                    if not func or (func.end_ea - func.start_ea) < 32:
                        continue
                    ops = _analyze_function_ops(func_ea)
                    if not ops:
                        continue
                    # Heuristic: key schedules typically have many XORs and shifts/rotates
                    if ops["xor"] >= 4 and (ops["shift"] + ops["rotate"]) >= 2:
                        xsl = _scan_for_xor_shift_loops(func.start_ea, func.end_ea, 10)
                        if xsl:
                            entry = {
                                "func": idc.get_func_name(func_ea),
                                "addr": hex(func_ea),
                                "op_counts": ops,
                                "xor_shift_loop_count": len(xsl),
                                "likely_key_schedule": True,
                            }
                            if include_context:
                                entry["context"] = _get_context_at(func_ea)
                            results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "block_cipher":
            # Detect SPN (substitution-permutation network) patterns
            results = []
            # First check for known S-box constants
            sbox_hits = _search_bytes_in_segments(_AES_SBOX[:16], limit)
            for h in sbox_hits:
                results.append(f"{h}")

            # Scan functions for SPN-like patterns: high XOR + shift + table lookups
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    func = ida_funcs.get_func(func_ea)
                    if not func or (func.end_ea - func.start_ea) < 64:
                        continue
                    ops = _analyze_function_ops(func_ea)
                    if not ops:
                        continue
                    # SPN heuristic: many XORs, shifts, and ANDs (byte masking for S-box lookup)
                    if ops["xor"] >= 8 and ops["shift"] >= 4 and ops["and"] >= 4:
                        entry = {
                            "type": "spn_pattern",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                            "op_counts": ops,
                            "likely_block_cipher": True,
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "hash_detect":
            results = []
            # Search for known hash constants
            hash_consts = [
                ("SHA-256 H", _SHA256_H[:4]),
                ("SHA-256 K", _SHA256_K[:4]),
                ("MD5 T", _MD5_T[:4]),
                ("MD5 init", _MD5_INIT),
                ("SHA-1 H", _SHA1_H[:4]),
                ("SHA-1 K", _SHA1_K),
            ]
            for cname, dwords in hash_consts:
                if len(results) >= limit:
                    break
                hits = _search_dwords_in_segments(dwords, limit - len(results))
                for h in hits:
                    results.append(f"{h}")

            # Scan for Merkle-Damgard-like functions: many rotates/shifts + XOR + add
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    func = ida_funcs.get_func(func_ea)
                    if not func or (func.end_ea - func.start_ea) < 100:
                        continue
                    ops = _analyze_function_ops(func_ea)
                    if not ops:
                        continue
                    # Hash round functions: many rotates + XOR + add
                    if (ops["rotate"] + ops["shift"]) >= 6 and ops["xor"] >= 4 and ops["add"] >= 4:
                        entry = {
                            "type": "hash_round_function",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                            "op_counts": ops,
                            "likely_hash": True,
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "rng_detect":
            results = []
            # Linear congruential generator constants
            lcg_consts = [
                ("glibc LCG multiplier", [0x41C64E6D]),
                ("MINSTD multiplier", [0x41A7]),  # 16807
                ("Mersenne Twister", [0x6C078965]),
                ("MMIX LCG multiplier", [0x5851F42D, 0x4C957F2D]),
            ]
            for cname, dwords in lcg_consts:
                if len(results) >= limit:
                    break
                hits = _search_dwords_in_segments(dwords, limit - len(results))
                for h in hits:
                    results.append(f"{h}")

            # Scan for RNG patterns: mul + add + and (masking)
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        continue
                    func_size = func.end_ea - func.start_ea
                    if func_size < 16 or func_size > 512:
                        continue
                    ops = _analyze_function_ops(func_ea)
                    if not ops:
                        continue
                    fname = idc.get_func_name(func_ea).lower()
                    name_hint = any(kw in fname for kw in ("rand", "random", "seed", "prng", "rng"))
                    # LCG pattern: mul + add + shift/and
                    if ops["mul"] >= 1 and ops["add"] >= 1 and (ops["shift"] >= 1 or ops["and"] >= 1):
                        if name_hint or (ops["mul"] >= 1 and ops["xor"] >= 1):
                            entry = {
                                "type": "rng_pattern",
                                "func": idc.get_func_name(func_ea),
                                "addr": hex(func_ea),
                                "op_counts": ops,
                                "name_hint": name_hint,
                            }
                            if include_context:
                                entry["context"] = _get_context_at(func_ea)
                            results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "asymmetric":
            results = []
            # RSA: look for public exponent 0x10001 (65537) and modular exponentiation
            rsa_exp_pattern_le = struct.pack("<I", 0x10001)
            rsa_exp_pattern_be = struct.pack(">I", 0x10001)
            for pat, endian in [(rsa_exp_pattern_le, "little"), (rsa_exp_pattern_be, "big")]:
                if len(results) >= limit:
                    break
                hits = _search_bytes_in_segments(pat, limit - len(results))
                for h in hits:
                    results.append(f"{h}")

            # Scan for modular exponentiation patterns: many mul + and + shift (squaring)
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    func = ida_funcs.get_func(func_ea)
                    if not func or (func.end_ea - func.start_ea) < 64:
                        continue
                    ops = _analyze_function_ops(func_ea)
                    if not ops:
                        continue
                    fname = idc.get_func_name(func_ea).lower()
                    name_hint = any(kw in fname for kw in ("rsa", "modpow", "modexp", "bignum", "bn_", "ecc", "ec_", "point", "curve"))
                    if name_hint:
                        entry = {
                            "type": "asymmetric_name_match",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                            "op_counts": ops,
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
                    elif ops["mul"] >= 4 and ops["shift"] >= 2 and ops["and"] >= 2:
                        entry = {
                            "type": "modular_arithmetic_pattern",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                            "op_counts": ops,
                            "likely_modexp": True,
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "custom_crypto":
            results = []
            for func_ea in idautils.Functions():
                if len(results) >= limit:
                    break
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                func_size = func.end_ea - func.start_ea
                if func_size < 64:
                    continue
                ops = _analyze_function_ops(func_ea)
                if not ops:
                    continue
                total_crypto_ops = ops["xor"] + ops["shift"] + ops["rotate"]
                # High density of crypto-relevant operations without matching known constants
                if total_crypto_ops >= 10 and ops["xor"] >= 3:
                    # Check if this function references any known constant
                    func_bytes = ida_bytes.get_bytes(func.start_ea, min(func_size, 4096))
                    known_match = False
                    if func_bytes:
                        for _, _, pat, is_dw in _CRYPTO_CONSTANTS:
                            check_pat = _dwords_to_bytes(pat) if is_dw else pat
                            if check_pat[:8] in func_bytes:
                                known_match = True
                                break
                    if not known_match:
                        density = round(total_crypto_ops / (func_size / 16), 2)
                        entry = {
                            "type": "custom_crypto_candidate",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                            "size": func_size,
                            "op_counts": ops,
                            "crypto_op_density": density,
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "encoding":
            results = []
            encoding_patterns = [
                ("Base64 alphabet", "Base64", _BASE64_ALPHABET),
                ("Base64 URL alphabet", "Base64-URL", _BASE64_URL_ALPHABET),
                ("Base32 alphabet", "Base32", _BASE32_ALPHABET),
                ("Hex lowercase", "Hex", _HEX_LOWER),
                ("Hex uppercase", "Hex", _HEX_UPPER),
            ]
            for cname, algo, pat in encoding_patterns:
                if len(results) >= limit:
                    break
                hits = _search_bytes_in_segments(pat, limit - len(results))
                for h in hits:
                    results.append(f"{h}  const={cname}  algo={algo}")

            # Look for functions with encoding-related names
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    fname = idc.get_func_name(func_ea).lower()
                    if any(kw in fname for kw in ("base64", "b64", "base32", "b32", "hex_encode", "hex_decode", "encode", "decode")):
                        entry = {
                            "type": "encoding_function",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "checksums":
            results = []
            # CRC32 table detection
            crc_hits = _search_dwords_in_segments(_CRC32_TABLE_PREFIX[:4], limit)
            for h in crc_hits:
                results.append(f"{h}")

            # Adler32 MOD constant (65521 = 0xFFF1)
            if len(results) < limit:
                adler_le = struct.pack("<H", _ADLER32_MOD)
                adler_hits = _search_bytes_in_segments(adler_le, limit - len(results))
                for h in adler_hits:
                    results.append(f"{h}")

            # Scan for checksum function names
            if len(results) < limit:
                for func_ea in idautils.Functions():
                    if len(results) >= limit:
                        break
                    fname = idc.get_func_name(func_ea).lower()
                    if any(kw in fname for kw in ("crc", "checksum", "adler", "fletcher", "cksum")):
                        entry = {
                            "type": "checksum_function",
                            "func": idc.get_func_name(func_ea),
                            "addr": hex(func_ea),
                        }
                        if include_context:
                            entry["context"] = _get_context_at(func_ea)
                        results.append(entry)
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
