
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import struct
import math
from collections import Counter


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

_AES_INV_SBOX_PREFIX = bytes([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
])

_SHA256_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
_SHA256_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174]
_MD5_T = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
          0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
          0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
          0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821]
_MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
_SHA1_H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
_SHA1_K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]
_CRC32_TABLE_PREFIX = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
                       0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3]
_BLOWFISH_P = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
               0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]
_DES_IP = bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4])
_TWOFISH_MDS = [0x01, 0xef, 0x5b, 0x5b]
_RC4_INIT = bytes(range(16))
_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_URL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_BASE32_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_HEX_LOWER = b"0123456789abcdef"
_HEX_UPPER = b"0123456789ABCDEF"
_ADLER32_MOD = 65521

# ChaCha20 constants
_CHACHA20_CONSTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
# Blake2b IV
_BLAKE2B_IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
               0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
# SHA-3 round constants (Keccak)
_SHA3_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000]

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
    ("ChaCha20 sigma", "ChaCha20", _CHACHA20_CONSTS, True),
    ("Blake2b IV", "Blake2", _BLAKE2B_IV[:4], "qword"),
    ("SHA-3 RC", "SHA-3/Keccak", _SHA3_RC[:2], "qword"),
]


def _dwords_to_bytes(dwords, endian="little"):
    fmt = "<I" if endian == "little" else ">I"
    return b"".join(struct.pack(fmt, d) for d in dwords)


def _qwords_to_bytes(qwords, endian="little"):
    fmt = "<Q" if endian == "little" else ">Q"
    return b"".join(struct.pack(fmt, q) for q in qwords)


def _search_bytes_in_segments(pattern, limit=50):
    hits = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        seg_size = seg.size()
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
    hits = []
    for endian in ("little", "big"):
        try:
            pattern = _dwords_to_bytes(dwords, endian)
        except struct.error:
            continue
        found = _search_bytes_in_segments(pattern, limit - len(hits))
        for h in found:
            hits.append(f"{h}  endian={endian}")
        if len(hits) >= limit:
            break
    return hits

def _search_qwords_in_segments(qwords, limit=50):
    hits = []
    for endian in ("little", "big"):
        try:
            pattern = _qwords_to_bytes(qwords, endian)
        except struct.error:
            continue
        found = _search_bytes_in_segments(pattern, limit - len(hits))
        for h in found:
            hits.append(f"{h}  endian={endian}")
        if len(hits) >= limit:
            break
    return hits


def _get_context_at(ea, count=5):
    lines = []
    cur = ea
    for _ in range(count):
        if cur == idaapi.BADADDR:
            break
        lines.append(f"{hex(cur)}  {ida_lines.tag_remove(idc.generate_disasm_line(cur, 0))}")
        cur = idc.next_head(cur, cur + 0x1000)
    return lines


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


def _detect_aes_ni(limit):
    results = []
    aes_ni_mnems = {"aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc", "aeskeygenassist"}
    for func_ea in idautils.Functions():
        if len(results) >= limit:
            break
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        found = []
        for item in idautils.FuncItems(func_ea):
            mnem = (idc.print_insn_mnem(item) or "").lower()
            if mnem in aes_ni_mnems:
                found.append(f"{hex(item)}  {mnem}")
        if found:
            results.append({
                "func": idc.get_func_name(func_ea),
                "addr": hex(func_ea),
                "aes_ni_insns": found,
                "count": len(found),
            })
    return results


@tool
@idaread
def crypto_id(
    action: Annotated[Literal[
        "identify", "constants", "encoding", "checksums", "entropy_analysis", "aes_ni"
    ], "Crypto identification action"],
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
    - encoding: Detect encoding algorithms (Base64, Base32, hex encoding/decoding tables).
    - checksums: Detect checksum algorithms (CRC32, Adler32, Fletcher, etc.).
    - entropy_analysis: Find functions with high entropy code/data (packed/encrypted regions).
    - aes_ni: Detect AES-NI instruction usage (aesenc, aeskeygenassist, etc.).
    """
    try:
        if action == "identify":
            findings = []
            algos_found = set()
            search_scope = None
            if addr:
                ea, err = validate_addr(addr)
                if err:
                    return err
                search_scope = ea
            for name, algo, pattern, mode in _CRYPTO_CONSTANTS:
                if mode == "qword":
                    hits = _search_qwords_in_segments(pattern, limit)
                elif mode:
                    hits = _search_dwords_in_segments(pattern, limit)
                else:
                    hits = _search_bytes_in_segments(pattern, limit)
                for h in hits:
                    hit_addr_str = h.split()[0] if h else "0x0"
                    hit_ea = int(hit_addr_str, 16)
                    if search_scope is not None:
                        func = ida_funcs.get_func(search_scope)
                        if func and not (func.start_ea <= hit_ea < func.end_ea):
                            continue
                        elif not func:
                            seg = idaapi.getseg(search_scope)
                            hit_seg = idaapi.getseg(hit_ea)
                            if seg and hit_seg and seg.start_ea != hit_seg.start_ea:
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
            for name, algo, pattern, mode in _CRYPTO_CONSTANTS:
                if mode == "qword":
                    hits = _search_qwords_in_segments(pattern, limit)
                elif mode:
                    hits = _search_dwords_in_segments(pattern, limit)
                else:
                    hits = _search_bytes_in_segments(pattern, limit)
                for h in hits:
                    hit_addr_str = h.split()[0] if h else "0x0"
                    hit_ea = int(hit_addr_str, 16)
                    if search_scope is not None:
                        func = ida_funcs.get_func(search_scope)
                        if func and not (func.start_ea <= hit_ea < func.end_ea):
                            continue
                        elif not func:
                            seg = idaapi.getseg(search_scope)
                            hit_seg = idaapi.getseg(hit_ea)
                            if seg and hit_seg and seg.start_ea != hit_seg.start_ea:
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
            for name, algo, pattern, mode in _CRYPTO_CONSTANTS:
                if mode == "qword":
                    hits = _search_qwords_in_segments(pattern, limit - len(findings))
                elif mode:
                    hits = _search_dwords_in_segments(pattern, limit - len(findings))
                else:
                    hits = _search_bytes_in_segments(pattern, limit - len(findings))
                for h in hits:
                    findings.append(f"{h}  const={name}  algo={algo}")
                if len(findings) >= limit:
                    break
            return {"ok": True, "findings": "\n".join(str(f) for f in findings), "count": len(findings)}

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
            crc_hits = _search_dwords_in_segments(_CRC32_TABLE_PREFIX[:4], limit)
            for h in crc_hits:
                results.append(f"{h}")
            if len(results) < limit:
                adler_le = struct.pack("<H", _ADLER32_MOD)
                adler_hits = _search_bytes_in_segments(adler_le, limit - len(results))
                for h in adler_hits:
                    results.append(f"{h}")
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

        elif action == "entropy_analysis":
            results = []
            for func_ea in idautils.Functions():
                if len(results) >= limit:
                    break
                func = ida_funcs.get_func(func_ea)
                if not func or (func.end_ea - func.start_ea) < 64:
                    continue
                func_bytes = ida_bytes.get_bytes(func.start_ea, min(func.end_ea - func.start_ea, 4096))
                if not func_bytes:
                    continue
                ent = _shannon_entropy(func_bytes)
                if ent >= 6.5:
                    results.append({
                        "func": idc.get_func_name(func_ea),
                        "addr": hex(func_ea),
                        "entropy": ent,
                        "size": len(func_bytes),
                        "note": "High entropy may indicate packed/encrypted code or crypto constants",
                    })
            return {"ok": True, "findings": "\n".join(str(f) for f in results), "count": len(results)}

        elif action == "aes_ni":
            hits = _detect_aes_ni(limit)
            return {"ok": True, "findings": "\n".join(str(f) for f in hits), "count": len(hits)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
