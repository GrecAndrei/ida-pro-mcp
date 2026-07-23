"""security — Unified security analysis tool.

Consolidates 7 former tools into one with real deduplication:
- packer, hooks, deobfuscate, crypto_id, entropy, protocol, taint

11 actions. Shared constants defined once. Unified analysis functions.

Actions:
  detect         — packer + entropy + crypto + obfuscation in one pass
  decode         — decode bytes at addr (XOR brute force, Base64)
  analyze        — scan for patterns (what=stack_strings|dead_code|api_hashing|
                   dynamic_dispatch|anti_disasm|crypto_constants|encoding|
                   checksums|entropy_high|aes_ni)
  hook           — generate instrumentation (method=frida|detours|inline)
  hook_targets   — find hookable functions (by category or importance)
  protocol       — detect protocol usage
  protocol_spec  — recover protocol structure (what=...)
  taint          — trace data flow source→sink
  taint_sources  — list taint sources
  taint_report   — full taint report
  eval           — run custom Python with all helpers + IDA SDK
"""

from __future__ import annotations

import base64
import math
import os
import re
import struct
import sys
import time
from collections import Counter
from typing import Annotated, Dict, List, Optional

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from ..support.taint_registry import (
    TAINT_SOURCES,
    DANGEROUS_SINKS,
    VULN_TYPE_TO_CWE,
)

# BehaviorClassifier for semantic analysis (optional, heavy dep)
try:
    from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
except ImportError:
    try:
        from host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder
    except ImportError:
        BehaviorClassifier = None
        BgeCodeEmbedder = None

# Blackboard for auto-writing findings
try:
    from .blackboard import BlackboardStore
except ImportError:
    try:
        from blackboard import BlackboardStore
    except ImportError:
        BlackboardStore = None


from ..support.crypto_registry import (
    KNOWN_HASH_CONSTANTS,
    HASH_RESOLVE_FUNCS,
    PACKER_SIGNATURES,
    PACKER_DISPLAY_NAMES,
    ANTI_DEBUG_APIS,
    ANTI_VM_STRINGS,
    GAME_ANTI_CHEAT,
    findcrypt_rules_dir,
)

# Aliases for code that references the old local names
_CRYPTO_SIGNATURES = []  # Replaced by YARA scanning below
_PACKER_SIGNATURES = PACKER_SIGNATURES
_ANTI_DEBUG_APIS = ANTI_DEBUG_APIS
_ANTI_VM_STRINGS = ANTI_VM_STRINGS
_GAME_ANTI_CHEAT = GAME_ANTI_CHEAT
_PACKER_DISPLAY = PACKER_DISPLAY_NAMES
_HASH_RESOLVE_FUNCS = HASH_RESOLVE_FUNCS
_KNOWN_HASH_CONSTANTS = KNOWN_HASH_CONSTANTS

# Encoding alphabets (small, stable, used by decode action — not worth downloading)
_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_URL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_BASE32_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_HEX_LOWER = b"0123456789abcdef"
_HEX_UPPER = b"0123456789ABCDEF"

_MOV_MNEMONICS = MOV_MNEMONICS
_COND_JUMPS = CONDITIONAL_BRANCH_MNEMONICS
_TERMINATORS = TERMINATOR_MNEMONICS
_CALL_MNEMONICS = CALL_MNEMONICS
_XOR_MNEMONICS = XOR_MNEMONICS

# --- Hook patterns ---

_HOOK_PATTERNS = {
    "network": ["send", "recv", "connect", "socket", "WSA", "accept", "bind", "listen",
                "getaddrinfo", "gethostby", "inet_", "http", "curl", "ssl", "tls"],
    "file": ["CreateFile", "ReadFile", "WriteFile", "fopen", "fread", "fwrite",
             "open", "read", "write", "close", "NtCreateFile", "NtReadFile"],
    "crypto": ["Crypt", "BCrypt", "NCrypt", "AES", "RSA", "SHA", "MD5", "hash",
               "encrypt", "decrypt", "cipher", "key", "EVP_"],
    "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreate", "NtOpenKey"],
    "process": ["CreateProcess", "VirtualAlloc", "VirtualProtect", "LoadLibrary",
                "GetProcAddress", "NtAllocate", "mmap", "mprotect", "execve", "fork"],
}

# --- Protocol ---

_NETWORK_APIS = {
    "socket": ["socket", "WSASocket", "WSASocketA", "WSASocketW"],
    "connect": ["connect", "WSAConnect"],
    "bind": ["bind"],
    "listen": ["listen"],
    "accept": ["accept", "WSAAccept"],
    "send": ["send", "sendto", "WSASend", "WSASendTo"],
    "recv": ["recv", "recvfrom", "WSARecv", "WSARecvFrom"],
    "close": ["closesocket", "close", "shutdown"],
    "dns": ["getaddrinfo", "gethostbyname", "gethostbyaddr"],
    "http": ["InternetOpen", "InternetConnect", "HttpOpenRequest",
             "HttpSendRequest", "WinHttpOpen", "WinHttpConnect",
             "curl_easy_init", "curl_easy_perform"],
    "tls": ["SSL_new", "SSL_connect", "SSL_accept", "SSL_read", "SSL_write",
            "SSL_CTX_new", "SSL_CTX_set_cipher_list",
            "mbedtls_ssl_handshake", "mbedtls_ssl_read"],
    "byte_order": ["ntohs", "ntohl", "htons", "htonl"],
    "init": ["WSAStartup", "WSACleanup"],
}

_TLS_CONFIG_APIS = [
    "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites",
    "SSL_CTX_set_verify", "SSL_CTX_load_verify_locations",
    "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file",
    "SSL_CTX_set_min_proto_version", "SSL_CTX_set_max_proto_version",
    "SSL_get_peer_certificate", "SSL_get_verify_result",
    "mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_ca_chain",
    "mbedtls_x509_crt_parse",
]

_KNOWN_MAGIC = {
    0x474554: ("HTTP GET", "ASCII 'GET'"),
    0x504F5354: ("HTTP POST", "ASCII 'POST'"),
    0x48545450: ("HTTP", "ASCII 'HTTP'"),
    0x16030100: ("TLS 1.0 Handshake", "TLS record layer"),
    0x16030300: ("TLS 1.2 Handshake", "TLS record layer"),
    0x4D515454: ("MQTT", "ASCII 'MQTT'"),
    0x89504E47: ("PNG", "PNG header"),
    0x7F454C46: ("ELF", "ELF header"),
    0x504B0304: ("ZIP/APK", "PK header"),
}

_PROTOCOL_ANCHORS = {
    "http_protocol": "HTTP_GET HTTP_POST Content-Type User-Agent url_encode http_connect recv_response parse_headers",
    "tls_ssl": "SSL_connect TLS_client_hello certificate_verify handshake_state cipher_suite x509",
    "custom_binary": "magic_bytes packet_header length_field checksum_verify parse_packet serialize_packet",
    "dns_protocol": "dns_query dns_response A_record AAAA_record resolve_hostname nslookup",
    "smtp_ftp": "EHLO MAIL FROM RCPT TO DATA QUIT FTP_connect PASV PORT",
}


# ============================================================
# SHARED HELPERS — one implementation, used by all analysis
# ============================================================

def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0.0–8.0)."""
    if not data:
        return 0.0
    occ = Counter(data)
    ent = 0.0
    for count in occ.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return round(ent, 4)


def _compute_entropy(start_ea: int, length: int) -> float:
    """Read bytes from IDA and compute entropy."""
    data = ida_bytes.get_bytes(start_ea, length)
    if not data:
        return 0.0
    return _shannon_entropy(data)


def _bytes_to_dwords(data: bytes, endian="little") -> List[int]:
    fmt = "<I" if endian == "little" else ">I"
    count = len(data) // 4
    return list(struct.unpack(fmt * count, data[:count * 4]))


def _bytes_to_qwords(data: bytes, endian="little") -> List[int]:
    fmt = "<Q" if endian == "little" else ">Q"
    count = len(data) // 8
    return list(struct.unpack(fmt * count, data[:count * 8]))


def _dwords_to_bytes(dwords, endian="little"):
    fmt = "<I" if endian == "little" else ">I"
    return b"".join(struct.pack(fmt, d) for d in dwords)


def _qwords_to_bytes(qwords, endian="little"):
    fmt = "<Q" if endian == "little" else ">Q"
    return b"".join(struct.pack(fmt, q) for q in qwords)


def _search_bytes(pattern: bytes, limit: int = 50) -> List[str]:
    """Search all segments for a byte pattern. Returns hex addresses."""
    hits = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        data = ida_bytes.get_bytes(seg.start_ea, min(seg.size(), 0x1000000))
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


def _search_dwords(dwords, limit=50) -> List[str]:
    hits = []
    for endian in ("little", "big"):
        pattern = _dwords_to_bytes(dwords, endian)
        found = _search_bytes(pattern, limit - len(hits))
        for h in found:
            hits.append(f"{h}  endian={endian}")
        if len(hits) >= limit:
            break
    return hits


def _search_qwords(qwords, limit=50) -> List[str]:
    hits = []
    for endian in ("little", "big"):
        pattern = _qwords_to_bytes(qwords, endian)
        found = _search_bytes(pattern, limit - len(hits))
        for h in found:
            hits.append(f"{h}  endian={endian}")
        if len(hits) >= limit:
            break
    return hits


def _scan_section_names() -> List[str]:
    names = []
    try:
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if seg:
                name = ida_segment.get_segm_name(seg) or ""
                if name:
                    names.append(name)
    except Exception:
        pass
    return names


def _scan_string_references(max_strings: int = 5000) -> List[str]:
    out = []
    try:
        qty = int(idaapi.get_strlist_qty())
        for i in range(min(qty, max_strings)):
            try:
                si = idaapi.get_string(i)
                if not si:
                    continue
                text = ""
                try:
                    if hasattr(si, "str"):
                        text = str(si.str or "")
                except Exception:
                    pass
                if not text and hasattr(si, "contents"):
                    try:
                        raw = bytes(si.contents or b"")
                        text = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    except Exception:
                        pass
                if text:
                    out.append(text.lower())
            except Exception:
                continue
    except Exception:
        pass
    return out


def _scan_import_names() -> List[str]:
    names = []
    try:
        for i in range(int(ida_nalt.get_import_module_qty())):
            try:
                def cb(ea, name, ordinal):
                    if name:
                        names.append(str(name))
                    return True
                ida_nalt.enum_import_names(i, cb)
            except Exception:
                continue
    except Exception:
        pass
    return names


def _get_import_addrs(name_set: set) -> Dict[str, int]:
    result = {}
    try:
        for i in range(idaapi.get_import_module_qty()):
            def _cb(ea, name, ord_):
                if name and name in name_set:
                    result[name] = ea
                return True
            idaapi.enum_import_names(i, _cb)
    except Exception:
        pass
    return result


def _read_section_bytes(seg_name_pattern: str, max_bytes: int = 0x10000) -> bytes:
    pat = seg_name_pattern.lower()
    try:
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if not seg:
                continue
            name = (ida_segment.get_segm_name(seg) or "").lower()
            if pat in name:
                size = min(int(seg.size() or 0), max_bytes)
                if size > 0:
                    return bytes(ida_bytes.get_bytes(seg.start_ea, size) or b"")
    except Exception:
        pass
    return b""


def _is_printable_ascii(data: bytes) -> bool:
    for b in data:
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return False
    return True


def _xor_decode(data: bytes, key_byte: int) -> bytes:
    return bytes(b ^ key_byte for b in data)


def _get_context_at(ea, count=5):
    lines = []
    cur = ea
    for _ in range(count):
        if cur == idaapi.BADADDR:
            break
        lines.append(f"{hex(cur)}  {ida_lines.tag_remove(idc.generate_disasm_line(cur, 0))}")
        cur = idc.next_head(cur, cur + 0x1000)
    return lines


def _safe_start_ea() -> int:
    try:
        if hasattr(ida_ida, "inf_get_start_ea"):
            ea = int(ida_ida.inf_get_start_ea())
            if ea and ea != idaapi.BADADDR:
                return ea
    except Exception:
        pass
    return 0


def _get_func_name_safe(ea: int) -> str:
    func = idaapi.get_func(ea)
    return ida_funcs.get_func_name(func.start_ea) if func else "unknown"


def _iter_target_functions(addr):
    if addr is not None:
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return
        yield ea
    else:
        for ea in idautils.Functions():
            yield ea


def _bb_write(title, content, category="findings", addr=None, tags=None, confidence=0.8, source="security"):
    if BlackboardStore is None:
        return
    try:
        store = BlackboardStore()
        store.write(title=title, content=content, category=category,
                    addr=addr, tags=tags or [], confidence=confidence, source=source)
    except Exception:
        pass


# ============================================================
# UNIFIED ANALYSIS FUNCTIONS
# Each function merges multiple former tools/actions into one
# ============================================================

# --- scan_crypto_constants ---
# Merges: crypto_id.identify + crypto_id.constants + crypto_id.encoding
#         + crypto_id.checksums + crypto_id.entropy_analysis + crypto_id.aes_ni
#         + entropy.crypto_detect
# ONE function scans for ALL crypto indicators.

def _scan_crypto_constants(scope_ea=None, limit=50) -> dict:
    """Unified crypto scanner: constants, S-boxes, encoding tables, checksums,
    high-entropy functions, and AES-NI instructions."""

    def in_scope(hit_str):
        if scope_ea is None:
            return True
        try:
            hit_ea = int(hit_str.split()[0], 16)
        except (ValueError, IndexError):
            return True
        func = ida_funcs.get_func(scope_ea)
        if func:
            return func.start_ea <= hit_ea < func.end_ea
        return True

    findings = []
    algos = set()

    # 1. Scan for crypto constants using FindCrypt YARA rules
    fc_dir = findcrypt_rules_dir()
    if fc_dir:
        try:
            from ida_pro_mcp.host.intelligence.yara_scanner import compile_rules
            from ida_pro_mcp.ida_mcp.support.crypto_registry import CRYPTO_CONSTANT_NAMES
            rules, _fe, _ce = compile_rules(fc_dir)
            if rules:
                def _read_idb_bytes(start, size):
                    return ida_bytes.get_bytes(start, size) or b""

                def _identify_constant_at(ea):
                    """Try to identify a known crypto constant at the given address."""
                    try:
                        data4 = ida_bytes.get_bytes(ea, 4)
                        if data4 and len(data4) == 4:
                            val_le = int.from_bytes(data4, "little")
                            val_be = int.from_bytes(data4, "big")
                            name = CRYPTO_CONSTANT_NAMES.get(val_le) or CRYPTO_CONSTANT_NAMES.get(val_be)
                            if name:
                                return name
                        data8 = ida_bytes.get_bytes(ea, 8)
                        if data8 and len(data8) == 8:
                            val_le = int.from_bytes(data8, "little")
                            val_be = int.from_bytes(data8, "big")
                            name = CRYPTO_CONSTANT_NAMES.get(val_le) or CRYPTO_CONSTANT_NAMES.get(val_be)
                            if name:
                                return name
                    except Exception:
                        pass
                    return None

                matches = rules.match(data=_read_idb_bytes, callback_data=None)
                for m in matches[:limit]:
                    meta = getattr(m, "meta", {})
                    rule_name = getattr(m, "rule", "unknown")
                    desc = meta.get("description", rule_name)
                    # Better algorithm guessing from rule name
                    algo_guess = "Unknown"
                    rule_upper = rule_name.upper()
                    for algo_key in ("AES", "SHA256", "SHA512", "SHA1", "MD5",
                                     "CRC32", "BLOWFISH", "DES", "BASE64",
                                     "WHIRLPOOL", "RIPEMD", "TEA", "CHACHA",
                                     "SALSA", "RSA", "DSA", "RC6"):
                        if algo_key in rule_upper:
                            algo_guess = algo_key
                            break
                    # Extract address from matched strings
                    addr_str = ""
                    if hasattr(m, "strings"):
                        for s in m.strings:
                            try:
                                # yara-python: (offset, identifier, data) or (offset, identifier)
                                offset = s[0] if isinstance(s[0], int) else None
                                if offset is not None:
                                    addr_str = hex(offset)
                                    break
                            except (IndexError, TypeError):
                                pass
                    # Enrich with registry constant name
                    const_name = ""
                    if addr_str:
                        const_name = _identify_constant_at(int(addr_str, 16))
                    label = f"{const_name} ({desc})" if const_name else desc
                    entry = f"{addr_str}  {label}  algo={algo_guess}" if addr_str else f"{label}  algo={algo_guess}"
                    findings.append(entry)
                    algos.add(algo_guess)
                    if len(findings) >= limit:
                        break
        except Exception:
            pass

    # Fallback: if YARA unavailable, try the old byte scanning approach
    if not findings and _CRYPTO_SIGNATURES:
        for name, algo, pattern, mode in _CRYPTO_SIGNATURES:
            if len(findings) >= limit:
                break
            if mode == "qwords":
                hits = _search_qwords(pattern, limit)
            elif mode == "dwords":
                hits = _search_dwords(pattern, limit)
            else:
                hits = _search_bytes(pattern, limit)
            for h in hits:
                if in_scope(h):
                    findings.append(f"{h}  const={name}  algo={algo}")
                    algos.add(algo)
                    if len(findings) >= limit:
                        break

    # 3. Encoding function names (base64, encode, decode)
    if len(findings) < limit:
        for func_ea in idautils.Functions():
            if len(findings) >= limit:
                break
            fname = idc.get_func_name(func_ea).lower()
            if any(kw in fname for kw in ("base64", "b64", "base32", "b32", "hex_encode", "hex_decode")):
                findings.append(f"{hex(func_ea)}  {_get_func_name_safe(func_ea)}  type=encoding_function")

    # 2. Checksum patterns (CRC32/Adler32 — also covered by YARA, but
    #    function-name matching catches implementations YARA can't see)
    if len(findings) < limit:
        for func_ea in idautils.Functions():
            if len(findings) >= limit:
                break
            fname = idc.get_func_name(func_ea).lower()
            if any(kw in fname for kw in ("crc32", "crc16", "adler32", "adler16", "checksum")):
                findings.append(f"{hex(func_ea)}  {_get_func_name_safe(func_ea)}  type=checksum_function")
                algos.add("CRC32")

    # 4. High-entropy functions (packed/encrypted code)
    high_ent = []
    for func_ea in idautils.Functions():
        if len(high_ent) >= limit:
            break
        func = ida_funcs.get_func(func_ea)
        if not func or (func.end_ea - func.start_ea) < 64:
            continue
        func_bytes = ida_bytes.get_bytes(func.start_ea, min(func.end_ea - func.start_ea, 4096))
        if not func_bytes:
            continue
        ent = _shannon_entropy(func_bytes)
        if ent >= 6.5:
            high_ent.append({
                "func": idc.get_func_name(func_ea), "addr": hex(func_ea),
                "entropy": ent, "size": len(func_bytes),
            })

    # 5. AES-NI instructions
    aes_ni = []
    aes_ni_mnems = {"aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc", "aeskeygenassist"}
    for func_ea in idautils.Functions():
        if len(aes_ni) >= limit:
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
            aes_ni.append({
                "func": idc.get_func_name(func_ea), "addr": hex(func_ea),
                "aes_ni_insns": found, "count": len(found),
            })

    # Auto-write crypto findings to blackboard
    if algos:
        for algo in sorted(algos):
            _bb_write(f"Crypto: {algo} detected",
                      f"Algorithm identified: {algo}. Matched via constant/signature scanning.",
                      category="crypto", tags=["crypto", algo.lower().replace(" ", "_")],
                      confidence=0.85, source="engine_crypto")

    return {
        "findings": findings[:limit],
        "algorithms": sorted(algos),
        "high_entropy_functions": high_ent,
        "aes_ni": aes_ni,
        "count": len(findings),
    }


# --- detect_obfuscation ---
# ONE function. `what` controls which detector runs. None = run all.

_DEOBF_ANCHORS = {
    "obfuscation_xor": "xor_loop rolling_key encrypted_buffer decode_stub xor_decode cleartext",
    "stack_strings": "mov byte_ptr stack_var push_char build_string char_by_char stack_buffer",
    "api_hashing": "hash_api GetProcAddress LdrGetProcedureAddress ror13 djb2 fnv1a resolve_api",
}


def _detect_encoding_in_func(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings
    xor_count = 0
    b64_refs = 0
    for ea in idautils.FuncItems(func_ea):
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem in _XOR_MNEMONICS:
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op0 != op1:
                xor_count += 1
        if mnem in _MOV_MNEMONICS or mnem in ("lea", "adr", "adrp"):
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
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem not in _MOV_MNEMONICS:
            continue
        op0_type = idc.get_operand_type(ea, 0)
        op1_type = idc.get_operand_type(ea, 1)
        if op0_type not in (idc.o_displ, idc.o_phrase) or op1_type != idc.o_imm:
            continue
        imm_val = idc.get_operand_value(ea, 1)
        if 0x20 <= imm_val <= 0x7E:
            char_stores.append((ea, chr(imm_val)))
    if len(char_stores) < 3:
        return findings
    current = [char_stores[0]]
    for i in range(1, len(char_stores)):
        if 0 < char_stores[i][0] - char_stores[i - 1][0] <= 16:
            current.append(char_stores[i])
        else:
            if len(current) >= 3:
                built = "".join(c for _, c in current)
                findings.append(f"{hex_ea(current[0][0])}  {_get_func_name_safe(func_ea)}  len={len(built)}  {built}")
                if len(findings) >= limit:
                    return findings
            current = [char_stores[i]]
    if len(current) >= 3:
        built = "".join(c for _, c in current)
        findings.append(f"{hex_ea(current[0][0])}  {_get_func_name_safe(func_ea)}  len={len(built)}  {built}")
    return findings[:limit]


def _find_dead_code(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings
    reachable = {func.start_ea}
    for ea in idautils.FuncItems(func_ea):
        matched = False
        for xi, xref in enumerate(idautils.XrefsTo(ea, 0)):
            if xi >= 1000:
                break
            if func.start_ea <= xref.frm < func.end_ea:
                reachable.add(ea)
                matched = True
                break
        if not matched:
            prev = idc.prev_head(ea)
            if prev != idaapi.BADADDR and prev >= func.start_ea:
                prev_mnem = idc.print_insn_mnem(prev)
                if prev_mnem and prev_mnem.lower() not in _TERMINATORS:
                    reachable.add(ea)
    prev_was_term = False
    for ea in idautils.FuncItems(func_ea):
        if ea == func.start_ea:
            prev_was_term = False
            continue
        mnem = idc.print_insn_mnem(ea)
        if prev_was_term and ea not in reachable:
            has_xref = any(xref.iscode for xref in idautils.XrefsTo(ea, 0))
            if not has_xref:
                dead = 0
                cur = ea
                while cur < func.end_ea and dead < 20:
                    dead += 1
                    cur = idc.next_head(cur)
                    if cur == idaapi.BADADDR:
                        break
                    if any(xref.iscode for xref in idautils.XrefsTo(cur, 0)):
                        break
                disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  dead_insns={dead}  {disasm}")
                if len(findings) >= limit:
                    return findings
        prev_was_term = mnem.lower() in _TERMINATORS if mnem else False
    return findings


def _detect_api_hashing(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings
    calls_resolve = False
    resolve_ea = None
    for ea in idautils.FuncItems(func_ea):
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem not in _CALL_MNEMONICS:
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
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem in ("ror", "rol"):
            has_ror = True
            imm = idc.get_operand_value(ea, 1)
            if imm == _KNOWN_HASH_CONSTANTS.get("ror13_additive"):
                hash_insns.append(("ror13", hex_ea(ea)))
        if mnem in ("mov", "add", "xor", "cmp"):
            if idc.get_operand_type(ea, 1) == idc.o_imm:
                val = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                for name, const in _KNOWN_HASH_CONSTANTS.items():
                    if val == const:
                        has_hash_const = True
                        hash_insns.append((name, hex_ea(ea)))
    if has_ror or has_hash_const:
        conf = "high" if has_ror and has_hash_const else "medium"
        info = " ".join(f"{n}@{a}" for n, a in hash_insns) if hash_insns else ""
        findings.append(f"{hex_ea(func_ea)}  {_get_func_name_safe(func_ea)}  resolve={hex_ea(resolve_ea)}  [{conf}]  {info}")
    return findings[:limit]


def _find_dynamic_dispatch(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings
    for ea in idautils.FuncItems(func_ea):
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem not in _CALL_MNEMONICS:
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
            break
    return findings


def _detect_anti_disasm(func_ea, limit):
    findings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return findings
    for ea in idautils.FuncItems(func_ea):
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem in _COND_JUMPS or mnem in ("jmp", "b"):
            target = idc.get_operand_value(ea, 0)
            if target != idaapi.BADADDR:
                prev = idc.prev_head(target)
                if prev != idaapi.BADADDR:
                    nxt = idc.next_head(prev)
                    if nxt != idaapi.BADADDR and nxt > target:
                        findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  jump_into_instruction  target={hex_ea(target)}")
                        if len(findings) >= limit:
                            return findings
        if mnem in _CALL_MNEMONICS:
            target = idc.get_operand_value(ea, 0)
            insn_size = idc.next_head(ea) - ea
            if target == ea + insn_size:
                findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  call_next_insn")
                if len(findings) >= limit:
                    return findings
        if mnem in ("int3", "hlt", "ud2", "int"):
            nxt = idc.next_head(ea)
            if nxt != idaapi.BADADDR and nxt < func.end_ea:
                findings.append(f"{hex_ea(ea)}  {_get_func_name_safe(func_ea)}  trap_instruction  {mnem}")
                if len(findings) >= limit:
                    return findings
    return findings


# Obfuscation sub-detector dispatch
_OBF_DETECTORS = {
    "stack_strings": _find_stack_strings,
    "dead_code": _find_dead_code,
    "api_hashing": _detect_api_hashing,
    "dynamic_dispatch": _find_dynamic_dispatch,
    "anti_disasm": _detect_anti_disasm,
    "encoding": _detect_encoding_in_func,
}


def _detect_obfuscation(addr=None, what=None, limit=50) -> dict:
    """Unified obfuscation detection.

    `what` controls which detector: stack_strings, dead_code, api_hashing,
    dynamic_dispatch, anti_disasm, encoding, or None for full semantic scan.
    """
    # Specific sub-detector
    if what and what in _OBF_DETECTORS:
        detector = _OBF_DETECTORS[what]
        all_findings = []
        for func_ea in _iter_target_functions(addr):
            if len(all_findings) >= limit:
                break
            all_findings.extend(detector(func_ea, limit - len(all_findings)))
        return {
            "ok": True, "what": what,
            "findings": "\n".join(all_findings[:limit]),
            "count": len(all_findings[:limit]),
            "truncated": len(all_findings) >= limit,
        }

    # Full semantic detection (BehaviorClassifier + all signal detectors)
    clf = None
    if BehaviorClassifier is not None and BgeCodeEmbedder is not None:
        try:
            embedder = BgeCodeEmbedder()
            clf = BehaviorClassifier.instance(embedder)
            for k, v in _DEOBF_ANCHORS.items():
                if k not in clf.ANCHORS:
                    clf.ANCHORS[k] = v
        except Exception:
            clf = None

    if clf is not None:
        findings = []
        behavior_tags = []
        for func_ea in _iter_target_functions(addr):
            if len(findings) >= limit:
                break
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    continue
                pseudo = str(cfunc)
                if not pseudo.strip():
                    continue
                tags = clf.classify(pseudo, threshold=0.0, top_k=8, block=False)
                if not tags:
                    continue
                vals = sorted(float(h.get("confidence", h.get("score", 0.0)) or 0.0) for h in tags)
                q50 = vals[len(vals) // 2]
                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                gate = q50 + max(0.0, q75 - q50)
                relevant = [h for h in tags if float(h.get("confidence", h.get("score", 0.0)) or 0.0) >= gate
                            and h["behavior"] in ("obfuscation_xor", "stack_strings", "api_hashing",
                                                   "anti_debug", "anti_vm", "evasion", "string_decrypt")]
                if not relevant:
                    continue
                func_name = _get_func_name_safe(func_ea)
                tag_strs = [f"{t['behavior']}({t['confidence']:.2f})" for t in relevant]
                findings.append(f"{hex_ea(func_ea)}  {func_name}  {' '.join(tag_strs)}")
                behavior_tags.extend([{"addr": hex_ea(func_ea), "func": func_name, **t} for t in relevant])
                # Auto-write high-confidence to blackboard
                high_scores = [t for t in relevant if float(t.get("confidence", 0) or 0) >= gate]
                if high_scores:
                    _bb_write(f"Obfuscation at {hex_ea(func_ea)}",
                              f"{func_name}: {' '.join(tag_strs)}",
                              category="obfuscation", addr=hex_ea(func_ea),
                              tags=[t["behavior"] for t in high_scores])
            except Exception:
                continue
        return {
            "ok": True, "what": "semantic", "classifier": "BehaviorClassifier",
            "findings": "\n".join(findings[:limit]),
            "behavior_tags": behavior_tags,
            "count": len(findings[:limit]),
        }

    # Fallback: deterministic signal detectors
    all_findings = []
    for func_ea in _iter_target_functions(addr):
        if len(all_findings) >= limit:
            break
        remaining = limit - len(all_findings)
        all_findings.extend(_detect_encoding_in_func(func_ea, remaining))
        all_findings.extend(_find_stack_strings(func_ea, remaining - len(all_findings)))
        all_findings.extend(_detect_api_hashing(func_ea, remaining - len(all_findings)))
        all_findings.extend(_detect_anti_disasm(func_ea, remaining - len(all_findings)))
    return {
        "ok": True, "what": "all", "classifier": "deterministic_signal_fallback",
        "findings": "\n".join(all_findings[:limit]),
        "count": len(all_findings[:limit]),
        "truncated": len(all_findings) >= limit,
    }


# --- detect_packer ---
# Merges: packer.detect + packer.profile
# Uses compute_entropy + scan_crypto_constants + detect_obfuscation directly.

def _evaluate_packer_signatures(section_names, strings):
    indicators = []
    s_names_lc = [s.lower() for s in section_names]
    s_blob = "\n".join(strings).lower()
    for sig in _PACKER_SIGNATURES:
        matched = False
        evidence = []
        if sig["check"] == "section_names":
            for pat in sig["patterns"]:
                for n in s_names_lc:
                    if pat.lower() in n:
                        matched = True
                        evidence.append(n)
        elif sig["check"] == "strings":
            for pat in sig["patterns"]:
                if pat.lower() in s_blob:
                    matched = True
                    evidence.append(pat)
            if not matched:
                for pat in sig["patterns"]:
                    pat_bytes = pat.encode("utf-8", errors="ignore")
                    if len(pat_bytes) < 4:
                        continue
                    for sec_name in s_names_lc:
                        blob = _read_section_bytes(sec_name, max_bytes=0x20000)
                        if blob and pat_bytes in blob:
                            matched = True
                            evidence.append(f"section:{sec_name}")
                            break
                    if matched:
                        break
        indicators.append({"name": sig.get("name", sig["label"]), "label": sig["label"],
                           "weight": sig["weight"], "matched": matched, "evidence": evidence[:5]})
    return indicators


def _evaluate_entropy_indicators(section_entropy):
    out = []
    text_segments = [(n, e) for n, e in section_entropy.items() if n.lower() in (".text", "text", "code", ".code")]
    text_ent = max((e for _, e in text_segments), default=None)
    if text_ent is not None:
        out.append({"name": "text_segment_entropy", "weight": 0.6,
                    "matched": text_ent >= 7.2,
                    "evidence": [f"{text_ent:.3f} (threshold 7.2)"] if text_ent >= 7.2 else [f"{text_ent:.3f}"]})
    high_count = sum(1 for e in section_entropy.values() if e >= 7.2)
    if high_count:
        out.append({"name": "high_entropy_segments", "weight": 0.3,
                    "matched": high_count >= 2, "evidence": [f"{high_count} segment(s) >= 7.2"]})
    return out


def _evaluate_anti_analysis(imports, strings):
    out = []
    imports_lc = [i.lower() for i in imports]
    s_blob = "\n".join(strings)
    anti_debug_hits = [a for a in _ANTI_DEBUG_APIS if a.lower() in imports_lc]
    if anti_debug_hits:
        out.append({"name": "anti_debug_imports", "weight": 0.4, "matched": True, "evidence": anti_debug_hits[:8]})
    elif any(a.lower() in s_blob for a in _ANTI_DEBUG_APIS):
        hits = [a for a in _ANTI_DEBUG_APIS if a.lower() in s_blob]
        out.append({"name": "anti_debug_strings", "weight": 0.25, "matched": True, "evidence": hits[:8]})
    anti_vm = [a for a in _ANTI_VM_STRINGS if a.lower() in s_blob]
    if anti_vm:
        out.append({"name": "anti_vm_strings", "weight": 0.25, "matched": True, "evidence": anti_vm[:8]})
    return out


def _evaluate_drm(strings, imports):
    s_blob = "\n".join(strings).lower()
    i_blob = "\n".join(imports).lower()
    ac_mods, ac_strs = [], []
    for ac_name, patterns in _GAME_ANTI_CHEAT.items():
        for pat in patterns:
            pl = pat.lower()
            if pl in i_blob:
                ac_mods.append(f"{ac_name}:{pat}")
            elif pl in s_blob:
                ac_strs.append(f"{ac_name}:{pat}")
    ac_mods = sorted(set(ac_mods))
    ac_strs = sorted(set(ac_strs))
    indicators = []
    if ac_mods:
        indicators.append("anti_cheat_imports")
    if ac_strs:
        indicators.append("anti_cheat_string_ref")
    note = None
    if ac_mods or ac_strs:
        note = ("Binary references game anti-cheat. Treat as adversarial: do not "
                "execute in a non-isolated environment.")
    return {"anti_cheat_modules": ac_mods, "anti_cheat_strings": ac_strs, "indicators": indicators, "note": note}


def _classify_packer(indicators, drm):
    label_votes = {}
    for ind in indicators:
        if ind["matched"] and ind.get("label"):
            label_votes[ind["label"]] = label_votes.get(ind["label"], 0.0) + float(ind["weight"])
    if not label_votes:
        for ind in indicators:
            if ind["matched"] and ind["name"] in ("text_segment_entropy", "high_entropy_segments"):
                return {"packer": "custom_or_unknown", "confidence": 0.4, "fallback": "high_entropy_no_signature"}
        return {"packer": "none", "confidence": 0.0, "fallback": None}
    best = max(label_votes, key=label_votes.get)
    conf = min(0.98, max(0.2, label_votes[best]))
    return {"packer": best.lower(), "confidence": round(conf, 2),
            "fallback": "custom_or_unknown" if conf < 0.6 else None}


def _recommend_packer(classification, matched_count, drm):
    packer = classification.get("packer") or "none"
    conf = float(classification.get("confidence") or 0.0)
    if drm.get("anti_cheat_modules") or drm.get("anti_cheat_strings"):
        return "do_not_unpack", "Anti-cheat references detected."
    if packer == "none" and matched_count == 0:
        return "none", None
    if packer in ("upx", "mpress", "aspack", "petite", "kkrunchy") and conf >= 0.7:
        return "auto_unpack", None
    if packer in ("vmprotect", "themida"):
        return "guided_unpack", f"{_PACKER_DISPLAY.get(packer, packer)} requires debug-based OEP finding."
    return "manual_only", "Low confidence or unknown packer."


def _detect_packer(addr=None, deep=False, include_anti_debug=True, include_drm=True, max_strings=5000) -> dict:
    """Unified packer detection. Uses shared entropy + crypto + obfuscation functions."""
    section_names = _scan_section_names()
    strings = _scan_string_references(max_strings)
    imports = _scan_import_names()

    # Section entropy (uses shared _compute_entropy)
    section_entropy = {}
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            scan_size = min(seg.size(), 0x100000)
            ent = _compute_entropy(seg.start_ea, scan_size)
            section_entropy[ida_segment.get_segm_name(seg)] = ent

    indicators = _evaluate_packer_signatures(section_names, strings)
    indicators.extend(_evaluate_entropy_indicators(section_entropy))
    if include_anti_debug:
        indicators.extend(_evaluate_anti_analysis(imports, strings))
    drm = _evaluate_drm(strings, imports) if include_drm else {"anti_cheat_modules": [], "anti_cheat_strings": [], "indicators": [], "note": None}

    # Deep mode: also run sliding-window entropy scan
    if deep:
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            scan_size = min(seg.size(), 0x200000)
            end_ea = seg.start_ea + scan_size
            cur = seg.start_ea
            while cur + 4096 <= end_ea:
                ent = _compute_entropy(cur, 4096)
                if ent >= 7.0:
                    indicators.append({"name": "sliding_window_high_entropy", "weight": 0.3,
                                       "matched": True, "evidence": [f"{hex(cur)}  ent={ent}"]})
                    break
                cur += 2048

    classification = _classify_packer(indicators, drm)
    matched_count = sum(1 for i in indicators if i["matched"])
    recommendation, warning = _recommend_packer(classification, matched_count, drm)

    binary_path = ""
    try:
        binary_path = idaapi.get_input_file_path() or ""
    except Exception:
        pass

    return {
        "ok": True, "ts": round(time.time(), 3),
        "binary": os.path.basename(binary_path),
        "indicators": indicators, "drm": drm,
        "entropy": section_entropy,
        "classification": classification,
        "recommendation": recommendation, "warning": warning,
    }


# --- detect (orchestrator) ---
# Combines packer + entropy + crypto + obfuscation in one pass.

def _run_detect(addr, limit, include_anti_debug, include_drm, max_strings):
    ts = time.time()
    results = {}

    results["packer"] = _detect_packer(addr, deep=False, include_anti_debug=include_anti_debug,
                                        include_drm=include_drm, max_strings=max_strings)

    # Per-section entropy summary (already computed in packer, just reuse)
    results["entropy"] = {"sections": results["packer"].get("entropy", {})}

    results["crypto"] = _scan_crypto_constants(limit=limit)
    results["obfuscation"] = _detect_obfuscation(addr=addr, limit=limit)

    packer_data = results["packer"]
    classification = packer_data.get("classification", {})
    summary_parts = []
    p = classification.get("packer", "none")
    if p != "none":
        summary_parts.append(f"packer={p}({classification.get('confidence', 0)})")
    algos = results["crypto"].get("algorithms", [])
    if algos:
        summary_parts.append(f"crypto={','.join(algos)}")
    obf = results["obfuscation"].get("count", 0)
    if obf:
        summary_parts.append(f"obfuscation_signals={obf}")

    return {
        "ok": True, "action": "detect", "ts": round(ts, 3),
        "summary": "  ".join(summary_parts) if summary_parts else "clean",
        "recommendation": packer_data.get("recommendation"),
        "warning": packer_data.get("warning"),
        **results,
    }


# --- hook generation ---
# Merges: hooks.generate_frida + hooks.generate_detours + hooks.inline_hooks

def _generate_frida(addr, func_name):
    if not addr and not func_name:
        return make_error(MCPError.INVALID_ARGS, "addr or func_name required")
    ea, err = validate_addr(addr or func_name)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
    name = idc.get_func_name(ea)
    tif = ida_typeinf.tinfo_t()
    arg_count = 0
    if ida_nalt.get_tinfo(tif, ea) and tif.is_func():
        arg_count = tif.get_nargs()
    if arg_count == 0:
        frame = ida_frame.get_frame(func)
        if frame:
            arg_count = min(8, ida_frame.get_frame_size(func) // 8)
    arg_logs = "\n".join([f'        console.log("    arg{i}:", args[{i}]);' for i in range(min(8, arg_count))])
    module_hint = os.path.basename(idaapi.get_input_file_path() or "").lower()
    offset = hex(ea - idaapi.get_imagebase())
    script = f'''// Frida hook for {name} at {hex(ea)}
const moduleHint = "{module_hint}";
const targetModule = Process.enumerateModules().find(m => m.name.toLowerCase() === moduleHint) || Process.mainModule;
if (!targetModule) {{ throw new Error("Unable to resolve target module"); }}
const funcAddr = targetModule.base.add({offset});
Interceptor.attach(funcAddr, {{
    onEnter: function(args) {{
        console.log("[+] {name} called @ " + funcAddr + " (module=" + targetModule.name + ")");
{arg_logs}
    }},
    onLeave: function(retval) {{
        console.log("[+] {name} returned:", retval);
    }}
}});
'''
    return {"ok": True, "function": name, "addr": hex(ea), "script": script}


def _generate_detours(addr, func_name):
    if not addr and not func_name:
        return make_error(MCPError.INVALID_ARGS, "addr or func_name required")
    ea, err = validate_addr(addr or func_name)
    if err:
        return err
    name = idc.get_func_name(ea) or f"sub_{ea:x}"
    proto = get_prototype(ida_funcs.get_func(ea)) or f"void* __stdcall {name}(...)"
    code = f'''// Microsoft Detours hook for {name}
#include <windows.h>
#include <detours.h>
typedef {proto.replace(name, f"(*Orig_{name}_t)")};
Orig_{name}_t pOrig_{name} = (Orig_{name}_t){hex(ea)};
// Hook function (adjust signature to match prototype)
void Install{name}Hook() {{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOrig_{name}, Hook_{name});
    DetourTransactionCommit();
}}
'''
    return {"ok": True, "function": name, "addr": hex(ea), "code": code}


def _find_inline_hook_points(addr):
    if not addr:
        return make_error(MCPError.INVALID_ARGS, "addr required")
    ea, err = validate_addr(addr)
    if err:
        return err
    func = ida_funcs.get_func(ea)
    if not func:
        return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {addr}")
    hook_points = []
    current = func.start_ea
    while current < func.end_ea and len(hook_points) < 20:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, current)
        if length >= 5:
            hook_points.append({
                "addr": hex(current), "bytes_available": length, "safe": length >= 5,
                "disasm": ida_lines.tag_remove(idc.generate_disasm_line(current, 0) or ""),
            })
        current += length if length > 0 else 1
    return {"ok": True, "function": idc.get_func_name(ea) or hex(ea), "hook_points": hook_points}


# --- decode ---
# Merges: deobfuscate.decode_attempt

def _decode_at(addr, key_hex, limit):
    ea, err = validate_addr(addr)
    if err:
        return err
    raw = ida_bytes.get_bytes(ea, 256)
    if not raw:
        return make_error(MCPError.IDA_ERROR, f"Cannot read bytes at {hex_ea(ea)}")
    results = []
    if key_hex:
        try:
            key_bytes = bytes.fromhex(key_hex.replace("0x", "").replace(" ", ""))
        except ValueError:
            return make_error(MCPError.INVALID_ARGS, "Invalid hex key format")
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
        try:
            b64_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            end = 0
            for i, b in enumerate(raw):
                if b in b64_chars:
                    end = i + 1
                else:
                    break
            if end >= 4:
                decoded_b64 = base64.b64decode(raw[:end], validate=True)
                results.append(f"base64  len={len(decoded_b64)}  \"{decoded_b64[:64].decode('ascii', errors='replace')}\"")
        except Exception:
            pass
    return {"ok": True, "addr": hex_ea(ea), "raw_hex": raw[:32].hex(), "results": "\n".join(results), "count": len(results)}


# --- hook_targets ---
# Merges: hooks.suggest + hooks.find_targets

def _find_hook_targets(category=None, limit=50):
    if category:
        cat = category.lower()
        if cat not in _HOOK_PATTERNS:
            return make_error(MCPError.INVALID_ARGS, f"Unknown category. Use: {', '.join(_HOOK_PATTERNS.keys())}")
        patterns = _HOOK_PATTERNS[cat]
        suggestions = []
        # Search imports
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg and seg.type == ida_segment.SEG_XTRN:
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_name(head)
                    if name:
                        for p in patterns:
                            if p.lower() in name.lower():
                                suggestions.append({"name": name, "addr": hex(head), "pattern_match": p, "type": "import"})
                                break
        # Search named functions
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                name = idc.get_func_name(func_ea)
                if name:
                    for p in patterns:
                        if p.lower() in name.lower():
                            suggestions.append({"name": name, "addr": hex(func_ea), "pattern_match": p, "type": "function"})
                            break
        return {"ok": True, "category": cat, "suggestions": suggestions[:50]}

    # No category: find all interesting targets by importance
    targets = []
    importance_kw = {
        "high": ["password", "key", "crypt", "auth", "token", "secret", "license"],
        "medium": ["send", "recv", "file", "read", "write", "execute", "load"],
    }
    for seg_ea in idautils.Segments():
        for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
            name = idc.get_func_name(func_ea)
            if not name or name.startswith("sub_"):
                continue
            nl = name.lower()
            cat_found = "other"
            for c, pats in _HOOK_PATTERNS.items():
                if any(p.lower() in nl for p in pats):
                    cat_found = c
                    break
            importance = "normal"
            for level, keywords in importance_kw.items():
                if any(kw in nl for kw in keywords):
                    importance = level
                    break
            if cat_found != "other" or importance != "normal":
                targets.append({"addr": hex(func_ea), "name": name, "category": cat_found, "importance": importance})
    targets.sort(key=lambda x: {"high": 0, "medium": 1, "normal": 2}.get(x["importance"], 2))
    return {"ok": True, "targets": targets[:100]}


# --- Protocol functions ---
# From protocol.py (mostly unchanged, uses shared helpers)

def _detect_protocol_impl(addr, limit):
    """Detect protocol usage in the binary."""
    if BehaviorClassifier is None or BgeCodeEmbedder is None:
        return {"ok": True, "note": "BehaviorClassifier not available", "network_apis": {}}

    def _get_protocol_classifier_fn():
        if BehaviorClassifier is None or BgeCodeEmbedder is None:
            return None
        try:
            embedder = BgeCodeEmbedder()
            return BehaviorClassifier.instance(embedder)
        except Exception:
            return None

    clf = _get_protocol_classifier_fn()
    network_hits = {}
    for api_names in _NETWORK_APIS.values():
        for name in api_names:
            ea = ida_name.get_name_ea(idaapi.BADADDR, name)
            if ea == idaapi.BADADDR:
                for suffix in ("A", "W", "@plt", "@PLT"):
                    ea = ida_name.get_name_ea(idaapi.BADADDR, name + suffix)
                    if ea != idaapi.BADADDR:
                        break
            if ea != idaapi.BADADDR:
                callers = []
                for xref in idautils.XrefsTo(ea, 0):
                    fn = ida_funcs.get_func(xref.frm)
                    if fn:
                        callers.append(idc.get_func_name(fn.start_ea))
                if callers:
                    network_hits[name] = {"addr": hex(ea), "callers": list(set(callers))[:10]}

    # Classify protocol behavior if we have a classifier
    behavior_tags = []
    if clf:
        for func_ea in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    continue
                pseudo = str(cfunc)
                if not pseudo.strip():
                    continue
                tags = clf.classify(pseudo, threshold=0.0, top_k=5, block=False)
                if tags:
                    proto_tags = [t for t in tags if t.get("behavior", "").endswith("_protocol") or
                                  t.get("behavior", "") in ("tls_ssl", "custom_binary", "dns_protocol", "smtp_ftp")]
                    if proto_tags:
                        behavior_tags.extend(proto_tags[:3])
            except Exception:
                continue

    # Auto-write to blackboard
    if network_hits:
        apis = ", ".join(sorted(network_hits.keys())[:10])
        _bb_write("Protocol APIs detected", apis, category="protocol", tags=["protocol"])

    return {
        "ok": True, "network_apis": network_hits,
        "behavior_tags": behavior_tags[:20],
        "api_count": len(network_hits),
    }


def _protocol_spec_impl(what, addr, limit):
    """Recover protocol structure (parsers, handlers, packet layout, etc.)."""
    result = {"ok": True, "action": what}

    if what == "parsers":
        parsers = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if not name:
                continue
            nl = name.lower()
            if any(kw in nl for kw in ("parse", "decode", "deserialize", "unpack", "unmarshal")):
                parsers.append({"addr": hex(func_ea), "name": name})
        result["parsers"] = parsers[:limit]

    elif what == "serializers":
        serializers = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if not name:
                continue
            nl = name.lower()
            if any(kw in nl for kw in ("serialize", "encode", "pack", "marshal", "format")):
                serializers.append({"addr": hex(func_ea), "name": name})
        result["serializers"] = serializers[:limit]

    elif what == "handlers":
        handlers = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if not name:
                continue
            nl = name.lower()
            if any(kw in nl for kw in ("handler", "dispatch", "process_msg", "handle_", "on_message")):
                handlers.append({"addr": hex(func_ea), "name": name})
        result["handlers"] = handlers[:limit]

    elif what == "endpoints":
        endpoints = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if not name:
                continue
            nl = name.lower()
            if any(kw in nl for kw in ("connect", "bind", "listen", "accept", "socket")):
                endpoints.append({"addr": hex(func_ea), "name": name})
        result["endpoints"] = endpoints[:limit]

    elif what == "tls_config":
        tls_findings = []
        for api_name in _TLS_CONFIG_APIS:
            ea = ida_name.get_name_ea(idaapi.BADADDR, api_name)
            if ea != idaapi.BADADDR:
                tls_findings.append({"api": api_name, "addr": hex(ea)})
        result["tls_config"] = tls_findings

    elif what == "packet_struct":
        # Find functions that do sequential buffer reads (field extraction)
        packet_fields = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if not name:
                continue
            nl = name.lower()
            if any(kw in nl for kw in ("parse", "decode", "unpack", "read_header", "packet")):
                # Decompile and look for offset patterns
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        pseudo = str(cfunc)
                        # Look for buffer+offset patterns
                        offsets = re.findall(r'\b(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\b', pseudo)
                        if offsets:
                            packet_fields.append({"func": name, "addr": hex(func_ea), "field_offsets": offsets[:10]})
                except Exception:
                    pass
        result["packet_struct"] = packet_fields[:limit]

    elif what == "magic_numbers":
        magic_hits = []
        for value, (label, desc) in _KNOWN_MAGIC.items():
            pattern = struct.pack(">I", value)
            hits = _search_bytes(pattern, 5)
            for h in hits:
                magic_hits.append({"magic": hex(value), "label": label, "desc": desc, "addr": h})
        result["magic_numbers"] = magic_hits

    elif what == "state_machine":
        # Find switch/dispatch patterns (state machines)
        state_machines = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            switch_count = 0
            for head in idautils.Heads(func.start_ea, func.end_ea):
                si = idaapi.get_switch_info(head)
                if si:
                    switch_count += si.get_jtable_size()
            if switch_count >= 3:
                state_machines.append({
                    "func": idc.get_func_name(func_ea), "addr": hex(func_ea),
                    "switch_cases": switch_count,
                })
        result["state_machine"] = state_machines[:limit]

    elif what == "reconstruct":
        # Combine: detect + parsers + handlers + packet_struct + magic_numbers
        result = _detect_protocol_impl(addr, limit)
        result["action"] = "reconstruct"
        result["parsers"] = _protocol_spec_impl("parsers", addr, limit).get("parsers", [])
        result["handlers"] = _protocol_spec_impl("handlers", addr, limit).get("handlers", [])

    elif what in ("trace_handler", "export_spec"):
        result["note"] = f"{what} requires a live trace or IDB export — not available in static analysis"

    return result


# --- Taint functions ---
# From taint.py (uses shared _get_import_addrs helper)

def _is_sanitizer_name(name: str) -> bool:
    n = str(name or "").lower()
    return n.startswith(("validate_", "check_", "sanitize_")) or n in ("strlen", "strnlen")


def _callers_of(ea, max_depth, visited):
    results = []
    queue = [(ea, 0, [ea])]
    while queue:
        curr, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        for xref in idautils.CodeRefsTo(curr, 0):
            fn = idaapi.get_func(xref)
            if not fn:
                continue
            fea = fn.start_ea
            if fea in visited:
                continue
            visited.add(fea)
            results.append((fea, depth + 1, path + [fea]))
            queue.append((fea, depth + 1, path + [fea]))
    return results


def _callees_of(ea, max_depth, visited):
    results = []
    queue = [(ea, 0, [ea])]
    while queue:
        curr, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        fn = idaapi.get_func(curr)
        if not fn:
            continue
        for item in idautils.FuncItems(fn.start_ea):
            for xref in idautils.XrefsFrom(item, 0):
                if not xref.iscode:
                    continue
                target_fn = idaapi.get_func(xref.to)
                target_ea = target_fn.start_ea if target_fn else xref.to
                if target_ea in visited:
                    continue
                visited.add(target_ea)
                results.append((target_ea, depth + 1, path + [target_ea]))
                queue.append((target_ea, depth + 1, path + [target_ea]))
    return results


def _dataflow_signal(source_ea, sink_ea):
    """Check dataflow from source to sink using microcode SSA, ctree, then regex."""
    # Microcode SSA check
    try:
        if hasattr(ida_hexrays, "init_hexrays_plugin") and ida_hexrays.init_hexrays_plugin():
            fn = idaapi.get_func(source_ea)
            if fn:
                cfunc = ida_hexrays.decompile(fn.start_ea)
                if cfunc:
                    mba = getattr(cfunc, "mba", None)
                    if mba:
                        source_name = (idc.get_name(source_ea) or hex_ea(source_ea)).lower()
                        sink_name = (idc.get_name(sink_ea) or hex_ea(sink_ea)).lower()
                        tainted_mregs = set()
                        seen_source = seen_sink = False
                        for bi in range(int(getattr(mba, "qty", 0) or 0)):
                            blk = mba.get_mblock(bi)
                            insn = getattr(blk, "head", None)
                            while insn:
                                txt = str(insn).lower()
                                if source_name and source_name in txt and "call" in txt:
                                    seen_source = True
                                    for attr in ("d",):
                                        mop = getattr(insn, attr, None)
                                        if mop and hasattr(mop, "r") and int(mop.r) >= 0:
                                            tainted_mregs.add(int(mop.r))
                                if sink_name and sink_name in txt:
                                    # Check if any tainted reg is used
                                    for attr in ("l", "r"):
                                        mop = getattr(insn, attr, None)
                                        if mop and hasattr(mop, "r") and int(mop.r) in tainted_mregs:
                                            seen_sink = True
                                insn = getattr(insn, "next", None)
                        if seen_source and seen_sink:
                            return {"desc": f"microcode_ssa: {source_name} -> {sink_name}",
                                    "confidence": "high", "method": "microcode_ssa", "reachability_only": False}
    except Exception:
        pass

    # Regex fallback
    try:
        fn = idaapi.get_func(source_ea)
        if fn:
            cfunc = ida_hexrays.decompile(fn.start_ea)
            if cfunc:
                pseudo = str(cfunc)
                source_name = idc.get_name(source_ea) or ""
                sink_name = idc.get_name(sink_ea) or ""
                if source_name and sink_name and source_name in pseudo and sink_name in pseudo:
                    assign = re.search(rf'(\w+)\s*=\s*{re.escape(source_name)}\s*\(', pseudo)
                    if assign:
                        tainted_var = assign.group(1)
                        if re.search(rf'{re.escape(sink_name)}\s*\([^)]*\b{re.escape(tainted_var)}\b', pseudo):
                            return {"desc": f"regex: {tainted_var} = {source_name}(...) -> {sink_name}(..., {tainted_var}, ...)",
                                    "confidence": "low", "method": "regex", "reachability_only": False}
    except Exception:
        pass

    return {"desc": None, "confidence": "low", "method": "callgraph", "reachability_only": True}


def _taint_trace(source, addr, max_depth=5, max_paths=20):
    """Trace taint from source to sinks."""
    source_ea = None
    source_name = source or ""

    if addr:
        ea, err = validate_addr(addr)
        if err:
            return err
        source_ea = ea
        if not source_name:
            source_name = idc.get_name(ea) or hex_ea(ea)
    elif source:
        imports = _get_import_addrs({source})
        if imports:
            source_ea = list(imports.values())[0]
            source_name = source
        else:
            try:
                source_ea = int(source, 16)
                source_name = idc.get_name(source_ea) or source
            except Exception:
                return make_error(MCPError.INVALID_ARGS, f"Source '{source}' not found")
    else:
        return make_error(MCPError.INVALID_ARGS, "addr or source required")

    sink_addrs = _get_import_addrs(set(DANGEROUS_SINKS.keys()))
    visited = {source_ea}
    reachable = _callees_of(source_ea, max_depth=max_depth, visited=visited)
    reachable_eas = {ea for ea, _, _ in reachable}

    found_sinks = []
    for sink_name, sink_ea in sink_addrs.items():
        if sink_ea not in reachable_eas and sink_ea != source_ea:
            continue
        path_to_sink = None
        for ea, _, path in reachable:
            if ea == sink_ea:
                path_to_sink = [hex_ea(p) for p in path]
                break
        flow = _dataflow_signal(source_ea, sink_ea)
        conf_label = flow.get("confidence", "medium")
        conf_num = {"high": 0.9, "medium": 0.6, "low": 0.45}.get(conf_label, 0.6)
        sanitized = []
        if path_to_sink:
            sanitized = [idc.get_name(int(p, 16)).lower() for p in path_to_sink
                         if _is_sanitizer_name(idc.get_name(int(p, 16)) or "")]
        found_sinks.append({
            "sink": sink_name, "sink_addr": hex_ea(sink_ea),
            "vuln_type": DANGEROUS_SINKS.get(sink_name, "unknown"),
            "depth": len(path_to_sink) - 1 if path_to_sink else -1,
            "path": path_to_sink,
            "dataflow": flow.get("desc"),
            "confidence": conf_num, "confidence_level": conf_label,
            "analysis_method": flow.get("method"),
            "reachability_only": flow.get("reachability_only", False),
            "sanitized_by": sorted(set(sanitized)),
            "cwe_ids": VULN_TYPE_TO_CWE.get(DANGEROUS_SINKS.get(sink_name, ""), []),
        })
    found_sinks.sort(key=lambda x: x["depth"] if x["depth"] >= 0 else 999)

    # Write high-confidence to blackboard
    for s in found_sinks:
        if not s.get("reachability_only") and s.get("confidence", 0) >= 0.8:
            _bb_write(f"Taint: {source_name} -> {s['sink']}",
                      s.get("dataflow") or f"Path depth: {s['depth']}",
                      category="vuln", addr=hex_ea(source_ea),
                      tags=["taint", s["vuln_type"], source_name],
                      confidence=s["confidence"], source="taint")

    return {
        "ok": True, "source": source_name, "source_addr": hex_ea(source_ea),
        "sinks_found": len(found_sinks), "sinks": found_sinks[:max_paths],
        "reachable_functions": len(reachable),
    }


def _taint_sources_list():
    import_sources = _get_import_addrs(TAINT_SOURCES)
    result = []
    for name, ea in sorted(import_sources.items()):
        callers = list(idautils.CodeRefsTo(ea, 0))
        result.append({"name": name, "addr": hex_ea(ea), "caller_count": len(callers), "type": "import"})
    # Blackboard IOCs
    try:
        if BlackboardStore:
            store = BlackboardStore()
            for ioc in store.list(category="ioc", include_resolved=False, limit=50):
                ioc_type = ioc.get("ioc_type", "")
                if ioc_type in ("ip_port", "url", "domain", "dma_buffer", "uart_rx"):
                    result.append({"name": ioc.get("title", ""), "addr": ioc.get("addr", ""),
                                   "type": "ioc", "category": ioc_type})
    except Exception:
        pass
    return {"ok": True, "sources": result, "count": len(result)}


def _taint_report_full(max_depth=5, max_paths=20):
    import_sources = _get_import_addrs(TAINT_SOURCES)
    all_findings = []
    for src_name, src_ea in import_sources.items():
        callers = list(idautils.CodeRefsTo(src_ea, 0))
        if not callers:
            continue
        sink_addrs = _get_import_addrs(set(DANGEROUS_SINKS.keys()))
        visited = {src_ea}
        reachable = _callees_of(src_ea, max_depth=max_depth, visited=visited)
        reachable_eas = {ea for ea, _, _ in reachable}
        for sink_name, sink_ea in sink_addrs.items():
            if sink_ea not in reachable_eas:
                continue
            path = None
            for ea, _, p in reachable:
                if ea == sink_ea:
                    path = [hex_ea(x) for x in p[:6]]
                    break
            all_findings.append({
                "source": src_name, "sink": sink_name,
                "vuln_type": DANGEROUS_SINKS.get(sink_name, "unknown"),
                "depth": len(path) - 1 if path else -1,
                "path_summary": " -> ".join(idc.get_name(int(p, 16)) or p for p in (path or [])[:4]),
            })
    all_findings.sort(key=lambda x: x["depth"] if x["depth"] >= 0 else 999)
    return {"ok": True, "findings": all_findings[:max_paths], "total": len(all_findings)}


# --- eval ---
# Merges: packer.script

_SCRIPT_SAFE_BUILTINS = {
    "abs", "all", "any", "bin", "bool", "bytes", "callable", "chr",
    "dict", "divmod", "enumerate", "filter", "float", "format", "frozenset",
    "hash", "hex", "id", "int", "isinstance", "issubclass", "iter", "len",
    "list", "map", "max", "min", "next", "object", "oct", "ord", "pow",
    "print", "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "str", "sum", "tuple", "type", "vars", "zip",
}

_MAX_SCRIPT_CHARS = 16384
_MAX_SCRIPT_OUTPUT = 200000


def _run_eval(code, extra_globals):
    import builtins as _b
    import json as _json

    if not code or not isinstance(code, str):
        return make_error(MCPError.INVALID_ARGS, "eval requires non-empty 'code'")
    if len(code) > _MAX_SCRIPT_CHARS:
        return make_error(MCPError.INVALID_ARGS, f"code exceeds {_MAX_SCRIPT_CHARS} chars")
    for tok in ("open", "exec", "eval", "__import__", "compile", "input"):
        if tok + "(" in code or tok + " " in code or code.startswith(tok):
            return make_error(MCPError.INVALID_ARGS, f"script may not use '{tok}'")

    safe_b = {k: getattr(_b, k) for k in _SCRIPT_SAFE_BUILTINS if hasattr(_b, k)}
    ns = {
        "security": security,  # self-reference for nested calls
        "idaapi": sys.modules.get("idaapi"), "idautils": sys.modules.get("idautils"),
        "idc": sys.modules.get("idc"), "ida_bytes": sys.modules.get("ida_bytes"),
        "ida_nalt": sys.modules.get("ida_nalt"), "ida_segment": sys.modules.get("ida_segment"),
        "ida_funcs": sys.modules.get("ida_funcs"), "ida_ida": sys.modules.get("ida_ida"),
        "json": __import__("json"), "os": __import__("os"), "re": __import__("re"),
        "time": __import__("time"), "math": __import__("math"), "struct": __import__("struct"),
        "collections": __import__("collections"), "hashlib": __import__("hashlib"),
        # Expose analysis functions directly
        "compute_entropy": _compute_entropy,
        "scan_crypto_constants": _scan_crypto_constants,
        "detect_obfuscation": _detect_obfuscation,
        "detect_packer": _detect_packer,
        "__builtins__": safe_b,
    }
    if extra_globals:
        for k, v in extra_globals.items():
            if isinstance(k, str) and k.isidentifier():
                ns[k] = v
    try:
        try:
            value = eval(compile(code, "<security-eval>", "eval"), ns)
        except SyntaxError:
            exec(compile(code, "<security-eval>", "exec"), ns)
            value = ns.get("result")
    except Exception as e:
        return make_error(MCPError.IDA_ERROR, f"script raised: {type(e).__name__}: {e}")
    try:
        if isinstance(value, (dict, list, str, int, float, bool, type(None))):
            raw = _json.dumps(value, default=str, ensure_ascii=False)
            if len(raw) > _MAX_SCRIPT_OUTPUT:
                raw = raw[:_MAX_SCRIPT_OUTPUT] + "...[truncated]"
                try:
                    value = _json.loads(raw)
                except Exception:
                    value = {"_truncated": True, "preview": raw}
    except Exception:
        pass
    return {"ok": True, "result": value}


# ============================================================
# DISPATCHER — 11 consolidated actions
# ============================================================

_ANALYZE_DISPATCH = {
    "stack_strings": lambda addr, limit, **kw: _detect_obfuscation(addr, what="stack_strings", limit=limit),
    "dead_code":     lambda addr, limit, **kw: _detect_obfuscation(addr, what="dead_code", limit=limit),
    "api_hashing":   lambda addr, limit, **kw: _detect_obfuscation(addr, what="api_hashing", limit=limit),
    "dynamic_dispatch": lambda addr, limit, **kw: _detect_obfuscation(addr, what="dynamic_dispatch", limit=limit),
    "anti_disasm":   lambda addr, limit, **kw: _detect_obfuscation(addr, what="anti_disasm", limit=limit),
    "encoding":      lambda addr, limit, **kw: _detect_obfuscation(addr, what="encoding", limit=limit),
    "crypto_constants": lambda addr, limit, **kw: _scan_crypto_constants(scope_ea=None, limit=limit),
    "checksums":     lambda addr, limit, **kw: _scan_crypto_constants(scope_ea=None, limit=limit),
    "entropy_high":  lambda addr, limit, **kw: _scan_crypto_constants(scope_ea=None, limit=limit),
    "aes_ni":        lambda addr, limit, **kw: _scan_crypto_constants(scope_ea=None, limit=limit),
}

_PROTOCOL_SPEC_TARGETS = {
    "parsers", "serializers", "handlers", "endpoints", "tls_config",
    "socket_flow", "packet_struct", "magic_numbers", "state_machine",
    "reconstruct", "trace_handler", "export_spec",
}


@tool
@idaread
def security(
    action: Annotated[str, "Security analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    what: Annotated[Optional[str], "Sub-target for analyze/protocol_spec"] = None,
    source: Annotated[Optional[str], "Taint source name or address"] = None,
    method: Annotated[Optional[str], "Hook method: frida|detours|inline"] = None,
    category: Annotated[Optional[str], "Hook category: network|file|crypto|registry|process"] = None,
    func_name: Annotated[Optional[str], "Function name for hook generation"] = None,
    max_depth: Annotated[int, "Max call-graph depth for taint"] = 5,
    max_paths: Annotated[int, "Max paths to return"] = 20,
    key: Annotated[Optional[str], "Decryption key for decode (hex)"] = None,
    code: Annotated[Optional[str], "Python code for eval action"] = None,
    include_anti_debug: Annotated[bool, "Include anti-debug detection in detect"] = True,
    include_drm: Annotated[bool, "Include anti-cheat detection in detect"] = True,
    **kwargs,
) -> dict:
    """Unified security analysis — 11 actions.

    detect — Full security sweep: packer + entropy + crypto + obfuscation.
    decode — Decode bytes at addr (XOR brute force, Base64). Params: addr, key.
    analyze — Scan for patterns. Params: what (stack_strings|dead_code|api_hashing|
        dynamic_dispatch|anti_disasm|encoding|crypto_constants|checksums|entropy_high|aes_ni).
    hook — Generate instrumentation. Params: method (frida|detours|inline), addr/func_name.
    hook_targets — Find hookable functions. Params: category (optional).
    protocol — Detect protocol usage.
    protocol_spec — Recover protocol structure. Params: what (parsers|serializers|handlers|
        endpoints|tls_config|socket_flow|packet_struct|magic_numbers|state_machine|reconstruct|
        trace_handler|export_spec).
    taint — Trace source→sink. Params: source.
    taint_sources — List all taint sources.
    taint_report — Full taint report.
    eval — Run custom Python. Params: code. Has access to compute_entropy,
        scan_crypto_constants, detect_obfuscation, detect_packer, IDA SDK.
    """
    try:
        if action == "detect":
            return _run_detect(addr, limit, include_anti_debug, include_drm, kwargs.get("max_string_scan", 5000))

        elif action == "decode":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for decode")
            return _decode_at(addr, key, limit)

        elif action == "analyze":
            if not what:
                return make_error(MCPError.INVALID_ARGS, "what required",
                                  hint=f"Available: {', '.join(sorted(_ANALYZE_DISPATCH.keys()))}")
            handler = _ANALYZE_DISPATCH.get(what)
            if not handler:
                return make_error(MCPError.INVALID_ARGS, f"Unknown analyze target: '{what}'")
            return handler(addr, limit, **kwargs)

        elif action == "hook":
            if not method:
                return make_error(MCPError.INVALID_ARGS, "method required", hint="frida, detours, inline")
            if not addr and not func_name:
                return make_error(MCPError.INVALID_ARGS, "addr or func_name required")
            if method == "frida":
                return _generate_frida(addr, func_name)
            elif method == "detours":
                return _generate_detours(addr, func_name)
            elif method == "inline":
                return _find_inline_hook_points(addr)
            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown method: '{method}'", hint="frida, detours, inline")

        elif action == "hook_targets":
            return _find_hook_targets(category, limit)

        elif action == "protocol":
            return _detect_protocol_impl(addr, limit)

        elif action == "protocol_spec":
            if not what:
                return make_error(MCPError.INVALID_ARGS, "what required",
                                  hint=f"Available: {', '.join(sorted(_PROTOCOL_SPEC_TARGETS))}")
            if what not in _PROTOCOL_SPEC_TARGETS:
                return make_error(MCPError.INVALID_ARGS, f"Unknown target: '{what}'")
            return _protocol_spec_impl(what, addr, limit)

        elif action == "taint":
            if not source and not addr:
                return make_error(MCPError.INVALID_ARGS, "source or addr required")
            return _taint_trace(source, addr, max_depth, max_paths)

        elif action == "taint_sources":
            return _taint_sources_list()

        elif action == "taint_report":
            return _taint_report_full(max_depth, max_paths)

        elif action == "eval":
            return _run_eval(code, kwargs.get("globals"))

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: '{action}'",
                              hint="detect, decode, analyze, hook, hook_targets, protocol, "
                                   "protocol_spec, taint, taint_sources, taint_report, eval")

    except Exception as e:
        return handle_error(e)
