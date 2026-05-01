
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re
import math
import base64
from collections import Counter


# ============================================================================
# STRING_OPS - Deep String Analysis for LLMs
# ============================================================================

_URL_PATTERN = re.compile(
    rb'(https?://|ftp://|file://)[^\s\x00"\'<>\)]{3,}', re.IGNORECASE
)

_DOMAIN_PATTERN = re.compile(
    rb'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', re.IGNORECASE
)

_PATH_PATTERN = re.compile(
    rb'([A-Za-z]:\\[^\x00"\'<>|]{2,}|/(?:usr|etc|var|tmp|bin|sbin|opt|home|proc|dev)/[^\x00"\'<>|]{1,})',
)

_REGISTRY_PATTERN = re.compile(
    rb'(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC|Software\\|CurrentVersion\\|Microsoft\\)',
    re.IGNORECASE,
)

_IPV4_PATTERN = re.compile(
    rb'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)',
)

_IPV6_PATTERN = re.compile(
    rb'([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})',
)

_EMAIL_PATTERN = re.compile(
    rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
)

_CMD_PATTERN = re.compile(
    rb'(cmd\.exe|cmd\s*/[cCkK]|powershell|pwsh|/bin/sh|/bin/bash|/bin/zsh|'
    rb'exec\s*\(|system\s*\(|popen|ShellExecute|WinExec|CreateProcess)',
    re.IGNORECASE,
)

_SUSPICIOUS_PATTERN = re.compile(
    rb'(password|passwd|secret|token|api.?key|private.?key|credential|authorization|'
    rb'bearer\s|basic\s[A-Za-z0-9+/=]{8,}|[A-Za-z0-9+/=]{40,})',
    re.IGNORECASE,
)

_FILE_EXT_PATTERN = re.compile(
    rb'\.(dll|exe|sys|bat|ps1|vbs|js|scr|com|pif|msi|cab|inf|lnk|drv)\b',
    re.IGNORECASE,
)

_BASE64_PATTERN = re.compile(
    rb'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)

_JWT_PATTERN = re.compile(
    rb'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
)

_AWS_KEY_PATTERN = re.compile(
    rb'(AKIA[0-9A-Z]{16})'
)

_AWS_SECRET_PATTERN = re.compile(
    rb'([0-9a-zA-Z/+]{40})'
)

_GITHUB_TOKEN_PATTERN = re.compile(
    rb'(gh[pousr]_[A-Za-z0-9_]{36,})'
)

_SLACK_TOKEN_PATTERN = re.compile(
    rb'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)'
)

_MONGO_URI_PATTERN = re.compile(
    rb'mongodb(\+srv)?://[^\s\x00"\'<>\)]+', re.IGNORECASE
)

_REDIS_URI_PATTERN = re.compile(
    rb'redis://[^\s\x00"\'<>\)]+', re.IGNORECASE
)

_SQL_CONN_PATTERN = re.compile(
    rb'(Server=|Data Source=|Host=|Port=|Database=|Initial Catalog=)[^;\s\x00]+',
    re.IGNORECASE,
)

_USER_AGENT_PATTERN = re.compile(
    rb'(Mozilla|curl|Wget|Python-urllib|libwww|Go-http|Java|OkHttp|Postman)[^\x00\r\n]{5,}',
    re.IGNORECASE,
)

_ONION_PATTERN = re.compile(
    rb'[a-z2-7]{16,56}\.onion', re.IGNORECASE
)

_BTC_PATTERN = re.compile(
    rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}'
)

_JSON_PATTERN = re.compile(
    rb'\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\}'
)

_XML_PATTERN = re.compile(
    rb'<\?xml[^?]*\?>'
)

_KEYVAL_PATTERN = re.compile(
    rb'([A-Za-z_][A-Za-z0-9_]{2,})\s*=\s*([^\s\x00;,"\']{1,64})'
)

_PORT_PATTERN = re.compile(
    rb':(\d{2,5})'
)

# --- Stack-string detection heuristics ---
# Look for sequences of mov instructions with immediate values in a function
_STACK_STRING_MOV_PATTERNS = [
    # x86/x64: mov [ebp+offset], imm8/imm16/imm32
    re.compile(rb'\xC6\x45[\x00-\xFF][\x00-\xFF]'),  # mov byte ptr [ebp+xx], yy
    re.compile(rb'\xC7\x45[\x00-\xFF][\x00-\xFF]{4}'),  # mov dword ptr [ebp+xx], imm32
    re.compile(rb'\x66\xC7\x45[\x00-\xFF][\x00-\xFF]{2}'),  # mov word ptr [ebp+xx], imm16
    # x64: mov [rsp+offset], imm
    re.compile(rb'\xC6\x44\x24[\x00-\xFF][\x00-\xFF]'),  # mov byte ptr [rsp+xx], yy
    re.compile(rb'\xC7\x44\x24[\x00-\xFF][\x00-\xFF]{4}'),  # mov dword ptr [rsp+xx], imm32
]


# ============================================================================
# Helpers
# ============================================================================

def _iter_strings(limit=500):
    """Iterate all strings via idautils.Strings(), yielding (ea, raw_bytes, str_type)."""
    results = []
    for s in idautils.Strings():
        str_type = idc.get_str_type(s.ea)
        raw = idc.get_strlit_contents(s.ea, -1, str_type if str_type not in (None, -1) else 0)
        if raw is not None:
            results.append((s.ea, raw, str_type))
            if len(results) >= limit:
                break
    return results


def _text_or_repr(raw):
    try:
        return raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception:
        return repr(raw)


def _scope_filter(strings, addr):
    if addr is None:
        return strings
    ea = parse_address(addr)
    func = ida_funcs.get_func(ea)
    if not func:
        return strings
    func_items = set(idautils.FuncItems(func.start_ea))
    scoped = []
    for s_ea, raw, st in strings:
        for xref in idautils.XrefsTo(s_ea):
            if xref.frm in func_items:
                scoped.append((s_ea, raw, st))
                break
    return scoped


def _query_filter(strings, query):
    if not query:
        return strings
    matcher = compile_smart_pattern(str(query), case_sensitive=False)
    filtered = []
    for ea, raw, st in strings:
        if matcher(_text_or_repr(raw)):
            filtered.append((ea, raw, st))
    return filtered


def _match_pattern(strings, pattern, limit, extract_groups=False):
    results = []
    for s_ea, raw, st in strings:
        m = pattern.search(raw)
        if m:
            text = _text_or_repr(raw)
            if extract_groups:
                results.append(f"{hex(s_ea)}  match={m.group(0).decode('utf-8', errors='replace') if isinstance(m.group(0), bytes) else str(m.group(0))}  {text}")
            else:
                results.append(f"{hex(s_ea)}  {text}")
            if len(results) >= limit:
                break
    return results


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


def _get_func_name_for_ea(ea):
    func = idaapi.get_func(ea)
    if func:
        return idc.get_func_name(func.start_ea) or "unknown"
    return "unknown"


def _find_string_xrefs(strings, limit):
    """Find which functions reference each string."""
    results = []
    for s_ea, raw, st in strings:
        funcs = set()
        for xref in idautils.XrefsTo(s_ea):
            func = idaapi.get_func(xref.frm)
            if func:
                funcs.add(idc.get_func_name(func.start_ea) or "unknown")
        if funcs:
            text = _text_or_repr(raw)
            # Truncate very long strings
            if len(text) > 120:
                text = text[:117] + "..."
            funcs_str = ", ".join(sorted(funcs))
            results.append(f"{hex(s_ea)}  funcs=[{funcs_str}]  {text}")
            if len(results) >= limit:
                break
    return results


def _find_stack_strings(limit):
    """Detect strings constructed on the stack via immediate mov instructions."""
    results = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        candidates = []
        for item in idautils.FuncItems(func_ea):
            insn = idaapi.get_dword(item) if idc.get_item_size(item) >= 4 else 0
            # Simple heuristic: look for mov with immediate value that looks like ASCII
            mnem = idc.print_insn_mnem(item)
            if not mnem or mnem.lower() not in ("mov", "movsx", "movzx", "movs", "movd"):
                continue
            # Check if destination is stack-relative
            op0_type = idc.get_operand_type(item, 0)
            op1_type = idc.get_operand_type(item, 1)
            if op1_type not in (idc.o_imm, idc.o_mem):
                continue
            # Get immediate value
            val = idc.get_operand_value(item, 1)
            if val == 0 or val == idaapi.BADADDR:
                continue
            # Check if value contains printable ASCII bytes
            try:
                bval = val.to_bytes(8, 'little')
            except OverflowError:
                continue
            printable = sum(1 for b in bval if 32 <= b <= 126)
            if printable >= 2:
                # Try to extract readable chars
                chars = ""
                for b in bval:
                    if 32 <= b <= 126:
                        chars += chr(b)
                    else:
                        break
                if len(chars) >= 2:
                    candidates.append((hex(item), chars))
        if candidates:
            func_name = idc.get_func_name(func_ea) or hex(func_ea)
            lines = [f"  {addr}: {text}" for addr, text in candidates[:8]]
            results.append(f"func={func_name}\n" + "\n".join(lines))
            if len(results) >= limit:
                break
    return results


def _find_base64_strings(strings, limit, decode=False):
    results = []
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        for m in _BASE64_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            b64_str = m.group(0).decode("ascii", errors="replace")
            # Quick validation: length divisible by 4 and has reasonable char distribution
            if len(b64_str) < 8 or len(b64_str) % 4 != 0:
                continue
            decoded = None
            if decode:
                try:
                    decoded_bytes = base64.b64decode(b64_str)
                    # Only decode if result is mostly printable
                    printable = sum(1 for b in decoded_bytes if 32 <= b <= 126)
                    if len(decoded_bytes) > 0 and printable / len(decoded_bytes) > 0.7:
                        decoded = decoded_bytes.decode("utf-8", errors="replace")
                except Exception:
                    pass
            if decoded:
                results.append(f"{hex(s_ea)}  b64={b64_str}  decoded={decoded}")
            else:
                results.append(f"{hex(s_ea)}  b64={b64_str}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
    return results


def _find_api_keys(strings, limit):
    results = []
    patterns = [
        ("AWS Access Key", _AWS_KEY_PATTERN),
        ("AWS Secret", _AWS_SECRET_PATTERN),
        ("GitHub Token", _GITHUB_TOKEN_PATTERN),
        ("Slack Token", _SLACK_TOKEN_PATTERN),
        ("JWT", _JWT_PATTERN),
    ]
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        for label, pat in patterns:
            for m in pat.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
                match_str = m.group(0).decode("utf-8", errors="replace")
                results.append(f"{hex(s_ea)}  [{label}]  {match_str}")
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
    return results


def _find_configs(strings, limit):
    results = []
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        # JSON-like
        for m in _JSON_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            json_str = m.group(0).decode("utf-8", errors="replace")
            if len(json_str) > 10:
                results.append(f"{hex(s_ea)}  [JSON]  {json_str[:120]}{'...' if len(json_str) > 120 else ''}")
                if len(results) >= limit:
                    break
                break
        if len(results) >= limit:
            break
        # XML-like
        if _XML_PATTERN.search(raw):
            results.append(f"{hex(s_ea)}  [XML]  {text[:120]}{'...' if len(text) > 120 else ''}")
            if len(results) >= limit:
                break
            continue
        # Key=value pairs
        for m in _KEYVAL_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            k = m.group(1).decode("utf-8", errors="replace")
            v = m.group(2).decode("utf-8", errors="replace")
            results.append(f"{hex(s_ea)}  [K=V]  {k}={v}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
    return results


def _find_c2(strings, limit):
    results = []
    seen = set()
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        # URLs
        for m in _URL_PATTERN.finditer(raw):
            url = m.group(0).decode("utf-8", errors="replace")
            key = ("url", url)
            if key not in seen:
                seen.add(key)
                results.append(f"{hex(s_ea)}  [URL]  {url}")
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
        # IPs
        for m in _IPV4_PATTERN.finditer(raw):
            ip = m.group(0).decode("ascii", errors="replace")
            key = ("ip", ip)
            if key not in seen:
                seen.add(key)
                results.append(f"{hex(s_ea)}  [IP]  {ip}")
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
        # Domains (that aren't URLs)
        for m in _DOMAIN_PATTERN.finditer(raw):
            domain = m.group(0).decode("utf-8", errors="replace")
            if domain.lower() in ("www.example.com", "example.com"):
                continue
            key = ("domain", domain)
            if key not in seen:
                seen.add(key)
                results.append(f"{hex(s_ea)}  [DOMAIN]  {domain}")
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
        # User agents
        for m in _USER_AGENT_PATTERN.finditer(raw):
            ua = m.group(0).decode("utf-8", errors="replace")
            key = ("ua", ua)
            if key not in seen:
                seen.add(key)
                results.append(f"{hex(s_ea)}  [UA]  {ua[:80]}{'...' if len(ua) > 80 else ''}")
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
        # Onion addresses
        for m in _ONION_PATTERN.finditer(raw):
            onion = m.group(0).decode("utf-8", errors="replace")
            key = ("onion", onion)
            if key not in seen:
                seen.add(key)
                results.append(f"{hex(s_ea)}  [ONION]  {onion}")
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
        # Ports
        for m in _PORT_PATTERN.finditer(raw):
            port = m.group(1).decode("ascii", errors="replace")
            try:
                pnum = int(port)
                if 1 <= pnum <= 65535:
                    key = ("port", port)
                    if key not in seen:
                        seen.add(key)
                        results.append(f"{hex(s_ea)}  [PORT]  {port}")
                        if len(results) >= limit:
                            break
            except ValueError:
                pass
        if len(results) >= limit:
            break
    return results


def _entropy_rank(strings, limit, min_entropy=4.0):
    ranked = []
    for s_ea, raw, st in strings:
        if not raw or len(raw) < 4:
            continue
        ent = _shannon_entropy(raw)
        if ent >= min_entropy:
            text = _text_or_repr(raw)
            ranked.append((ent, s_ea, text))
    ranked.sort(reverse=True)
    results = []
    for ent, s_ea, text in ranked[:limit]:
        if len(text) > 120:
            text = text[:117] + "..."
        results.append(f"{hex(s_ea)}  ent={ent}  {text}")
    return results


def _find_databases(strings, limit):
    results = []
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        for m in _MONGO_URI_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            uri = m.group(0).decode("utf-8", errors="replace")
            results.append(f"{hex(s_ea)}  [MONGO]  {uri}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
        for m in _REDIS_URI_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            uri = m.group(0).decode("utf-8", errors="replace")
            results.append(f"{hex(s_ea)}  [REDIS]  {uri}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
        for m in _SQL_CONN_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            conn = m.group(0).decode("utf-8", errors="replace")
            results.append(f"{hex(s_ea)}  [SQL]  {conn}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
    return results


def _find_crypto_addrs(strings, limit):
    results = []
    for s_ea, raw, st in strings:
        text = _text_or_repr(raw)
        for m in _BTC_PATTERN.finditer(raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")):
            addr = m.group(0).decode("utf-8", errors="replace")
            results.append(f"{hex(s_ea)}  [BTC]  {addr}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break
    return results


# ============================================================================
# Main Tool
# ============================================================================

@tool
@idaread
def string_ops(
    action: Annotated[Literal[
        "decode_all", "find_urls", "find_paths", "find_registry", "find_ips", "find_emails",
        "find_commands", "encoding_stats", "multilingual", "suspicious", "find_xrefs",
        "find_stack_strings", "find_base64", "find_api_keys", "find_configs", "find_c2",
        "find_databases", "find_crypto_addrs", "entropy_rank"
    ], "String operations action"],
    addr: Annotated[Optional[str], "Function or address scope"] = None,
    limit: Annotated[int, "Max results"] = 50,
    query: Annotated[Optional[str], "Filter pattern (regex/glob/substring/semantic auto-detected)"] = None,
    decode: Annotated[bool, "Decode base64 strings (for find_base64)"] = False,
    min_entropy: Annotated[float, "Minimum entropy threshold (for entropy_rank)"] = 4.0,
) -> dict:
    """
    Deep string analysis for binary reverse engineering.

    Actions:
    - decode_all: Attempt to decode all non-ASCII strings (UTF-16, UTF-8, wide, shift_jis, gb2312, cp1252)
    - find_urls: Find URL-like strings (http, https, ftp, file)
    - find_paths: Find file path strings (Windows and Unix paths, extensions)
    - find_registry: Find Windows registry key strings
    - find_ips: Find IP address strings (IPv4 and IPv6)
    - find_emails: Find email address strings
    - find_commands: Find command-line / shell execution strings
    - encoding_stats: Statistics on string encodings in the binary
    - multilingual: Find strings with non-ASCII / non-English characters
    - suspicious: Find suspicious strings (passwords, tokens, keys, base64-like)
    - find_xrefs: Cross-reference strings to the functions that use them
    - find_stack_strings: Detect strings constructed on the stack via immediate movs (malware technique)
    - find_base64: Detect and optionally decode base64-encoded strings
    - find_api_keys: Detect common API keys/tokens (AWS, GitHub, Slack, JWT)
    - find_configs: Detect JSON, XML, and key=value configuration strings
    - find_c2: Extract C2 indicators (URLs, IPs, domains, user agents, ports, onion addresses)
    - find_databases: Detect database connection strings (MongoDB, Redis, SQL)
    - find_crypto_addrs: Detect cryptocurrency addresses (Bitcoin)
    - entropy_rank: Rank strings by Shannon entropy to find encrypted/obfuscated data
    """
    try:
        all_strings = _iter_strings(limit=limit * 10)
        all_strings = _scope_filter(all_strings, addr)
        all_strings = _query_filter(all_strings, query)

        if action == "decode_all":
            results = []
            for s_ea, raw, st in all_strings:
                has_non_ascii = any(b > 127 for b in raw)
                if not has_non_ascii:
                    continue
                best_decoded = None
                best_enc = "unknown"
                best_conf = 0.0
                for try_enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1", "cp1252", "shift_jis", "gb2312", "euc-kr"):
                    try:
                        decoded = raw.decode(try_enc)
                        # Confidence heuristic: ratio of printable chars
                        printable = sum(1 for c in decoded if c.isprintable() or c.isspace())
                        conf = printable / len(decoded) if decoded else 0.0
                        if conf > best_conf:
                            best_conf = conf
                            best_decoded = decoded
                            best_enc = try_enc
                    except (UnicodeDecodeError, Exception):
                        continue
                if best_decoded is None:
                    best_decoded = raw.decode("utf-8", errors="replace")
                    best_enc = "utf-8-lossy"
                    best_conf = 0.0
                display = best_decoded.replace("\n", "\\n").replace("\r", "\\r")
                if len(display) > 120:
                    display = display[:117] + "..."
                results.append(f"{hex(s_ea)}  [{best_enc}] conf={best_conf:.2f}  {display}")
                if len(results) >= limit:
                    break
            return {"ok": True, "decoded_strings": "\n".join(results), "count": len(results)}

        elif action == "find_urls":
            hits = _match_pattern(all_strings, _URL_PATTERN, limit)
            return {"ok": True, "urls": "\n".join(hits), "count": len(hits)}

        elif action == "find_paths":
            combined = re.compile(
                _PATH_PATTERN.pattern + b"|" + _FILE_EXT_PATTERN.pattern,
                re.IGNORECASE,
            )
            hits = _match_pattern(all_strings, combined, limit)
            return {"ok": True, "paths": "\n".join(hits), "count": len(hits)}

        elif action == "find_registry":
            hits = _match_pattern(all_strings, _REGISTRY_PATTERN, limit)
            return {"ok": True, "registry_keys": "\n".join(hits), "count": len(hits)}

        elif action == "find_ips":
            results = []
            for s_ea, raw, st in all_strings:
                m4 = _IPV4_PATTERN.search(raw)
                m6 = _IPV6_PATTERN.search(raw)
                if m4 or m6:
                    text = _text_or_repr(raw)
                    ip = (m4 or m6).group(0).decode("ascii", errors="replace")
                    results.append(f"{hex(s_ea)}  ip={ip}  {text}")
                    if len(results) >= limit:
                        break
            return {"ok": True, "ip_addresses": "\n".join(results), "count": len(results)}

        elif action == "find_emails":
            hits = _match_pattern(all_strings, _EMAIL_PATTERN, limit)
            return {"ok": True, "emails": "\n".join(hits), "count": len(hits)}

        elif action == "find_commands":
            hits = _match_pattern(all_strings, _CMD_PATTERN, limit)
            return {"ok": True, "commands": "\n".join(hits), "count": len(hits)}

        elif action == "encoding_stats":
            stats = {"ascii": 0, "utf-8": 0, "utf-16": 0, "wide": 0, "unknown": 0}
            total = 0
            for s_ea, raw, st in all_strings:
                total += 1
                if st == idc.STRTYPE_C:
                    if all(b < 128 for b in raw):
                        stats["ascii"] += 1
                    else:
                        stats["utf-8"] += 1
                elif st in (idc.STRTYPE_C_16, 1):
                    stats["utf-16"] += 1
                elif st in (idc.STRTYPE_C_32,) if hasattr(idc, "STRTYPE_C_32") else ():
                    stats["wide"] += 1
                else:
                    stats["unknown"] += 1
            lines = [f"{enc}: {cnt}" for enc, cnt in stats.items()]
            return {"ok": True, "total": total, "encoding_stats": "\n".join(lines)}

        elif action == "multilingual":
            results = []
            for s_ea, raw, st in all_strings:
                has_non_ascii = any(b > 127 for b in raw)
                if not has_non_ascii:
                    continue
                text = _text_or_repr(raw)
                if any(ord(c) > 255 for c in text):
                    results.append(f"{hex(s_ea)}  {text}")
                    if len(results) >= limit:
                        break
            return {"ok": True, "multilingual_strings": "\n".join(results), "count": len(results)}

        elif action == "suspicious":
            hits = _match_pattern(all_strings, _SUSPICIOUS_PATTERN, limit)
            return {"ok": True, "suspicious_strings": "\n".join(hits), "count": len(hits)}

        elif action == "find_xrefs":
            hits = _find_string_xrefs(all_strings, limit)
            return {"ok": True, "xrefs": "\n".join(hits), "count": len(hits)}

        elif action == "find_stack_strings":
            hits = _find_stack_strings(limit)
            return {"ok": True, "stack_strings": "\n\n".join(hits), "count": len(hits)}

        elif action == "find_base64":
            hits = _find_base64_strings(all_strings, limit, decode=decode)
            return {"ok": True, "base64_strings": "\n".join(hits), "count": len(hits)}

        elif action == "find_api_keys":
            hits = _find_api_keys(all_strings, limit)
            return {"ok": True, "api_keys": "\n".join(hits), "count": len(hits)}

        elif action == "find_configs":
            hits = _find_configs(all_strings, limit)
            return {"ok": True, "configs": "\n".join(hits), "count": len(hits)}

        elif action == "find_c2":
            hits = _find_c2(all_strings, limit)
            return {"ok": True, "c2_indicators": "\n".join(hits), "count": len(hits)}

        elif action == "find_databases":
            hits = _find_databases(all_strings, limit)
            return {"ok": True, "database_strings": "\n".join(hits), "count": len(hits)}

        elif action == "find_crypto_addrs":
            hits = _find_crypto_addrs(all_strings, limit)
            return {"ok": True, "crypto_addrs": "\n".join(hits), "count": len(hits)}

        elif action == "entropy_rank":
            hits = _entropy_rank(all_strings, limit, min_entropy=min_entropy)
            return {"ok": True, "entropy_ranked": "\n".join(hits), "count": len(hits)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
