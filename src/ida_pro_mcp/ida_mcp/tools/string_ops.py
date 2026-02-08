
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re


# ============================================================================
# STRING_OPS - Deep String Analysis for LLMs
# ============================================================================

_URL_PATTERN = re.compile(
    rb'(https?://|ftp://|file://)[^\s\x00"\'<>\)]{3,}', re.IGNORECASE
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


def _scope_filter(strings, addr):
    """Filter strings to those referenced by a specific function, if addr is given."""
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
    """Filter strings by a text substring or regex pattern."""
    if not query:
        return strings
    try:
        pat = re.compile(query.encode() if isinstance(query, str) else query, re.IGNORECASE)
        return [(ea, raw, st) for ea, raw, st in strings if pat.search(raw)]
    except re.error:
        q = query.encode() if isinstance(query, str) else query
        return [(ea, raw, st) for ea, raw, st in strings if q.lower() in raw.lower()]


def _match_pattern(strings, pattern, limit):
    """Return strings matching a regex pattern."""
    results = []
    for s_ea, raw, st in strings:
        m = pattern.search(raw)
        if m:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = repr(raw)
            results.append(f"{hex(s_ea)}  {text}")
            if len(results) >= limit:
                break
    return results


@tool
@idaread
def string_ops(
    action: Annotated[Literal["decode_all", "find_urls", "find_paths", "find_registry", "find_ips", "find_emails", "find_commands", "encoding_stats", "multilingual", "suspicious"],
                      "String operations action"],
    addr: Annotated[Optional[str], "Function or address scope"] = None,
    limit: Annotated[int, "Max results"] = 50,
    query: Annotated[Optional[str], "Filter pattern (regex/glob/substring auto-detected)"] = None,
) -> dict:
    """
    Deep string analysis for binary reverse engineering.

    Actions:
    - decode_all: Attempt to decode all non-ASCII strings (UTF-16, UTF-8, wide)
    - find_urls: Find URL-like strings (http, https, ftp, file)
    - find_paths: Find file path strings (Windows and Unix paths, extensions)
    - find_registry: Find Windows registry key strings
    - find_ips: Find IP address strings (IPv4 and IPv6)
    - find_emails: Find email address strings
    - find_commands: Find command-line / shell execution strings
    - encoding_stats: Statistics on string encodings in the binary
    - multilingual: Find strings with non-ASCII / non-English characters
    - suspicious: Find suspicious strings (passwords, tokens, keys, base64)
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
                decoded = None
                enc = "unknown"
                for try_enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1", "shift_jis", "gb2312"):
                    try:
                        decoded = raw.decode(try_enc)
                        enc = try_enc
                        break
                    except (UnicodeDecodeError, Exception):
                        continue
                if decoded is None:
                    decoded = raw.decode("utf-8", errors="replace")
                    enc = "utf-8-lossy"
                results.append(f"{hex(s_ea)}  [{enc}]  {decoded}")
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
                    try:
                        text = raw.decode("utf-8", errors="replace")
                    except Exception:
                        text = repr(raw)
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
                try:
                    text = raw.decode("utf-8", errors="replace")
                except Exception:
                    text = repr(raw)
                if any(ord(c) > 255 for c in text):
                    results.append(f"{hex(s_ea)}  {text}")
                    if len(results) >= limit:
                        break
            return {"ok": True, "multilingual_strings": "\n".join(results), "count": len(results)}

        elif action == "suspicious":
            hits = _match_pattern(all_strings, _SUSPICIOUS_PATTERN, limit)
            return {"ok": True, "suspicious_strings": "\n".join(hits), "count": len(hits)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
