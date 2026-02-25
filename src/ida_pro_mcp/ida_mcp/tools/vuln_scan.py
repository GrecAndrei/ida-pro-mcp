
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import json as _json
import urllib.error
import urllib.request


# ============================================================================
# VULN_SCAN - LLM-Optimized Automated Vulnerability Scanning
# ============================================================================

# Dangerous API patterns grouped by vulnerability class
_BUFFER_OVERFLOW_FUNCS = [
    "strcpy", "strcat", "sprintf", "gets", "memcpy", "memmove",
    "wcscpy", "wcscat", "lstrcpy", "lstrcpyA", "lstrcpyW",
    "lstrcat", "lstrcatA", "lstrcatW", "scanf", "sscanf", "fscanf",
    "vscanf", "vsprintf",
    # POSIX / embedded
    "bcopy", "bzero", "stpcpy", "stpncpy",
    "read", "recv", "recvfrom",
]

_FORMAT_STRING_FUNCS = [
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "syslog", "swprintf", "wprintf",
    # Android / embedded
    "__android_log_print", "NSLog",
]

_COMMAND_INJECTION_FUNCS = [
    "system", "popen", "execl", "execle", "execlp", "execv", "execve",
    "execvp", "execvpe", "posix_spawn", "posix_spawnp",
    "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "CreateProcess", "CreateProcessA", "CreateProcessW",
    "_popen", "_wsystem",
    "dlopen",
]

_UAF_FREE_FUNCS = [
    "free", "HeapFree", "VirtualFree", "GlobalFree", "LocalFree",
    "CoTaskMemFree", "SysFreeString", "delete", "operator delete",
    "munmap",
]

_ALLOC_FUNCS = [
    "malloc", "calloc", "realloc", "HeapAlloc", "VirtualAlloc",
    "GlobalAlloc", "LocalAlloc", "new", "operator new",
    "mmap", "memalign", "aligned_alloc", "pvalloc", "valloc",
]

_RACE_CONDITION_FUNCS = [
    "access", "stat", "lstat", "fstat", "chmod", "chown",
    "rename", "unlink", "remove", "tmpnam", "tempnam", "mktemp",
]

_AUTH_FUNCS = [
    "strcmp", "strncmp", "memcmp", "wcsncmp", "wcscmp",
    "lstrcmp", "lstrcmpA", "lstrcmpW",
    "lstrcmpi", "lstrcmpiA", "lstrcmpiW",
]

_INFO_LEAK_FUNCS = [
    "syslog", "printf", "fprintf", "OutputDebugString",
    "OutputDebugStringA", "OutputDebugStringW",
    "NSLog", "Log", "WriteFile", "send",
]

_CWE_MAP = {
    "buffer_overflow":    ("CWE-120", "critical", "Buffer Copy without Checking Size of Input"),
    "format_string":      ("CWE-134", "high",     "Use of Externally-Controlled Format String"),
    "integer_overflow":   ("CWE-190", "high",     "Integer Overflow or Wraparound"),
    "use_after_free":     ("CWE-416", "critical", "Use After Free"),
    "command_injection":  ("CWE-78",  "critical", "OS Command Injection"),
    "race_condition":     ("CWE-362", "medium",   "Race Condition (TOCTOU)"),
    "null_deref":         ("CWE-476", "medium",   "NULL Pointer Dereference"),
    "info_leak":          ("CWE-200", "medium",   "Exposure of Sensitive Information"),
    "auth_bypass":        ("CWE-287", "high",     "Improper Authentication"),
    "hardcoded_creds":    ("CWE-798", "high",     "Use of Hard-coded Credentials"),
    "osv_known_vuln":     ("CWE-937", "high",     "Using Components with Known Vulnerabilities"),
}

_CREDENTIAL_PATTERNS = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "api_secret", "token", "auth_token", "access_key", "private_key",
    "credential", "login",
]

_AUTH_KEYWORDS = [
    "admin", "root", "password", "passwd",
    "login", "auth", "backdoor", "master",
]

_CREDENTIAL_EXCLUSIONS = [
    ".h", ".c", ".dll", "usage:", "help",
    "error", "warning", "invalid",
]


def _matches_win_api_variant(name, target):
    """Match Windows API names including A/W suffixes (e.g. CreateFileA, CreateFileW)."""
    n = name.lower()
    t = target.lower()
    return n == t or n == t + "a" or n == t + "w"


def _get_func_name_safe(ea):
    """Get function name for an address, or 'unknown'."""
    func = idaapi.get_func(ea)
    if func:
        return ida_funcs.get_func_name(func.start_ea)
    return "unknown"


def _normalize_api_name(name):
    """Normalize import/symbol names for robust matching across ABIs."""
    if not name:
        return ""
    n = name.strip().lower()
    if n.startswith("__imp_"):
        n = n[6:]
    elif n.startswith("imp_"):
        n = n[4:]
    while n.startswith("_"):
        n = n[1:]
    if "@" in n and n.rsplit("@", 1)[1].isdigit():
        n = n.rsplit("@", 1)[0]
    return n


def _find_symbol_eas(name, max_symbols=64):
    """Resolve symbol/import EAs for a target API name (with common variants)."""
    normalized_target = _normalize_api_name(name)
    eas = set()

    direct = idc.get_name_ea_simple(name)
    if direct != idaapi.BADADDR:
        eas.add(direct)

    # Also try normalized variants directly.
    if normalized_target and normalized_target != name.lower():
        direct2 = idc.get_name_ea_simple(normalized_target)
        if direct2 != idaapi.BADADDR:
            eas.add(direct2)

    # Scan imports for variant matches (A/W suffixes, stdcall decorators, prefixes).
    for i in range(ida_nalt.get_import_module_qty()):
        def cb(ea, imp_name, ordinal):
            if not imp_name:
                return True
            n = _normalize_api_name(imp_name)
            if n == normalized_target or _matches_win_api_variant(n, normalized_target):
                eas.add(ea)
                if len(eas) >= max_symbols:
                    return False
            return True
        ida_nalt.enum_import_names(i, cb)
        if len(eas) >= max_symbols:
            break
    return list(eas)


def _find_xrefs_to_name(name, limit):
    """Find code xrefs to a symbol/API name, including import variants."""
    refs = []
    seen = set()
    for ea in _find_symbol_eas(name):
        for xref in idautils.XrefsTo(ea, 0):
            if not xref.iscode:
                continue
            if xref.frm in seen:
                continue
            seen.add(xref.frm)
            refs.append(xref.frm)
            if len(refs) >= limit:
                return refs
    refs.sort()
    return refs


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


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _clip(text, max_len=180):
    if text is None:
        return ""
    s = " ".join(str(text).split())
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _resolve_scope(addr):
    """Resolve optional function scope address once per scanner."""
    if addr is None:
        return None, None
    scope_ea, err = validate_addr(addr, require_func=True)
    if err:
        return None, err
    return scope_ea, None


def _in_scope(ea, scope_ea):
    if scope_ea is None:
        return True
    func = idaapi.get_func(ea)
    return bool(func and func.start_ea == scope_ea)


def _format_finding_line(finding):
    return (
        f"{finding['addr']}  [{finding['severity']}/{finding['confidence']}] "
        f"{finding['cwe']} {finding['function']}: {finding['description']}"
    )


def _make_finding(
    ea,
    vuln_type,
    desc,
    pattern="",
    include_context=False,
    confidence="medium",
    severity_override=None,
):
    """Build a structured finding with compact + machine-readable fields."""
    cwe_id, severity, cwe_desc = _CWE_MAP.get(vuln_type, ("CWE-0", "low", vuln_type))
    if severity_override in _SEVERITY_RANK:
        severity = severity_override
    func_name = _get_func_name_safe(ea)
    finding = {
        "addr": hex_ea(ea),
        "ea": int(ea),
        "function": func_name,
        "type": vuln_type,
        "cwe": cwe_id,
        "severity": severity,
        "confidence": confidence if confidence in _CONFIDENCE_RANK else "medium",
        "description": _clip(desc, 240),
        "pattern": _clip(pattern, 120),
    }
    if include_context:
        ctx = _get_decompiled_context(ea)
        if ctx:
            finding["context"] = _clip(ctx, 320)
    finding["line"] = _format_finding_line(finding)
    return finding


def _dedupe_sort_paginate(findings, limit, offset=0, severity=None):
    """Normalize findings: dedupe, filter, rank, paginate."""
    unique = {}
    for f in findings:
        key = (f.get("type"), f.get("ea"), f.get("pattern"))
        current = unique.get(key)
        if current is None:
            unique[key] = f
            continue
        # Keep highest-confidence duplicate.
        if _CONFIDENCE_RANK.get(f.get("confidence", "low"), 1) > _CONFIDENCE_RANK.get(current.get("confidence", "low"), 1):
            unique[key] = f

    rows = list(unique.values())
    if severity:
        rows = [f for f in rows if f.get("severity") == severity]

    rows.sort(
        key=lambda f: (
            _SEVERITY_RANK.get(f.get("severity", "low"), 0),
            _CONFIDENCE_RANK.get(f.get("confidence", "low"), 0),
            -int(f.get("ea", 0)),
        ),
        reverse=True,
    )

    total = len(rows)
    page = rows[offset : offset + limit]
    truncated = (offset + len(page)) < total
    return page, total, truncated


def _summary_counts(findings):
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_type = {}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in by_severity:
            by_severity[sev] += 1
        t = f.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    return by_severity, by_type


def _normalize_osv_endpoint(endpoint):
    base = (endpoint or "https://api.osv.dev").strip()
    if not base:
        base = "https://api.osv.dev"
    if base.endswith("/v1/querybatch"):
        return base
    return base.rstrip("/") + "/v1/querybatch"


def _parse_osv_coord(coord, default_ecosystem=None):
    """
    Parse OSV coordinate formats:
    - ecosystem:name@version    (recommended)
    - name@version              (with default ecosystem)
    - pkg:purl/...              (purl mode)
    """
    raw = (coord or "").strip()
    if not raw:
        return None, "empty coordinate"

    if raw.startswith("pkg:"):
        # PURL query uses package.purl.
        return {"package": {"purl": raw}}, {"input": raw, "purl": raw}

    ecosystem = None
    name_part = raw
    if ":" in raw and "@" in raw and raw.index(":") < raw.index("@"):
        ecosystem, name_part = raw.split(":", 1)
        ecosystem = ecosystem.strip()
    elif default_ecosystem:
        ecosystem = default_ecosystem.strip()

    if "@" in name_part:
        pkg_name, version = name_part.rsplit("@", 1)
        pkg_name = pkg_name.strip()
        version = version.strip()
    else:
        pkg_name = name_part.strip()
        version = ""

    if not pkg_name:
        return None, f"invalid coordinate '{raw}' (missing package name)"
    if not ecosystem:
        return None, f"invalid coordinate '{raw}' (missing ecosystem, expected ecosystem:name@version)"

    query = {"package": {"name": pkg_name, "ecosystem": ecosystem}}
    if version:
        query["version"] = version

    return query, {"input": raw, "ecosystem": ecosystem, "name": pkg_name, "version": version}


def _http_json_post(url, payload, timeout_sec=8):
    body = _json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    if not raw:
        return {}
    return _json.loads(raw)


def _severity_from_osv(vuln):
    sev_entries = vuln.get("severity") or []
    for sev in sev_entries:
        score = str(sev.get("score") or "").strip()
        if not score:
            continue
        # Support either numeric scores ("9.8") or vectors containing a numeric prefix.
        num = ""
        for ch in score:
            if ch.isdigit() or ch == ".":
                num += ch
            elif num:
                break
        if not num:
            continue
        try:
            s = float(num)
        except Exception:
            continue
        if s >= 9.0:
            return "critical"
        if s >= 7.0:
            return "high"
        if s >= 4.0:
            return "medium"
        return "low"
    return None


def _scan_osv_coordinates(osv_coordinates, osv_endpoint, osv_ecosystem):
    queries = []
    query_meta = []
    parse_errors = []
    for coord in (osv_coordinates or []):
        query, meta_or_err = _parse_osv_coord(coord, default_ecosystem=osv_ecosystem)
        if query is None:
            parse_errors.append(meta_or_err)
            continue
        queries.append(query)
        query_meta.append(meta_or_err)

    if not queries:
        return [], query_meta, parse_errors, None

    url = _normalize_osv_endpoint(osv_endpoint)
    try:
        resp = _http_json_post(url, {"queries": queries}, timeout_sec=10)
    except urllib.error.HTTPError as e:
        return [], query_meta, parse_errors, f"OSV HTTP error {e.code}: {e.reason}"
    except Exception as e:
        return [], query_meta, parse_errors, f"OSV request failed: {e}"

    results = resp.get("results") or []
    findings = []
    for idx, entry in enumerate(results):
        meta = query_meta[idx] if idx < len(query_meta) else {}
        eco = meta.get("ecosystem", "unknown")
        pkg = meta.get("name", meta.get("purl", "unknown"))
        ver = meta.get("version", "")
        pkg_label = f"{eco}:{pkg}" + (f"@{ver}" if ver else "")
        for vuln in (entry.get("vulns") or []):
            osv_id = vuln.get("id", "OSV-UNKNOWN")
            summary = vuln.get("summary") or vuln.get("details") or "Known vulnerable component"
            sev_override = _severity_from_osv(vuln)
            finding = _make_finding(
                0,
                "osv_known_vuln",
                f"{pkg_label} affected by {osv_id}: {_clip(summary, 180)}",
                pattern=f"{pkg_label}:{osv_id}",
                include_context=False,
                confidence="high",
                severity_override=sev_override,
            )
            aliases = vuln.get("aliases") or []
            finding["osv"] = {
                "id": osv_id,
                "aliases": aliases,
                "package": pkg,
                "ecosystem": eco,
                "version": ver,
                "summary": _clip(summary, 220),
                "modified": vuln.get("modified"),
                "published": vuln.get("published"),
            }
            finding["line"] = finding["line"] + f"  [{osv_id}]"
            findings.append(finding)

    return findings, query_meta, parse_errors, None


def _get_decompiled_context(ea):
    """Return a few lines of decompiled code around ea, or empty string."""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return ""
        func = idaapi.get_func(ea)
        if not func:
            return ""
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            return ""
        text = str(cfunc)
        lines = text.splitlines()
        # Find the line closest to ea
        for i, ln in enumerate(lines):
            if hex(ea).removeprefix("0x") in ln or hex(ea) in ln:
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                return "\n".join(lines[start:end])
        return ""
    except Exception:
        return ""


def _scan_buffer_overflow(addr, limit, include_context):
    """Scan for buffer overflow vulnerabilities."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for dangerous in _BUFFER_OVERFLOW_FUNCS:
        refs = _find_xrefs_to_name(dangerous, max(16, limit * 3))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            f = _make_finding(
                call_ea, "buffer_overflow",
                f"Call to {dangerous}() without bounds checking",
                dangerous,
                include_context=include_context,
                confidence="medium" if dangerous in ("read", "recv", "recvfrom", "memmove") else "high",
            )
            findings.append(f)
            if len(findings) >= limit * 3:
                return findings
    return findings


def _scan_format_string(addr, limit, include_context):
    """Scan for format string vulnerabilities."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for dangerous in _FORMAT_STRING_FUNCS:
        refs = _find_xrefs_to_name(dangerous, max(16, limit * 3))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            # Heuristic: check if format arg is a register (non-const)
            is_suspicious = True
            confidence = "high"
            # Check previous instruction for lea with string literal
            prev = idc.prev_head(call_ea)
            if prev != idaapi.BADADDR:
                for xref in idautils.XrefsFrom(prev, 0):
                    if ida_bytes.is_strlit(ida_bytes.get_flags(xref.to)):
                        is_suspicious = False
                        confidence = "low"
                        break
            if is_suspicious:
                f = _make_finding(
                    call_ea, "format_string",
                    f"Call to {dangerous}() with potentially non-constant format string",
                    dangerous,
                    include_context=include_context,
                    confidence=confidence,
                )
                findings.append(f)
                if len(findings) >= limit * 3:
                    return findings
    return findings


def _scan_integer_overflow(addr, limit, include_context):
    """Scan for integer overflow before allocation/memcpy patterns."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    alloc_names = _ALLOC_FUNCS + ["memcpy", "memmove"]
    for alloc in alloc_names:
        refs = _find_xrefs_to_name(alloc, max(20, limit * 5))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            # Heuristic: look for arithmetic (add/mul/shl) in preceding instructions
            curr = call_ea
            for _ in range(8):
                curr = idc.prev_head(curr)
                if curr == idaapi.BADADDR:
                    break
                mnem = idc.print_insn_mnem(curr)
                if mnem and mnem.lower() in ARITHMETIC_MNEMONICS:
                    f = _make_finding(
                        curr, "integer_overflow",
                        f"Unchecked arithmetic ({mnem}) before {alloc}() at {hex_ea(call_ea)}",
                        f"{mnem} -> {alloc}",
                        include_context=include_context,
                        confidence="medium",
                    )
                    findings.append(f)
                    if len(findings) >= limit * 3:
                        return findings
                    break
    return findings


def _scan_use_after_free(addr, limit, include_context):
    """Scan for use-after-free patterns (free followed by pointer use)."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for free_func in _UAF_FREE_FUNCS:
        refs = _find_xrefs_to_name(free_func, max(16, limit * 4))
        for free_ea in refs:
            func = idaapi.get_func(free_ea)
            if not func:
                continue
            if scope_ea is not None and func.start_ea != scope_ea:
                continue
            # Check instructions after free for potential use of freed pointer
            curr = free_ea
            for i in range(10):
                curr = idc.next_head(curr)
                if curr == idaapi.BADADDR or curr >= func.end_ea:
                    break
                mnem = idc.print_insn_mnem(curr)
                if not mnem:
                    continue
                ml = mnem.lower()
                # Skip if we hit another call to free or a return
                if ml in RETURN_MNEMONICS or ml in UNCONDITIONAL_JUMP_MNEMONICS:
                    break
                # Look for dereference patterns after free
                disasm = ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))
                if "[" in disasm and ml not in ("lea", "push", "adr", "adrp"):
                    f = _make_finding(
                        curr, "use_after_free",
                        f"Potential use after {free_func}() at {hex_ea(free_ea)}",
                        f"{free_func} -> {disasm.strip()}",
                        include_context=include_context,
                        confidence="medium",
                    )
                    findings.append(f)
                    if len(findings) >= limit * 3:
                        return findings
                    break
    return findings


def _scan_command_injection(addr, limit, include_context):
    """Scan for command injection vulnerabilities."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for dangerous in _COMMAND_INJECTION_FUNCS:
        refs = _find_xrefs_to_name(dangerous, max(16, limit * 3))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            f = _make_finding(
                call_ea, "command_injection",
                f"Call to {dangerous}() - verify input is not user-controlled",
                dangerous,
                include_context=include_context,
                confidence="high" if dangerous in ("system", "popen", "execve", "CreateProcess", "CreateProcessA", "CreateProcessW") else "medium",
            )
            findings.append(f)
            if len(findings) >= limit * 3:
                return findings
    return findings


def _scan_race_condition(addr, limit, include_context):
    """Scan for TOCTOU and race condition patterns."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    check_funcs = {"access", "stat", "lstat", "fstat"}
    use_funcs = {"open", "fopen", "chmod", "chown", "rename",
                 "unlink", "remove", "CreateFile", "CreateFileA", "CreateFileW"}

    for check in check_funcs:
        check_refs = _find_xrefs_to_name(check, max(16, limit * 4))
        for check_ea in check_refs:
            func = idaapi.get_func(check_ea)
            if not func:
                continue
            if scope_ea is not None and func.start_ea != scope_ea:
                continue
            # Look for a file use operation in the same function after the check
            for item in idautils.FuncItems(func.start_ea):
                if item <= check_ea:
                    continue
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                        name = idc.get_name(xref.to)
                        name_norm = _normalize_api_name(name or "")
                        if name and any(_matches_win_api_variant(name_norm, u)
                                        for u in use_funcs):
                            f = _make_finding(
                                check_ea, "race_condition",
                                f"TOCTOU: {check}() at {hex_ea(check_ea)} then {name}() at {hex_ea(item)}",
                                f"{check} -> {name}",
                                include_context=include_context,
                                confidence="medium",
                            )
                            findings.append(f)
                            if len(findings) >= limit * 3:
                                return findings
    # Also flag tmpnam/mktemp usage directly
    for risky in ("tmpnam", "tempnam", "mktemp"):
        refs = _find_xrefs_to_name(risky, max(8, limit * 2))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            f = _make_finding(
                call_ea, "race_condition",
                f"Insecure temp file creation via {risky}()",
                risky,
                include_context=include_context,
                confidence="high",
            )
            findings.append(f)
            if len(findings) >= limit * 3:
                return findings
    return findings


def _scan_null_deref(addr, limit, include_context):
    """Scan for potential null pointer dereference (alloc without null check)."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for alloc in _ALLOC_FUNCS:
        refs = _find_xrefs_to_name(alloc, max(16, limit * 4))
        for call_ea in refs:
            func = idaapi.get_func(call_ea)
            if not func:
                continue
            if scope_ea is not None and func.start_ea != scope_ea:
                continue
            # Heuristic: check if next few instructions include a null test
            curr = call_ea
            has_null_check = False
            for _ in range(6):
                curr = idc.next_head(curr)
                if curr == idaapi.BADADDR or curr >= func.end_ea:
                    break
                mnem = idc.print_insn_mnem(curr)
                if not mnem:
                    continue
                ml = mnem.lower()
                if ml in COMPARISON_MNEMONICS or ml in CONDITIONAL_BRANCH_MNEMONICS:
                    has_null_check = True
                    break
                if ml in CALL_MNEMONICS or ml in RETURN_MNEMONICS:
                    break
            if not has_null_check:
                f = _make_finding(
                    call_ea, "null_deref",
                    f"Return value of {alloc}() used without NULL check",
                    alloc,
                    include_context=include_context,
                    confidence="medium",
                )
                findings.append(f)
                if len(findings) >= limit * 3:
                    return findings
    return findings


def _scan_info_leak(addr, limit, include_context):
    """Scan for information disclosure patterns."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    sensitive_strs = ["password", "secret", "token", "key", "cookie",
                      "session", "credit", "ssn", "cvv"]

    for log_func in _INFO_LEAK_FUNCS:
        refs = _find_xrefs_to_name(log_func, max(16, limit * 4))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            # Check if any nearby string references contain sensitive keywords
            prev = call_ea
            for _ in range(5):
                prev = idc.prev_head(prev)
                if prev == idaapi.BADADDR:
                    break
                for xref in idautils.XrefsFrom(prev, 0):
                    contents = idc.get_strlit_contents(xref.to)
                    if contents:
                        try:
                            s = contents.decode("utf-8", errors="ignore").lower()
                        except Exception:
                            s = str(contents).lower()
                        if any(kw in s for kw in sensitive_strs):
                            f = _make_finding(
                                call_ea, "info_leak",
                                f"Possible sensitive data logged via {log_func}(): \"{s[:60]}\"",
                                f"{log_func} with '{s[:40]}'",
                                include_context=include_context,
                                confidence="medium",
                            )
                            findings.append(f)
                            if len(findings) >= limit * 3:
                                return findings
    return findings


def _scan_auth_bypass(addr, limit, include_context):
    """Scan for authentication bypass patterns (compare with constants)."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    findings = []
    for cmp_func in _AUTH_FUNCS:
        refs = _find_xrefs_to_name(cmp_func, max(16, limit * 4))
        for call_ea in refs:
            if not _in_scope(call_ea, scope_ea):
                continue
            # Check if comparison references a hardcoded string with auth keywords
            for i in range(5):
                check_ea = call_ea
                for _ in range(i + 1):
                    check_ea = idc.prev_head(check_ea)
                    if check_ea == idaapi.BADADDR:
                        break
                if check_ea == idaapi.BADADDR:
                    break
                for xref in idautils.XrefsFrom(check_ea, 0):
                    contents = idc.get_strlit_contents(xref.to)
                    if contents:
                        try:
                            s = contents.decode("utf-8", errors="ignore").lower()
                        except Exception:
                            s = str(contents).lower()
                        if any(kw in s for kw in _AUTH_KEYWORDS):
                            f = _make_finding(
                                call_ea, "auth_bypass",
                                f"Hardcoded auth check via {cmp_func}() against \"{s[:60]}\"",
                                f"{cmp_func} vs '{s[:40]}'",
                                include_context=include_context,
                                confidence="medium" if "auth" in s or "login" in s else "low",
                            )
                            findings.append(f)
                            if len(findings) >= limit * 3:
                                return findings
    return findings


def _scan_hardcoded_creds(addr, limit, include_context):
    """Scan for hardcoded credentials and keys in strings."""
    scope_ea, err = _resolve_scope(addr)
    if err:
        return []
    import re

    # Require key=value or key:value style assignments for stronger signal.
    assign_re = re.compile(
        r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*[^\s]{3,}",
        re.IGNORECASE,
    )
    findings = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(findings) < (limit * 3):
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_strlit(flags):
                contents = idc.get_strlit_contents(ea)
                if contents:
                    try:
                        s = contents.decode("utf-8", errors="ignore")
                    except Exception:
                        s = str(contents)
                    s_lower = s.lower()
                    if len(s) < 8 or len(s) > 1024:
                        ea = idc.next_head(ea)
                        if ea == idaapi.BADADDR:
                            break
                        continue
                    if any(skip in s_lower for skip in _CREDENTIAL_EXCLUSIONS):
                        ea = idc.next_head(ea)
                        if ea == idaapi.BADADDR:
                            break
                        continue
                    m = assign_re.search(s)
                    if not m and not any(kw in s_lower for kw in _CREDENTIAL_PATTERNS):
                        ea = idc.next_head(ea)
                        if ea == idaapi.BADADDR:
                            break
                        continue
                    if scope_ea is not None:
                        # Check if string is referenced by target function.
                        func_match = False
                        for xref in idautils.XrefsTo(ea, 0):
                            f2 = idaapi.get_func(xref.frm)
                            if f2 and f2.start_ea == scope_ea:
                                func_match = True
                                break
                        if not func_match:
                            ea = idc.next_head(ea)
                            if ea == idaapi.BADADDR:
                                break
                            continue
                    kw = (m.group(1).lower() if m else next((k for k in _CREDENTIAL_PATTERNS if k in s_lower), "credential"))
                    f = _make_finding(
                        ea, "hardcoded_creds",
                        f"Potential hardcoded credential material ({kw}): \"{_clip(s, 80)}\"",
                        _clip(s, 80),
                        include_context=include_context,
                        confidence="high" if m else "medium",
                    )
                    findings.append(f)
                    if len(findings) >= limit * 3:
                        return findings
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break
    return findings


# Scanner dispatch table
_SCANNERS = {
    "buffer_overflow":   _scan_buffer_overflow,
    "format_string":     _scan_format_string,
    "integer_overflow":  _scan_integer_overflow,
    "use_after_free":    _scan_use_after_free,
    "command_injection": _scan_command_injection,
    "race_condition":    _scan_race_condition,
    "null_deref":        _scan_null_deref,
    "info_leak":         _scan_info_leak,
    "auth_bypass":       _scan_auth_bypass,
    "hardcoded_creds":   _scan_hardcoded_creds,
}


@tool
@idaread
def vuln_scan(
    action: Annotated[Literal["buffer_overflow", "format_string", "integer_overflow",
                               "use_after_free", "command_injection", "race_condition",
                               "null_deref", "info_leak", "auth_bypass", "hardcoded_creds",
                               "scan_all", "classify", "osv_query"],
                      "Vulnerability scan action"],
    addr: Annotated[Optional[str], "Address or function to scan (default: all functions)"] = None,
    limit: Annotated[int, "Max results"] = 50,
    offset: Annotated[int, "Result offset (skip first N findings)"] = 0,
    severity: Annotated[Optional[str], "Filter by severity: critical|high|medium|low"] = None,
    include_context: Annotated[bool, "Include decompiled code context"] = False,
    osv_coordinates: Annotated[Optional[list[str]], "OSV package coordinates (ecosystem:name@version or pkg:purl); used by osv_query and optional scan_all enrichment"] = None,
    osv_ecosystem: Annotated[Optional[str], "Default OSV ecosystem for shorthand coords like name@version"] = None,
    osv_endpoint: Annotated[str, "OSV API endpoint/base URL (default: https://api.osv.dev)"] = "https://api.osv.dev",
) -> dict:
    """
    LLM-optimized automated vulnerability scanner for binary analysis.

    Actions:
    - buffer_overflow: Find buffer overflow risks (strcpy, gets, memcpy, etc.) [CWE-120]
    - format_string: Find format string vulns (printf family with non-const fmt) [CWE-134]
    - integer_overflow: Find unchecked arithmetic before alloc/memcpy [CWE-190]
    - use_after_free: Find potential use-after-free patterns [CWE-416]
    - command_injection: Find command injection via system/exec/popen [CWE-78]
    - race_condition: Find TOCTOU and insecure temp file patterns [CWE-362]
    - null_deref: Find missing NULL checks after allocation [CWE-476]
    - info_leak: Find sensitive data in log/output calls [CWE-200]
    - auth_bypass: Find hardcoded auth comparisons [CWE-287]
    - hardcoded_creds: Find hardcoded credentials/keys in strings [CWE-798]
    - scan_all: Run all scans, aggregate by severity
    - classify: Classify a specific address by CWE (requires addr)
    - osv_query: Query OSV for known vulnerable package versions

    Each finding: {addr, function, cwe, severity, type, description, pattern}
    """
    try:
        if severity and severity not in ("critical", "high", "medium", "low"):
            return make_error(MCPError.INVALID_ARGS,
                              "severity must be one of: critical, high, medium, low")
        try:
            limit = int(limit)
        except Exception:
            limit = 50
        if limit <= 0:
            limit = 1
        if limit > 500:
            limit = 500
        try:
            offset = max(0, int(offset))
        except Exception:
            offset = 0

        if action == "osv_query":
            if not osv_coordinates:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "osv_coordinates required (example: ['PyPI:requests@2.28.2'])",
                )

            osv_findings, parsed_queries, parse_errors, osv_error = _scan_osv_coordinates(
                osv_coordinates, osv_endpoint=osv_endpoint, osv_ecosystem=osv_ecosystem
            )
            page, total, truncated = _dedupe_sort_paginate(
                osv_findings, limit=limit, offset=offset, severity=severity
            )
            sev_counts, type_counts = _summary_counts(osv_findings)
            return {
                "ok": True,
                "action": "osv_query",
                "source": "osv",
                "endpoint": _normalize_osv_endpoint(osv_endpoint),
                "queried": parsed_queries,
                "parse_errors": parse_errors,
                "osv_error": osv_error,
                "findings": "\n".join(f["line"] for f in page),
                "items": page,
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": truncated,
                "severity_counts": sev_counts,
                "type_counts": type_counts,
            }

        if action == "classify":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for classify")
            ea, err = validate_addr(addr)
            if err:
                return err

            # Run all scanners against this address, collect matching CWEs
            classifications = []
            func = idaapi.get_func(ea)
            scan_addr = hex_ea(func.start_ea) if func else hex_ea(ea)
            for scan_type, scanner in _SCANNERS.items():
                hits = scanner(scan_addr, max(20, limit), include_context)
                classifications.extend(hits)

            page, total, truncated = _dedupe_sort_paginate(
                classifications, limit=limit, offset=offset, severity=severity
            )
            if not page:
                return {
                    "ok": True,
                    "classifications": "No known vulnerability patterns detected.",
                    "count": 0,
                    "total": total,
                    "offset": offset,
                    "truncated": truncated,
                    "items": [],
                }
            sev_counts, type_counts = _summary_counts(classifications)
            return {
                "ok": True,
                "classifications": "\n".join(f["line"] for f in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": truncated,
                "items": page,
                "severity_counts": sev_counts,
                "type_counts": type_counts,
            }

        if action == "scan_all":
            all_findings = []
            per_scanner_limit = max(64, limit * 2)
            for scan_type, scanner in _SCANNERS.items():
                hits = scanner(addr, per_scanner_limit, include_context)
                all_findings.extend(hits)

            osv_meta = {"queried": [], "parse_errors": [], "osv_error": None}
            if osv_coordinates:
                osv_findings, parsed_queries, parse_errors, osv_error = _scan_osv_coordinates(
                    osv_coordinates, osv_endpoint=osv_endpoint, osv_ecosystem=osv_ecosystem
                )
                all_findings.extend(osv_findings)
                osv_meta = {
                    "queried": parsed_queries,
                    "parse_errors": parse_errors,
                    "osv_error": osv_error,
                }

            page, total, truncated = _dedupe_sort_paginate(
                all_findings, limit=limit, offset=offset, severity=severity
            )
            sev_counts, type_counts = _summary_counts(all_findings)

            return {
                "ok": True,
                "total": total,
                "offset": offset,
                "count": len(page),
                "findings": "\n".join(f["line"] for f in page),
                "truncated": truncated,
                "items": page,
                "severity_counts": sev_counts,
                "type_counts": type_counts,
                "osv": osv_meta,
            }

        # Single scanner action
        scanner = _SCANNERS.get(action)
        if not scanner:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        findings = scanner(addr, max(20, limit * 2), include_context)
        page, total, truncated = _dedupe_sort_paginate(
            findings, limit=limit, offset=offset, severity=severity
        )
        sev_counts, type_counts = _summary_counts(findings)

        return {
            "ok": True,
            "action": action,
            "cwe": _CWE_MAP[action][0],
            "findings": "\n".join(f["line"] for f in page),
            "items": page,
            "count": len(page),
            "total": total,
            "offset": offset,
            "truncated": truncated,
            "severity_counts": sev_counts,
            "type_counts": type_counts,
        }

    except Exception as e:
        return handle_error(e)
