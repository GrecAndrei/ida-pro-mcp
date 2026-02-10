
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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


def _find_xrefs_to_name(name, limit):
    """Find code xrefs to a named symbol."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        return []
    refs = []
    for xref in idautils.XrefsTo(ea, 0):
        if xref.iscode:
            refs.append(xref.frm)
            if len(refs) >= limit:
                break
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


def _make_finding(ea, vuln_type, desc, pattern=""):
    """Build a compact one-line finding string."""
    cwe_id, severity, cwe_desc = _CWE_MAP.get(vuln_type, ("CWE-0", "low", vuln_type))
    func_name = _get_func_name_safe(ea)
    return f"{hex_ea(ea)}  [{severity}] {cwe_id} {func_name}: {desc}"


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
    findings = []
    for dangerous in _BUFFER_OVERFLOW_FUNCS:
        refs = _find_xrefs_to_name(dangerous, limit - len(findings))
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
                    continue
            f = _make_finding(
                call_ea, "buffer_overflow",
                f"Call to {dangerous}() without bounds checking",
                dangerous,
            )
            findings.append(f)
            if len(findings) >= limit:
                return findings
    return findings


def _scan_format_string(addr, limit, include_context):
    """Scan for format string vulnerabilities."""
    findings = []
    for dangerous in _FORMAT_STRING_FUNCS:
        refs = _find_xrefs_to_name(dangerous, limit - len(findings))
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
                    continue
            # Heuristic: check if format arg is a register (non-const)
            disasm = idc.generate_disasm_line(call_ea, 0)
            is_suspicious = True
            # Check previous instruction for lea with string literal
            prev = idc.prev_head(call_ea)
            if prev != idaapi.BADADDR:
                for xref in idautils.XrefsFrom(prev, 0):
                    if ida_bytes.is_strlit(ida_bytes.get_flags(xref.to)):
                        is_suspicious = False
                        break
            if is_suspicious:
                f = _make_finding(
                    call_ea, "format_string",
                    f"Call to {dangerous}() with potentially non-constant format string",
                    dangerous,
                )
                findings.append(f)
                if len(findings) >= limit:
                    return findings
    return findings


def _scan_integer_overflow(addr, limit, include_context):
    """Scan for integer overflow before allocation/memcpy patterns."""
    findings = []
    alloc_names = _ALLOC_FUNCS + ["memcpy", "memmove"]
    for alloc in alloc_names:
        refs = _find_xrefs_to_name(alloc, limit * 4)
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
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
                    )
                    findings.append(f)
                    if len(findings) >= limit:
                        return findings
                    break
    return findings


def _scan_use_after_free(addr, limit, include_context):
    """Scan for use-after-free patterns (free followed by pointer use)."""
    findings = []
    for free_func in _UAF_FREE_FUNCS:
        refs = _find_xrefs_to_name(free_func, limit * 4)
        for free_ea in refs:
            func = idaapi.get_func(free_ea)
            if not func:
                continue
            if addr is not None:
                ea_check, _ = validate_addr(addr, require_func=True)
                if func.start_ea != ea_check:
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
                # Skip if we hit another call to free or a return
                if mnem.lower() in RETURN_MNEMONICS or mnem.lower() in UNCONDITIONAL_JUMP_MNEMONICS:
                    break
                # Look for dereference patterns after free
                disasm = ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))
                if "[" in disasm and mnem.lower() not in ("lea", "push"):
                    f = _make_finding(
                        curr, "use_after_free",
                        f"Potential use after {free_func}() at {hex_ea(free_ea)}",
                        f"{free_func} -> {disasm.strip()}",
                    )
                    findings.append(f)
                    if len(findings) >= limit:
                        return findings
                    break
    return findings


def _scan_command_injection(addr, limit, include_context):
    """Scan for command injection vulnerabilities."""
    findings = []
    for dangerous in _COMMAND_INJECTION_FUNCS:
        refs = _find_xrefs_to_name(dangerous, limit - len(findings))
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
                    continue
            f = _make_finding(
                call_ea, "command_injection",
                f"Call to {dangerous}() - verify input is not user-controlled",
                dangerous,
            )
            findings.append(f)
            if len(findings) >= limit:
                return findings
    return findings


def _scan_race_condition(addr, limit, include_context):
    """Scan for TOCTOU and race condition patterns."""
    findings = []
    check_funcs = {"access", "stat", "lstat", "fstat"}
    use_funcs = {"open", "fopen", "chmod", "chown", "rename",
                 "unlink", "remove", "CreateFile", "CreateFileA", "CreateFileW"}

    for check in check_funcs:
        check_refs = _find_xrefs_to_name(check, limit * 4)
        for check_ea in check_refs:
            func = idaapi.get_func(check_ea)
            if not func:
                continue
            if addr is not None:
                ea_check, _ = validate_addr(addr, require_func=True)
                if func.start_ea != ea_check:
                    continue
            # Look for a file use operation in the same function after the check
            for item in idautils.FuncItems(func.start_ea):
                if item <= check_ea:
                    continue
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                        name = idc.get_name(xref.to)
                        if name and any(_matches_win_api_variant(name, u)
                                        for u in use_funcs):
                            f = _make_finding(
                                check_ea, "race_condition",
                                f"TOCTOU: {check}() at {hex_ea(check_ea)} then {name}() at {hex_ea(item)}",
                                f"{check} -> {name}",
                            )
                            findings.append(f)
                            if len(findings) >= limit:
                                return findings
    # Also flag tmpnam/mktemp usage directly
    for risky in ("tmpnam", "tempnam", "mktemp"):
        refs = _find_xrefs_to_name(risky, limit - len(findings))
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
                    continue
            f = _make_finding(
                call_ea, "race_condition",
                f"Insecure temp file creation via {risky}()",
                risky,
            )
            findings.append(f)
            if len(findings) >= limit:
                return findings
    return findings


def _scan_null_deref(addr, limit, include_context):
    """Scan for potential null pointer dereference (alloc without null check)."""
    findings = []
    for alloc in _ALLOC_FUNCS:
        refs = _find_xrefs_to_name(alloc, limit * 4)
        for call_ea in refs:
            func = idaapi.get_func(call_ea)
            if not func:
                continue
            if addr is not None:
                ea_check, _ = validate_addr(addr, require_func=True)
                if func.start_ea != ea_check:
                    continue
            # Heuristic: check if next few instructions include a null test
            curr = call_ea
            has_null_check = False
            for _ in range(6):
                curr = idc.next_head(curr)
                if curr == idaapi.BADADDR or curr >= func.end_ea:
                    break
                mnem = idc.print_insn_mnem(curr)
                if mnem and (mnem.lower() in COMPARISON_MNEMONICS or
                            mnem.lower() in CONDITIONAL_BRANCH_MNEMONICS):
                    has_null_check = True
                    break
                if mnem and (mnem.lower() in CALL_MNEMONICS or
                             mnem.lower() in RETURN_MNEMONICS):
                    break
            if not has_null_check:
                f = _make_finding(
                    call_ea, "null_deref",
                    f"Return value of {alloc}() used without NULL check",
                    alloc,
                )
                findings.append(f)
                if len(findings) >= limit:
                    return findings
    return findings


def _scan_info_leak(addr, limit, include_context):
    """Scan for information disclosure patterns."""
    findings = []
    sensitive_strs = ["password", "secret", "token", "key", "cookie",
                      "session", "credit", "ssn", "cvv"]

    for log_func in _INFO_LEAK_FUNCS:
        refs = _find_xrefs_to_name(log_func, limit * 4)
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
                    continue
            # Check if any nearby string references contain sensitive keywords
            for i in range(5):
                prev = idc.prev_head(call_ea) if i == 0 else idc.prev_head(prev)
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
                            )
                            findings.append(f)
                            if len(findings) >= limit:
                                return findings
    return findings


def _scan_auth_bypass(addr, limit, include_context):
    """Scan for authentication bypass patterns (compare with constants)."""
    findings = []
    for cmp_func in _AUTH_FUNCS:
        refs = _find_xrefs_to_name(cmp_func, limit * 4)
        for call_ea in refs:
            if addr is not None:
                func = idaapi.get_func(call_ea)
                ea_check, _ = validate_addr(addr, require_func=True)
                if not func or func.start_ea != ea_check:
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
                            )
                            findings.append(f)
                            if len(findings) >= limit:
                                return findings
    return findings


def _scan_hardcoded_creds(addr, limit, include_context):
    """Scan for hardcoded credentials and keys in strings."""
    findings = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(findings) < limit:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_strlit(flags):
                contents = idc.get_strlit_contents(ea)
                if contents:
                    try:
                        s = contents.decode("utf-8", errors="ignore")
                    except Exception:
                        s = str(contents)
                    s_lower = s.lower()
                    for kw in _CREDENTIAL_PATTERNS:
                        if kw in s_lower and len(s) > len(kw) + 2:
                            # Filter out obvious non-credentials
                            if any(skip in s_lower for skip in
                                   _CREDENTIAL_EXCLUSIONS):
                                break
                            if addr is not None:
                                # Check if string is referenced by target func
                                func_match = False
                                ea_check, _ = validate_addr(addr, require_func=True)
                                for xref in idautils.XrefsTo(ea, 0):
                                    f2 = idaapi.get_func(xref.frm)
                                    if f2 and f2.start_ea == ea_check:
                                        func_match = True
                                        break
                                if not func_match:
                                    break
                            f = _make_finding(
                                ea, "hardcoded_creds",
                                f"String contains potential credential keyword '{kw}': \"{s[:80]}\"",
                                s[:60],
                            )
                            findings.append(f)
                            break
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
                               "scan_all", "classify"],
                      "Vulnerability scan action"],
    addr: Annotated[Optional[str], "Address or function to scan (default: all functions)"] = None,
    limit: Annotated[int, "Max results"] = 50,
    severity: Annotated[Optional[str], "Filter by severity: critical|high|medium|low"] = None,
    include_context: Annotated[bool, "Include decompiled code context"] = False,
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

    Each finding: {addr, function, cwe, severity, type, description, pattern}
    """
    try:
        if severity and severity not in ("critical", "high", "medium", "low"):
            return make_error(MCPError.INVALID_ARGS,
                              "severity must be one of: critical, high, medium, low")

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
                hits = scanner(scan_addr, 10, include_context)
                classifications.extend(hits)

            if not classifications:
                return {"ok": True, "classifications": "No known vulnerability patterns detected.", "count": 0}
            return {"ok": True, "classifications": "\n".join(classifications), "count": len(classifications)}

        if action == "scan_all":
            all_findings = []
            per_scanner_limit = max(1, limit // len(_SCANNERS))
            for scan_type, scanner in _SCANNERS.items():
                hits = scanner(addr, per_scanner_limit, include_context)
                all_findings.extend(hits)

            if severity:
                tag = f"[{severity}]"
                all_findings = [f for f in all_findings if tag in f]

            return {
                "ok": True,
                "total": len(all_findings),
                "findings": "\n".join(all_findings[:limit]),
                "truncated": len(all_findings) > limit,
            }

        # Single scanner action
        scanner = _SCANNERS.get(action)
        if not scanner:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        findings = scanner(addr, limit, include_context)

        if severity:
            tag = f"[{severity}]"
            findings = [f for f in findings if tag in f]

        return {
            "ok": True,
            "action": action,
            "cwe": _CWE_MAP[action][0],
            "findings": "\n".join(findings[:limit]),
            "count": len(findings),
        }

    except Exception as e:
        return handle_error(e)
