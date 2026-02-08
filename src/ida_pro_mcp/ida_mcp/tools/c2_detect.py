
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re

# ============================================================================
# C2_DETECT - LLM-Optimized C2/Malware Behavior Detection
# ============================================================================

# --- Persistence APIs (registry run keys, services, scheduled tasks, startup) ---
_PERSISTENCE_APIS = [
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyEx", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegOpenKeyEx", "RegOpenKeyExA", "RegOpenKeyExW",
    "CreateService", "CreateServiceA", "CreateServiceW",
    "ChangeServiceConfig", "ChangeServiceConfigA", "ChangeServiceConfigW",
    "StartServiceCtrlDispatcher", "StartServiceCtrlDispatcherA", "StartServiceCtrlDispatcherW",
    "CopyFile", "CopyFileA", "CopyFileW",
    "MoveFile", "MoveFileA", "MoveFileW",
    "SHGetFolderPath", "SHGetFolderPathA", "SHGetFolderPathW",
    "SHGetSpecialFolderPath", "SHGetSpecialFolderPathA", "SHGetSpecialFolderPathW",
    "GetStartupInfo", "GetStartupInfoA", "GetStartupInfoW",
]

_PERSISTENCE_STRINGS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"CurrentVersion\Explorer\Shell Folders",
    "schtasks", "at.exe", "Startup",
    "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
    "HKLM", "HKCU",
]

# --- Evasion / anti-analysis APIs ---
_EVASION_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtQuerySystemInformation",
    "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter",
    "NtSetInformationThread",
    "NtClose",
    "CloseHandle",
    "GetSystemInfo",
    "GlobalMemoryStatusEx",
    "EnumProcesses",
    "CreateToolhelp32Snapshot",
    "Process32First", "Process32FirstW",
    "Process32Next", "Process32NextW",
    "FindWindow", "FindWindowA", "FindWindowW",
    "GetModuleHandle", "GetModuleHandleA", "GetModuleHandleW",
    "SleepEx", "Sleep",
    "WaitForSingleObject",
]

_EVASION_STRINGS = [
    "vmware", "VMWARE", "VMware",
    "VBOX", "VBox", "vbox", "VirtualBox",
    "qemu", "QEMU",
    "Xen",
    "SbieDll", "sbiedll",
    "wine_get_unix_file_name",
    "OllyDbg", "ollydbg",
    "x64dbg", "x32dbg",
    "IDA", "Ida",
    "Wireshark", "wireshark",
    "Procmon", "procmon",
    "ProcessHacker",
    "Fiddler", "fiddler",
    "int 2dh", "int 3",
    "cpuid",
    "\\\\HARDWARE\\DESCRIPTION\\System",
    "HARDWARE\\DEVICEMAP\\Scsi",
    "SystemBiosVersion",
]

# --- Process injection APIs ---
_INJECTION_APIS = [
    "VirtualAllocEx",
    "VirtualAlloc",
    "NtAllocateVirtualMemory",
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtSetContextThread",
    "NtUnmapViewOfSection",
    "NtMapViewOfSection",
    "OpenProcess",
    "NtOpenProcess",
    "SuspendThread",
    "ResumeThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "CreateFileMappingA", "CreateFileMappingW",
    "MapViewOfFile",
]

# --- Exfiltration APIs ---
_EXFILTRATION_APIS = [
    "send", "sendto", "WSASend",
    "InternetOpen", "InternetOpenA", "InternetOpenW",
    "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
    "InternetConnect", "InternetConnectA", "InternetConnectW",
    "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "ReadFile",
    "CreateFile", "CreateFileA", "CreateFileW",
    "FindFirstFile", "FindFirstFileA", "FindFirstFileW",
    "FindNextFile", "FindNextFileA", "FindNextFileW",
    "GetClipboardData",
    "OpenClipboard",
    "CryptEncrypt",
    "CryptDecrypt",
]

# --- Lateral movement APIs ---
_LATERAL_MOVEMENT_APIS = [
    "WNetAddConnection2", "WNetAddConnection2A", "WNetAddConnection2W",
    "WNetUseConnection", "WNetUseConnectionA", "WNetUseConnectionW",
    "NetShareEnum",
    "NetUserEnum",
    "NetSessionEnum",
    "NetScheduleJobAdd",
    "CreateService", "CreateServiceA", "CreateServiceW",
    "OpenSCManager", "OpenSCManagerA", "OpenSCManagerW",
    "StartService", "StartServiceA", "StartServiceW",
    "WinExec",
    "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
]

_LATERAL_MOVEMENT_STRINGS = [
    "psexec", "PsExec", "PSEXESVC",
    "\\\\pipe\\",
    "IPC$", "ADMIN$", "C$",
    "\\\\\\\\",
    "wmic", "WMIC",
    "winrm", "WinRM",
    "smbclient",
    "net use", "net share",
    "mstsc", "rdp",
    "3389", "445", "135",
]

# --- Privilege escalation APIs ---
_PRIV_ESC_APIS = [
    "AdjustTokenPrivileges",
    "LookupPrivilegeValue", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "OpenProcessToken",
    "DuplicateTokenEx",
    "ImpersonateLoggedOnUser",
    "SetTokenInformation",
    "CreateProcessAsUser", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW",
    "CreateProcessWithTokenW",
    "NtSetInformationToken",
    "RtlAdjustPrivilege",
    "LdrLoadDll",
    "SetSecurityDescriptorDacl",
    "AddAccessAllowedAce",
]

_PRIV_ESC_STRINGS = [
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeImpersonatePrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "NT AUTHORITY\\SYSTEM",
]

# --- IOC regex patterns ---
_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_URL = re.compile(
    r'https?://[^\s\x00"\'<>\]\)]{4,}'
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|info|biz|io|cc|ru|cn|top|xyz|tk|ml|ga|cf|gq|pw|onion)\b'
)
_RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_REGISTRY = re.compile(
    r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\x00"\']{4,}'
)
_RE_MUTEX = re.compile(
    r'(?:Global\\|Local\\)[^\s\x00"\']{2,}'
)
_RE_EMAIL = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)
_RE_BITCOIN = re.compile(
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
)

# --- Capability categories for comprehensive assessment ---
_CAPABILITY_GROUPS = {
    "networking": [
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "WSAStartup", "WSASocket", "WSASocketA", "WSASocketW",
        "InternetOpen", "InternetOpenA", "InternetOpenW",
        "WinHttpOpen", "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
        "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
        "getaddrinfo", "gethostbyname",
    ],
    "file_system": [
        "CreateFile", "CreateFileA", "CreateFileW",
        "ReadFile", "WriteFile",
        "DeleteFile", "DeleteFileA", "DeleteFileW",
        "FindFirstFile", "FindFirstFileA", "FindFirstFileW",
        "CopyFile", "CopyFileA", "CopyFileW",
        "MoveFile", "MoveFileA", "MoveFileW",
        "GetTempPath", "GetTempPathA", "GetTempPathW",
        "fopen", "fread", "fwrite", "fclose",
        "open", "read", "write", "close",
    ],
    "process_control": [
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "OpenProcess",
        "TerminateProcess",
        "CreateThread",
        "CreateRemoteThread",
        "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "WinExec",
        "system", "popen", "execv", "execve",
        "fork", "execl", "execlp",
    ],
    "registry": [
        "RegOpenKeyEx", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
        "RegQueryValueEx", "RegQueryValueExA", "RegQueryValueExW",
        "RegCreateKeyEx", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegDeleteKey", "RegDeleteKeyA", "RegDeleteKeyW",
        "RegDeleteValue", "RegDeleteValueA", "RegDeleteValueW",
    ],
    "crypto": [
        "CryptAcquireContext", "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptEncrypt", "CryptDecrypt",
        "CryptCreateHash", "CryptHashData",
        "CryptGenKey", "CryptDeriveKey",
        "CryptImportKey", "CryptExportKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptEncrypt", "BCryptDecrypt",
    ],
    "info_gathering": [
        "GetComputerName", "GetComputerNameA", "GetComputerNameW",
        "GetUserName", "GetUserNameA", "GetUserNameW",
        "GetSystemInfo",
        "GetVersionEx", "GetVersionExA", "GetVersionExW",
        "GetAdaptersInfo",
        "GetCurrentProcess", "GetCurrentProcessId",
        "gethostname", "getenv",
        "GetEnvironmentVariable", "GetEnvironmentVariableA", "GetEnvironmentVariableW",
        "GetSystemDirectory", "GetSystemDirectoryA", "GetSystemDirectoryW",
        "GetWindowsDirectory", "GetWindowsDirectoryA", "GetWindowsDirectoryW",
    ],
    "persistence": [
        "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
        "CreateService", "CreateServiceA", "CreateServiceW",
        "CopyFile", "CopyFileA", "CopyFileW",
    ],
    "defense_evasion": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "VirtualProtect", "VirtualProtectEx",
        "NtSetInformationThread",
    ],
    "injection": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    ],
    "keylogging": [
        "GetAsyncKeyState",
        "GetKeyState",
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "GetForegroundWindow",
        "GetWindowText", "GetWindowTextA", "GetWindowTextW",
    ],
    "screenshot": [
        "BitBlt",
        "GetDC",
        "CreateCompatibleDC",
        "CreateCompatibleBitmap",
        "GetDIBits",
    ],
}


# ============================================================================
# Helper functions
# ============================================================================

def _get_func_name_safe(ea):
    """Get function name for an address, or 'unknown'."""
    func = idaapi.get_func(ea)
    if func:
        return ida_funcs.get_func_name(func.start_ea)
    return "unknown"


def _find_api_xrefs(name, limit):
    """Find code xrefs to a named symbol, returning list of caller EAs."""
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


def _make_finding(ea, category, description, api_or_pattern="", include_context=False):
    """Build a standardised finding dict."""
    f = {
        "addr": hex_ea(ea),
        "function": _get_func_name_safe(ea),
        "category": category,
        "description": description,
        "indicator": api_or_pattern,
    }
    if include_context:
        try:
            disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            f["context"] = disasm
        except Exception:
            pass
    return f


def _scan_api_list(api_list, category, addr, limit, include_context, desc_fmt=None):
    """Scan for xrefs to a list of APIs within an optional target function."""
    findings = []
    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return findings
        target_ea = resolved

    for api in api_list:
        if len(findings) >= limit:
            break
        refs = _find_api_xrefs(api, limit - len(findings))
        for call_ea in refs:
            if target_ea is not None:
                func = idaapi.get_func(call_ea)
                if not func or func.start_ea != target_ea:
                    continue
            desc = (desc_fmt or "Call to {api}()").format(api=api)
            findings.append(_make_finding(call_ea, category, desc, api, include_context))
            if len(findings) >= limit:
                break
    return findings


def _scan_strings_for_patterns(patterns, category, addr, limit, include_context,
                               desc_fmt=None):
    """Scan all defined strings for substring matches."""
    findings = []
    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return findings
        target_ea = resolved

    patterns_lower = [p.lower() for p in patterns]

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
                    for pat in patterns_lower:
                        if pat in s_lower:
                            if target_ea is not None:
                                func_match = False
                                for xref in idautils.XrefsTo(ea, 0):
                                    f = idaapi.get_func(xref.frm)
                                    if f and f.start_ea == target_ea:
                                        func_match = True
                                        break
                                if not func_match:
                                    continue
                            desc = (desc_fmt or "String match: \"{s}\"").format(
                                s=s[:80], pat=pat)
                            findings.append(
                                _make_finding(ea, category, desc, s[:60], include_context))
                            break
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break
    return findings


def _collect_all_strings():
    """Collect all defined strings from the IDB."""
    strings = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_strlit(flags):
                contents = idc.get_strlit_contents(ea)
                if contents:
                    try:
                        s = contents.decode("utf-8", errors="ignore")
                    except Exception:
                        s = str(contents)
                    if len(s) >= 4:
                        strings.append((ea, s))
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break
    return strings


# ============================================================================
# Action implementations
# ============================================================================

def _action_indicators(addr, limit, include_context):
    """Find all potential C2 indicators (URLs, IPs, domains, registry keys, mutexes)."""
    findings = []
    all_strings = _collect_all_strings()

    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return findings
        target_ea = resolved

    checks = [
        (_RE_URL,      "url",      "URL found: \"{s}\""),
        (_RE_IPV4,     "ip",       "IP address found: \"{s}\""),
        (_RE_DOMAIN,   "domain",   "Domain found: \"{s}\""),
        (_RE_REGISTRY, "registry", "Registry path: \"{s}\""),
        (_RE_MUTEX,    "mutex",    "Mutex name: \"{s}\""),
        (_RE_EMAIL,    "email",    "Email address: \"{s}\""),
        (_RE_BITCOIN,  "bitcoin",  "Bitcoin address: \"{s}\""),
    ]

    for ea, s in all_strings:
        if len(findings) >= limit:
            break
        if target_ea is not None:
            func_match = False
            for xref in idautils.XrefsTo(ea, 0):
                f = idaapi.get_func(xref.frm)
                if f and f.start_ea == target_ea:
                    func_match = True
                    break
            if not func_match:
                continue
        for regex, ioc_type, desc_fmt in checks:
            m = regex.search(s)
            if m:
                desc = desc_fmt.format(s=s[:80])
                finding = _make_finding(ea, "c2_indicator", desc, m.group()[:60],
                                        include_context)
                finding["ioc_type"] = ioc_type
                findings.append(finding)
                break

    return findings


def _action_persistence(addr, limit, include_context):
    """Find persistence mechanisms."""
    api_hits = _scan_api_list(
        _PERSISTENCE_APIS, "persistence", addr, limit, include_context,
        desc_fmt="Persistence API: {api}()")
    remaining = limit - len(api_hits)
    str_hits = []
    if remaining > 0:
        str_hits = _scan_strings_for_patterns(
            _PERSISTENCE_STRINGS, "persistence", addr, remaining, include_context,
            desc_fmt="Persistence indicator: \"{s}\"")
    return api_hits + str_hits


def _action_evasion(addr, limit, include_context):
    """Find evasion/anti-analysis techniques."""
    api_hits = _scan_api_list(
        _EVASION_APIS, "evasion", addr, limit, include_context,
        desc_fmt="Anti-analysis API: {api}()")
    remaining = limit - len(api_hits)
    str_hits = []
    if remaining > 0:
        str_hits = _scan_strings_for_patterns(
            _EVASION_STRINGS, "evasion", addr, remaining, include_context,
            desc_fmt="Anti-analysis string: \"{s}\"")
    return api_hits + str_hits


def _action_injection(addr, limit, include_context):
    """Find process injection techniques."""
    return _scan_api_list(
        _INJECTION_APIS, "injection", addr, limit, include_context,
        desc_fmt="Injection API: {api}()")


def _action_exfiltration(addr, limit, include_context):
    """Find data exfiltration patterns (file read + network send)."""
    return _scan_api_list(
        _EXFILTRATION_APIS, "exfiltration", addr, limit, include_context,
        desc_fmt="Exfiltration-related API: {api}()")


def _action_lateral_movement(addr, limit, include_context):
    """Find lateral movement techniques."""
    api_hits = _scan_api_list(
        _LATERAL_MOVEMENT_APIS, "lateral_movement", addr, limit, include_context,
        desc_fmt="Lateral movement API: {api}()")
    remaining = limit - len(api_hits)
    str_hits = []
    if remaining > 0:
        str_hits = _scan_strings_for_patterns(
            _LATERAL_MOVEMENT_STRINGS, "lateral_movement", addr, remaining,
            include_context, desc_fmt="Lateral movement indicator: \"{s}\"")
    return api_hits + str_hits


def _action_privilege_escalation(addr, limit, include_context):
    """Find privilege escalation attempts."""
    api_hits = _scan_api_list(
        _PRIV_ESC_APIS, "privilege_escalation", addr, limit, include_context,
        desc_fmt="Privilege escalation API: {api}()")
    remaining = limit - len(api_hits)
    str_hits = []
    if remaining > 0:
        str_hits = _scan_strings_for_patterns(
            _PRIV_ESC_STRINGS, "privilege_escalation", addr, remaining,
            include_context, desc_fmt="Privilege token: \"{s}\"")
    return api_hits + str_hits


def _action_capabilities(addr, limit, include_context):
    """Comprehensive capability assessment."""
    capabilities = {}
    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return capabilities
        target_ea = resolved

    for cap_name, api_list in _CAPABILITY_GROUPS.items():
        found_apis = []
        for api in api_list:
            refs = _find_api_xrefs(api, 5)
            for call_ea in refs:
                if target_ea is not None:
                    func = idaapi.get_func(call_ea)
                    if not func or func.start_ea != target_ea:
                        continue
                if api not in found_apis:
                    found_apis.append(api)
                break
        if found_apis:
            capabilities[cap_name] = found_apis

    return capabilities


def _action_config_extract(addr, limit, include_context):
    """Find embedded configuration data (encrypted blocks, XOR'd data near C2 strings)."""
    findings = []
    all_strings = _collect_all_strings()

    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return findings
        target_ea = resolved

    # Look for strings near XOR / encryption patterns
    c2_indicators = []
    for ea, s in all_strings:
        if _RE_URL.search(s) or _RE_IPV4.search(s) or _RE_DOMAIN.search(s):
            c2_indicators.append((ea, s))

    # Find XOR loops and crypto constants near C2 strings
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(findings) < limit:
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                # Check for high-entropy data blocks (potential encrypted config)
                block_size = 0
                check_ea = ea
                non_zero = 0
                while check_ea < seg.end_ea and block_size < 256:
                    b = ida_bytes.get_byte(check_ea)
                    if b != 0:
                        non_zero += 1
                    block_size += 1
                    check_ea += 1
                if block_size >= 32 and non_zero > block_size * 0.7:
                    # Check if any C2 string references this area
                    has_c2_nearby = False
                    for xref in idautils.XrefsTo(ea, 0):
                        if xref.iscode:
                            # Check if the referencing function also refs a C2 string
                            func = idaapi.get_func(xref.frm)
                            if func:
                                if target_ea is not None and func.start_ea != target_ea:
                                    continue
                                for item in idautils.FuncItems(func.start_ea):
                                    mnem = idc.print_insn_mnem(item)
                                    if mnem and mnem.lower() == "xor":
                                        has_c2_nearby = True
                                        break
                    if has_c2_nearby:
                        findings.append(_make_finding(
                            ea, "config_data",
                            f"Potential encrypted config block ({block_size} bytes) "
                            f"referenced by XOR loop",
                            f"data_block_{block_size}B", include_context))
            ea = idc.next_head(ea)
            if ea == idaapi.BADADDR:
                break

    # Also scan for XOR decryption routines
    xor_funcs = []
    for func_ea in idautils.Functions():
        if len(findings) >= limit:
            break
        if target_ea is not None and func_ea != target_ea:
            continue
        xor_count = 0
        loop_count = 0
        for item in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(item)
            if not mnem:
                continue
            m = mnem.lower()
            if m == "xor":
                op0 = idc.print_operand(item, 0)
                op1 = idc.print_operand(item, 1)
                if op0 != op1:
                    xor_count += 1
            elif m in ("loop", "jnz", "jne", "dec"):
                loop_count += 1
        if xor_count >= 1 and loop_count >= 1:
            findings.append(_make_finding(
                func_ea, "config_data",
                f"Potential XOR decryption routine "
                f"(xor_ops={xor_count}, loop_indicators={loop_count})",
                _get_func_name_safe(func_ea), include_context))

    return findings


def _action_ioc_extract(addr, limit, include_context):
    """Extract all IOCs in structured format."""
    all_strings = _collect_all_strings()
    iocs = {
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "registry_keys": [],
        "mutexes": [],
        "bitcoin_addrs": [],
        "md5_hashes": [],
        "sha1_hashes": [],
        "sha256_hashes": [],
    }

    target_ea = None
    if addr is not None:
        resolved, err = validate_addr(addr, require_func=True)
        if err:
            return iocs
        target_ea = resolved

    total = 0
    seen = set()
    for ea, s in all_strings:
        if total >= limit:
            break
        if target_ea is not None:
            func_match = False
            for xref in idautils.XrefsTo(ea, 0):
                f = idaapi.get_func(xref.frm)
                if f and f.start_ea == target_ea:
                    func_match = True
                    break
            if not func_match:
                continue

        extractions = [
            (_RE_URL,      "urls"),
            (_RE_IPV4,     "ips"),
            (_RE_DOMAIN,   "domains"),
            (_RE_EMAIL,    "emails"),
            (_RE_REGISTRY, "registry_keys"),
            (_RE_MUTEX,    "mutexes"),
            (_RE_BITCOIN,  "bitcoin_addrs"),
            (_RE_SHA256,   "sha256_hashes"),
            (_RE_SHA1,     "sha1_hashes"),
            (_RE_MD5,      "md5_hashes"),
        ]

        for regex, key in extractions:
            for m in regex.finditer(s):
                val = m.group()
                if val in seen:
                    continue
                seen.add(val)
                entry = {"value": val, "addr": hex_ea(ea)}
                if include_context:
                    entry["string"] = s[:120]
                iocs[key].append(entry)
                total += 1
                if total >= limit:
                    break
            if total >= limit:
                break

    return iocs


# ============================================================================
# Action dispatch
# ============================================================================

_ACTIONS = {
    "indicators":           _action_indicators,
    "persistence":          _action_persistence,
    "evasion":              _action_evasion,
    "injection":            _action_injection,
    "exfiltration":         _action_exfiltration,
    "lateral_movement":     _action_lateral_movement,
    "privilege_escalation": _action_privilege_escalation,
    "config_extract":       _action_config_extract,
}


@tool
@idaread
def c2_detect(
    action: Annotated[Literal["indicators", "persistence", "evasion", "injection",
                               "exfiltration", "lateral_movement",
                               "privilege_escalation", "capabilities",
                               "config_extract", "ioc_extract"],
                      "C2/malware detection action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    include_context: Annotated[bool, "Include code context"] = False,
) -> dict:
    """
    LLM-optimized C2/malware behavior detection for binary analysis.

    Actions:
    - indicators: Find all potential C2 indicators (URLs, IPs, domains, registry keys, mutexes)
    - persistence: Find persistence mechanisms (registry run keys, services, scheduled tasks)
    - evasion: Find evasion/anti-analysis techniques (anti-debug, anti-VM, sandbox detection)
    - injection: Find process injection techniques (VirtualAllocEx, WriteProcessMemory, etc.)
    - exfiltration: Find data exfiltration patterns (file reading + network sending)
    - lateral_movement: Find lateral movement techniques (WMI, PSExec, SMB, RDP patterns)
    - privilege_escalation: Find privilege escalation attempts (token manipulation)
    - capabilities: Comprehensive capability assessment (what can this malware do?)
    - config_extract: Find embedded configuration data (encrypted blocks, XOR'd data)
    - ioc_extract: Extract all IOCs (indicators of compromise) in structured format

    Architecture-neutral: works on ARM and x86 binaries.
    Each finding: {addr, function, category, description, indicator}
    """
    try:
        if action == "capabilities":
            caps = _action_capabilities(addr, limit, include_context)
            active = [name for name, apis in caps.items() if apis]
            return {
                "ok": True,
                "action": "capabilities",
                "capabilities": caps,
                "active_capabilities": active,
                "total_categories": len(active),
            }

        if action == "ioc_extract":
            iocs = _action_ioc_extract(addr, limit, include_context)
            total = sum(len(v) for v in iocs.values())
            return {
                "ok": True,
                "action": "ioc_extract",
                "iocs": iocs,
                "total": total,
            }

        handler = _ACTIONS.get(action)
        if not handler:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        findings = handler(addr, limit, include_context)
        return {
            "ok": True,
            "action": action,
            "findings": findings[:limit],
            "count": len(findings),
            "truncated": len(findings) >= limit,
        }

    except Exception as e:
        return handle_error(e)
