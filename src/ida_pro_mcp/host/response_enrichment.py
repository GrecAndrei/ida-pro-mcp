"""
Response Enrichment — minimal version.

Original 339-line implementation had:
  - `patch_addresses`: keep (legitimate — resolves rip-relative in pseudocode)
  - `digest_decompiled`: keep core (api_calls, patterns, security_notes, behavior_tags)
    - dropped `density` (made-up formula)
    - dropped `severity` (useless count-based heuristic)
  - GHOST_CHAINS: dropped (folded callers/callees/strings into code:decompile response
    directly by the IDA-side tool; the runtime ghost-chain was emitting 7 phases
    of recursive tool calls per decompile)
  - auto_blackboard_write: dropped (silent side effects + canned hypotheses)
"""
from __future__ import annotations

import re
from typing import Any

# ============================================================================
# Address Patching
# ============================================================================

# Matches common base+offset patterns in x86/x64 assembly/disassembly
_BASE_OFFSET_RE = re.compile(
    r'(rip|rsp|rbp|rsi|rdi|r[89]|r1[0-5]|gs|fs|cs|ds)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)',
    re.IGNORECASE,
)
# Matches direct address references in pseudocode
_DIRECT_ADDR_RE = re.compile(
    r'&\w+\s*\[\s*(0x[0-9a-fA-F]+)\s*\]|address\s+(0x[0-9a-fA-F]+)|\bat\s+(0x[0-9a-fA-F]+)',
    re.IGNORECASE,
)
# Matches string assignments that reveal address info
_STRING_ADDR_RE = re.compile(
    r'"([^"]*)"\s*(?:@|at|located at|stored at|address)\s*(0x[0-9a-fA-F]+)',
    re.IGNORECASE,
)
# Matches load effective address patterns in x86
_LEA_RE = re.compile(
    r'lea\s+(\w+)\s*,\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+)\]',
    re.IGNORECASE,
)
# Matches mov with displacement
_MOV_DISP_RE = re.compile(
    r'mov\s+(\w+)\s*,\s*(?:qword|dword|word|byte)\s+ptr\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+)\]',
    re.IGNORECASE,
)


def patch_addresses(text: str, base_registers: dict[str, int] | None = None) -> str:
    """Annotate rip-relative / base+offset expressions in disassembly or pseudocode.

    For each match, append a `; -> 0xNNN` comment with the resolved address.
    This is purely additive — original text is preserved.
    """
    if not text or not isinstance(text, str):
        return text

    base_registers = base_registers or {}
    lines = text.split("\n")
    patched_lines = []

    for line in lines:
        # rip-relative LEA
        for match in _LEA_RE.finditer(line):
            base = match.group(2)
            op = match.group(3)
            try:
                offset = int(match.group(4), 16)
            except ValueError:
                continue
            if base in base_registers:
                base_val = base_registers[base]
                abs_addr = base_val + (offset if op == "+" else -offset)
                line = line.replace(match.group(0), f"{match.group(0)}  ; -> {hex(abs_addr)}")

        # Generic base+offset
        if "rip" in line.lower() or "base+" in line.lower():
            for match in _BASE_OFFSET_RE.finditer(line):
                base_name = match.group(1)
                offset_str = match.group(3)
                try:
                    from .intelligence.helpers import coerce_int
                    offset = coerce_int(offset_str)
                except (ValueError, ImportError):
                    continue
                if base_name in base_registers:
                    base_val = base_registers[base_name]
                    resolved = hex(base_val + offset)
                    if "; ->" not in line:
                        line = f"{line}  ; {match.group(0)} -> {resolved}"

        patched_lines.append(line)

    return "\n".join(patched_lines)


# ============================================================================
# Decompile Auto-Digest (core only)
# ============================================================================

# Common Windows API patterns
_WIN32_API_PATTERN = re.compile(
    r'\b(CreateFile|ReadFile|WriteFile|CloseHandle|VirtualAlloc|VirtualFree|'
    r'VirtualProtect|CreateProcess|OpenProcess|TerminateProcess|'
    r'CreateThread|CreateRemoteThread|LoadLibrary|GetProcAddress|'
    r'HeapAlloc|HeapFree|HeapCreate|malloc|free|calloc|realloc|'
    r'WinExec|ShellExecute|RegOpenKey|RegSetValue|RegQueryValue|'
    r'Socket|connect|send|recv|bind|listen|accept|WSASocket|'
    r'InternetOpen|InternetConnect|HttpOpenRequest|HttpSendRequest|'
    r'URLDownloadToFile|WinHttpOpen|WinHttpConnect|WinHttpOpenRequest|'
    r'GetModuleHandle|WriteProcessMemory|ReadProcessMemory|'
    r'CreateFileMapping|MapViewOfFile|UnmapViewOfFile|OpenProcessToken|'
    r'AdjustTokenPrivileges|LookupPrivilegeValue|SetWindowsHookEx|'
    r'GetAsyncKeyState|GetForegroundWindow|GetWindowText|'
    r'CryptEncrypt|CryptDecrypt|CryptAcquireContext|CryptGenKey|'
    r'Certificate|X509|SSL|TLS|RSA|AES|MD5|SHA|'
    r'FindFirstFile|FindNextFile|DeleteFile|MoveFile|CopyFile|'
    r'GetTickCount|QueryPerformanceCounter|Sleep|GetSystemTime|'
    r'RtlDecompressBuffer|NtQuerySystemInformation|NtQueryInformationProcess)\b',
    re.IGNORECASE,
)
# Security-relevant patterns
_XOR_LOOP_RE = re.compile(
    r'(for|while)\s*\(.*\)\s*\{[^}]*\^=|xor\s+.*,\s*0x[0-9a-fA-F]+',
    re.IGNORECASE,
)
_ANTIDEBUG_RE = re.compile(
    r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|'
    r'ZwQueryInformationProcess|OutputDebugString|SetLastError.*call.*GetLastError',
    re.IGNORECASE,
)
_ANTIVM_RE = re.compile(
    r'cpuid|in\s+eax,\s*dx|sidt|sgdt|sldt|str|smsw|rdtsc|icebp|int\s+3|'
    r'int\s+1|int\s+0x2d',
    re.IGNORECASE,
)
_SHELLCODE_RE = re.compile(
    r'VirtualAlloc.*PAGE_EXECUTE|WriteProcessMemory.*VirtualAlloc|'
    r'CreateRemoteThread|QueueUserAPC',
    re.IGNORECASE,
)
_DYNAMIC_IMPORT_RE = re.compile(
    r'GetProcAddress\s*\(\s*.*,\s*.*\s*\)|LoadLibrary.*GetProcAddress',
    re.IGNORECASE,
)
_STRING_IN_CODE_RE = re.compile(
    r'(?:push|mov|lea).*(?:offset\s+)?(?:a[A-Z]\w+|off_[0-9A-F]+|byte_[0-9A-F]+)',
    re.IGNORECASE,
)


def digest_decompiled(pseudocode: str, func_name: str = "", func_addr: str = "",
                       schema_attrs: dict | None = None) -> dict:
    """Parse decompiled pseudocode and extract a structured summary.

    Returns:
        {
          api_calls:        list of detected Windows API names (deduped, ordered)
          api_categories:   list of functional groups (memory, network, crypto, ...)
          patterns:         list of human-readable behavioral observations
          security_notes:   list of warnings (anti-debug, shellcode staging, etc.)
          complexity:       {lines, calls, branches, loops} (coarse counts)
          string_refs:      inferred string references from push/mov/lea patterns
          behavior_tags:    routing tags (network, crypto, allocator, ...)
        }

    Note: the original implementation included `density` (a fabricated formula
    combining lexical_diversity + char entropy + useful_fraction with made-up
    weights) and `severity` (a count-of-api-calls heuristic). Both were removed
    — they did not correspond to any real metric and the LLM was treating them
    as ground truth.
    """
    if not pseudocode or not isinstance(pseudocode, str):
        return {}

    schema_attrs = schema_attrs or {}

    digest: dict[str, Any] = {
        "api_calls": [],
        "api_categories": set(),
        "patterns": [],
        "security_notes": [],
        "complexity": {"lines": 0, "calls": 0, "branches": 0, "loops": 0},
        "string_refs": [],
        "behavior_tags": [],
    }

    _API_CATEGORIES = {
        "memory": {"VirtualAlloc", "VirtualFree", "VirtualProtect", "HeapAlloc",
                   "HeapFree", "malloc", "free", "WriteProcessMemory",
                   "ReadProcessMemory", "GlobalAlloc", "VirtualQuery",
                   "NtAllocateVirtualMemory"},
        "process": {"CreateProcess", "OpenProcess", "TerminateProcess",
                    "CreateThread", "CreateRemoteThread", "NtCreateThreadEx"},
        "network": {"socket", "connect", "send", "recv", "bind", "listen",
                    "InternetOpen", "InternetConnect", "HttpOpenRequest",
                    "URLDownloadToFile", "WSASocket", "WinHttpOpen",
                    "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
                    "WinHttpReceiveResponse"},
        "file": {"CreateFile", "ReadFile", "WriteFile", "DeleteFile",
                 "FindFirstFile", "FindNextFile", "CopyFile", "MoveFile",
                 "NtCreateFile"},
        "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
                   "CryptGenKey", "AES", "MD5", "SHA", "RSA", "X509", "BCrypt",
                   "NCrypt", "CryptStringToBinary", "CryptBinaryToString"},
        "registry": {"RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey",
                     "RegDeleteKey", "RegEnumKey", "RegCloseKey"},
        "injection": {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                      "SetWindowsHookEx", "QueueUserAPC", "NtMapViewOfSection"},
        "evasion": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "GetTickCount",
                    "QueryPerformanceCounter", "NtSetInformationThread",
                    "OutputDebugStringA"},
        "persistence": {"RegCreateKeyEx", "CreateService", "StartService",
                        "schtasks", "CreateScheduledTask"},
    }

    lines = pseudocode.split("\n")
    digest["complexity"]["lines"] = len(lines)

    seen_apis: set = set()
    for match in _WIN32_API_PATTERN.finditer(pseudocode):
        api = match.group(0)
        if api in seen_apis:
            continue
        seen_apis.add(api)
        digest["api_calls"].append(api)
        for cat, apis in _API_CATEGORIES.items():
            if api in apis:
                digest["api_categories"].add(cat)

    digest["complexity"]["calls"] = pseudocode.count("(") // 2  # rough
    digest["complexity"]["branches"] = pseudocode.count("if ") + pseudocode.count("if(")
    digest["complexity"]["loops"] = (
        pseudocode.count("for(") + pseudocode.count("while(") + pseudocode.count("do{")
    )

    if _XOR_LOOP_RE.search(pseudocode):
        digest["patterns"].append("XOR-based loop (possible string/resource decryption)")
    if _DYNAMIC_IMPORT_RE.search(pseudocode):
        digest["patterns"].append("Dynamic API resolution (GetProcAddress + LoadLibrary)")
        digest["security_notes"].append("Uses dynamic imports (obfuscation likely)")
    if _SHELLCODE_RE.search(pseudocode):
        digest["patterns"].append("Shellcode staging (VirtualAlloc + WriteProcessMemory)")
        digest["security_notes"].append("WARNING: Shellcode staging detected")
    if _ANTIDEBUG_RE.search(pseudocode):
        digest["patterns"].append("Anti-debug check")
        digest["security_notes"].append("Contains anti-debugging techniques")
    if _ANTIVM_RE.search(pseudocode):
        digest["patterns"].append("Anti-VM/anti-sandbox check")
        digest["security_notes"].append("Contains anti-VM/anti-sandboxing techniques")

    for match in _STRING_IN_CODE_RE.finditer(pseudocode):
        digest["string_refs"].append(match.group(0))

    api_cats = digest["api_categories"]
    if "network" in api_cats:
        digest["behavior_tags"].append("network")
    if "crypto" in api_cats:
        digest["behavior_tags"].append("crypto")
    if "memory" in api_cats:
        digest["behavior_tags"].append("allocator")
    if "injection" in api_cats:
        digest["behavior_tags"].append("process_injection")
        digest["security_notes"].append("WARNING: process-injection capability detected")
    if "evasion" in api_cats:
        digest["behavior_tags"].append("anti_analysis")
    if "persistence" in api_cats:
        digest["behavior_tags"].append("persistence")
    if "file" in api_cats and "registry" in api_cats:
        digest["behavior_tags"].append("file_io")

    if schema_attrs:
        sb_loops = schema_attrs.get("has_loops", False)
        if sb_loops:
            digest["complexity"]["has_loops"] = True
        sb_cc = schema_attrs.get("cyclomatic_complexity", 0)
        if sb_cc and sb_cc > digest["complexity"].get("cyclomatic_complexity", 0):
            digest["complexity"]["cyclomatic_complexity"] = sb_cc
        sb_entropy = schema_attrs.get("entropy", 0.0)
        if sb_entropy:
            digest["complexity"]["entropy"] = round(sb_entropy, 3)
        sb_xrefs = schema_attrs.get("xref_count", 0)
        if sb_xrefs:
            digest["complexity"]["xref_count"] = sb_xrefs

        sb_apis = schema_attrs.get("apis", [])
        if isinstance(sb_apis, list):
            for api in sb_apis:
                if api not in digest["api_calls"]:
                    digest["api_calls"].append(api)
        if schema_attrs.get("has_crypto_constants"):
            digest["patterns"].append("Crypto constants (verified by SchemaBoot)")
            if "crypto" not in digest["behavior_tags"]:
                digest["behavior_tags"].append("crypto")

    digest["api_categories"] = sorted(digest["api_categories"])
    return digest


# `build_session_resume` was moved to response_signals.py during the
# ghost-chain cleanup. Re-export here so prior call sites that
# imported from response_enrichment keep working.
from .response_signals import (  # noqa: E402,F401  (legacy re-export)
    build_session_resume,
)
