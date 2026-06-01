"""
Response Enrichment Middleware.

Post-processes tool responses before the LLM sees them:
  1. Address Patching: Resolves rip-relative expressions in pseudocode
  2. Auto-Digest: Parses decompiled pseudocode for APIs, strings, patterns
  3. Session Resume: Injects previous session state on reconnect
  4. Auto-Blackboard: Silently writes significant findings to blackboard
  5. Security Pattern Detection: Flags anti-debug, anti-VM, crypto patterns
  6. Ghost Tool Chains: Pre-emptively executes companion tool calls

All operations are deterministic regex/parsing based. No LLM dependencies.
"""

from __future__ import annotations

import json
import re
import os
from typing import Any, Dict, List, Optional, Set, Tuple, Callable


# ============================================================================
# Address Patching
# ============================================================================

# Matches common base+offset patterns in x86/x64 assembly/disassembly
_BASE_OFFSET_RE = re.compile(
    r'(rip|rsp|rbp|rsi|rdi|r[89]|r1[0-5]|gs|fs|cs|ds)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)',
    re.IGNORECASE,
)

# Matches direct address references in pseudocode
_DIRECT_ADDR_RE = re.compile(r'&\w+\s*\[\s*(0x[0-9a-fA-F]+)\s*\]|address\s+(0x[0-9a-fA-F]+)|\bat\s+(0x[0-9a-fA-F]+)', re.IGNORECASE)

# Matches string assignments that reveal address info
_STRING_ADDR_RE = re.compile(r'"([^"]*)"\s*(?:@|at|located at|stored at|address)\s*(0x[0-9a-fA-F]+)', re.IGNORECASE)

# Matches load effective address patterns in x86
_LEA_RE = re.compile(r'lea\s+(\w+)\s*,\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+)\]', re.IGNORECASE)

# Matches mov with displacement
_MOV_DISP_RE = re.compile(r'mov\s+(\w+)\s*,\s*(?:qword|dword|word|byte)\s+ptr\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+)\]', re.IGNORECASE)


def patch_addresses(text: str, base_registers: Optional[Dict[str, int]] = None) -> str:
    """
    Scan text for unresolved address expressions and inject computed values.
    
    For each rip-relative expression like 'rip+0x12345':
      - Compute absolute address (if we have the RIP value)
      - Inject comment with the resolved address
      - If the address points to a string, inject the string content
    
    Returns the patched text.
    """
    if not text or not isinstance(text, str):
        return text
    
    base_registers = base_registers or {}
    lines = text.split("\n")
    patched_lines = []
    
    for line in lines:
        original = line
        
        # Pattern: rip-relative LEA
        for match in _LEA_RE.finditer(line):
            base = match.group(2)
            op = match.group(3)
            offset = int(match.group(4), 16)
            if base in base_registers:
                base_val = base_registers[base]
                abs_addr = base_val + (offset if op == "+" else -offset)
                line = line.replace(match.group(0), f"{match.group(0)}  ; → {hex(abs_addr)}")
        
        # Pattern: rip-relative in pseudocode comments
        if "rip" in line.lower() or "base+" in line.lower():
            for match in _BASE_OFFSET_RE.finditer(line):
                base_name = match.group(1)
                offset_str = match.group(3)
                try:
                    offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                except ValueError:
                    continue
                if base_name in base_registers:
                    base_val = base_registers[base_name]
                    abs_addr = base_val + offset
                    resolved = hex(abs_addr)
                    # Don't modify the code text, add an inline comment
                    if f"; →" not in line:
                        line = f"{line}  ; {match.group(0)} → {resolved}"
        
        patched_lines.append(line)
    
    return "\n".join(patched_lines)


# ============================================================================
# Decompile Auto-Digest
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
    re.IGNORECASE
)

# Security-relevant patterns
_XOR_LOOP_RE = re.compile(r'(for|while)\s*\(.*\)\s*\{[^}]*\^=|xor\s+.*,\s*0x[0-9a-fA-F]+', re.IGNORECASE)
_ANTIDEBUG_RE = re.compile(r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ZwQueryInformationProcess|OutputDebugString|SetLastError.*call.*GetLastError', re.IGNORECASE)
_ANTIVM_RE = re.compile(r'cpuid|in\s+eax,\s*dx|sidt|sgdt|sldt|str|smsw|rdtsc|icebp|int\s+3|int\s+1|int\s+0x2d', re.IGNORECASE)
_SHELLCODE_RE = re.compile(r'VirtualAlloc.*PAGE_EXECUTE|WriteProcessMemory.*VirtualAlloc|CreateRemoteThread|QueueUserAPC', re.IGNORECASE)
_CRYPTO_RE = re.compile(r'(?:0x[0-9a-fA-F]{2}\s*,\s*){4,}|(?:0x[0-9a-fA-F]{2},\s*){0,3}0x[0-9a-fA-F]{2}', re.IGNORECASE)
_DYNAMIC_IMPORT_RE = re.compile(r'GetProcAddress\s*\(\s*.*,\s*.*\s*\)|LoadLibrary.*GetProcAddress', re.IGNORECASE)

# String references in pseudocode
_STRING_IN_CODE_RE = re.compile(r'(?:push|mov|lea).*(?:offset\s+)?(?:a[A-Z]\w+|off_[0-9A-F]+|byte_[0-9A-F]+)', re.IGNORECASE)


def digest_decompiled(pseudocode: str, func_name: str = "", func_addr: str = "",
                      schema_attrs: Optional[dict] = None) -> dict:
    """
    Parse decompiled pseudocode and extract structured summary.
    Incorporates SchemaBoot attribute data for richer classification.
    
    Uses composite scoring from Context Density research:
      D(C) = 0.4 * lexdiv_norm + 0.3 * entropy_norm + 0.3 * useful_fraction
    
    Returns a digest dict with:
      - api_calls: List of detected API calls with categories
      - patterns: List of detected behavioral patterns
      - security_notes: Security-relevant observations
      - complexity: Complexity metrics (from both parsing and SchemaBoot)
      - string_refs: Inferred string references
      - behavior_classification: Inferred behavior tags (preference-bank-compatible)
      - density: Information density of the pseudocode
    """
    if not pseudocode or not isinstance(pseudocode, str):
        return {}
    
    schema_attrs = schema_attrs or {}
    
    digest = {
        "api_calls": [],
        "api_categories": set(),
        "patterns": [],
        "security_notes": [],
        "complexity": {"lines": 0, "calls": 0, "branches": 0, "loops": 0},
        "string_refs": [],
        "behavior_tags": [],
        "density": {},
    }
    
    lines = pseudocode.split("\n")
    digest["complexity"]["lines"] = len(lines)
    
    # Categorize APIs into functional groups
    _API_CATEGORIES = {
        "memory": {"VirtualAlloc", "VirtualFree", "VirtualProtect", "HeapAlloc", "HeapFree",
                   "malloc", "free", "WriteProcessMemory", "ReadProcessMemory", "GlobalAlloc",
                   "VirtualQuery", "NtAllocateVirtualMemory"},
        "process": {"CreateProcess", "OpenProcess", "TerminateProcess",
                    "CreateThread", "CreateRemoteThread", "NtCreateThreadEx"},
        "network": {"socket", "connect", "send", "recv", "bind", "listen",
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "URLDownloadToFile",
                    "WSASocket", "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
                    "WinHttpSendRequest", "WinHttpReceiveResponse"},
        "file": {"CreateFile", "ReadFile", "WriteFile", "DeleteFile",
                 "FindFirstFile", "FindNextFile", "CopyFile", "MoveFile", "NtCreateFile"},
        "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey",
                   "AES", "MD5", "SHA", "RSA", "X509", "BCrypt", "NCrypt",
                   "CryptStringToBinary", "CryptBinaryToString"},
        "registry": {"RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey",
                     "RegDeleteKey", "RegEnumKey", "RegCloseKey"},
        "injection": {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                      "SetWindowsHookEx", "QueueUserAPC", "NtMapViewOfSection"},
        "evasion": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
                    "NtSetInformationThread", "OutputDebugStringA"},
        "persistence": {"RegCreateKeyEx", "CreateService", "StartService",
                        "schtasks", "CreateScheduledTask"},
    }
    
    for match in _WIN32_API_PATTERN.finditer(pseudocode):
        api = match.group(0)
        digest["api_calls"].append(api)
        for cat, apis in _API_CATEGORIES.items():
            if api in apis:
                digest["api_categories"].add(cat)
    
    # Count control flow constructs
    digest["complexity"]["calls"] = pseudocode.count("(") // 2  # Rough call count
    digest["complexity"]["branches"] = pseudocode.count("if ") + pseudocode.count("if(")
    digest["complexity"]["loops"] = pseudocode.count("for(") + pseudocode.count("while(") + pseudocode.count("do{")
    
    # Pattern detection
    if _XOR_LOOP_RE.search(pseudocode):
        digest["patterns"].append("XOR-based loop — possible string/resource decryption")
    if _DYNAMIC_IMPORT_RE.search(pseudocode):
        digest["patterns"].append("Dynamic API resolution (GetProcAddress + LoadLibrary)")
        digest["security_notes"].append("Uses dynamic imports — obfuscation likely")
    if _SHELLCODE_RE.search(pseudocode):
        digest["patterns"].append("Shellcode staging — VirtualAlloc + WriteProcessMemory")
        digest["security_notes"].append("WARNING: Shellcode staging detected")
    if _ANTIDEBUG_RE.search(pseudocode):
        digest["patterns"].append("Anti-debug check")
        digest["security_notes"].append("Contains anti-debugging techniques")
    if _ANTIVM_RE.search(pseudocode):
        digest["patterns"].append("Anti-VM/anti-sandbox check")
        digest["security_notes"].append("Contains anti-VM/anti-sandboxing")
    
    # String references inference
    for match in _STRING_IN_CODE_RE.finditer(pseudocode):
        digest["string_refs"].append(match.group(0))
    
    # Behavior classification (preference-bank-compatible tags)
    api_cats = digest.get("api_categories", set())
    if "network" in api_cats:
        digest["behavior_tags"].append("network")
    if "crypto" in api_cats:
        digest["behavior_tags"].append("crypto")
    if "memory" in api_cats:
        digest["behavior_tags"].append("allocator")
    if "injection" in api_cats:
        digest["behavior_tags"].append("process_injection")
        digest["security_notes"].append("WARNING: Process injection capability detected")
    if "evasion" in api_cats:
        digest["behavior_tags"].append("anti_analysis")
    if "persistence" in api_cats:
        digest["behavior_tags"].append("persistence")
    if "file" in api_cats and "registry" in api_cats:
        digest["behavior_tags"].append("file_io")
    
    # Incorporate SchemaBoot attributes for richer classification
    if schema_attrs:
        # Structural complexity from SchemaBoot
        sb_size = schema_attrs.get("size", 0)
        sb_cc = schema_attrs.get("cyclomatic_complexity", 0)
        sb_loops = schema_attrs.get("has_loops", False)
        sb_entropy = schema_attrs.get("entropy", 0.0)
        sb_xrefs = schema_attrs.get("xref_count", 0)
        
        if sb_loops:
            digest["complexity"]["has_loops"] = True
        if sb_cc and sb_cc > digest["complexity"].get("cyclomatic_complexity", 0):
            digest["complexity"]["cyclomatic_complexity"] = sb_cc
        if sb_entropy:
            digest["complexity"]["entropy"] = round(sb_entropy, 3)
        if sb_xrefs:
            digest["complexity"]["xref_count"] = sb_xrefs
        
        # SchemaBoot API attribution
        sb_apis = schema_attrs.get("apis", [])
        if isinstance(sb_apis, list) and sb_apis:
            for api in sb_apis:
                if api not in digest["api_calls"]:
                    digest["api_calls"].append(api)
        
        # SchemaBoot crypto detection
        if schema_attrs.get("has_crypto_constants"):
            digest["patterns"].append("Crypto constants detected (verified by SchemaBoot)")
            if "crypto" not in digest["behavior_tags"]:
                digest["behavior_tags"].append("crypto")
    
    # Compute information density (from Context Density research)
    # D(C) = 0.4 * lexdiv_norm + 0.3 * entropy_norm + 0.3 * useful_fraction
    words = pseudocode.split()
    unique_words = set(words)
    lexical_diversity = len(unique_words) / max(1, len(words))
    
    # Shannon entropy approximation
    import math
    char_counts = {}
    for c in pseudocode:
        char_counts[c] = char_counts.get(c, 0) + 1
    total_chars = len(pseudocode)
    entropy = -sum((count / total_chars) * math.log2(count / total_chars)
                   for count in char_counts.values()) if total_chars > 0 else 0.0
    
    # Useful fraction: code lines vs comments/whitespace
    useful_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith("//"))
    useful_fraction = useful_lines / max(1, len(lines))
    
    normalized_lexdiv = min(1.0, lexical_diversity * 3.0)
    normalized_entropy = min(1.0, entropy / 8.0)
    density_score = 0.4 * normalized_lexdiv + 0.3 * normalized_entropy + 0.3 * useful_fraction
    
    digest["density"] = {
        "score": round(density_score, 4),
        "lexical_diversity": round(lexical_diversity, 4),
        "shannon_entropy": round(entropy, 2),
        "useful_fraction": round(useful_fraction, 4),
    }
    
    # Set severity based on combined signals
    if digest.get("security_notes"):
        if any("WARNING" in n for n in digest["security_notes"]):
            digest["severity"] = "high"
        else:
            digest["severity"] = "medium"
    elif len(digest.get("api_calls", [])) > 10:
        digest["severity"] = "medium"
    else:
        digest["severity"] = "low"
    
    # Convert set to list for JSON serialization
    digest["api_categories"] = list(digest.get("api_categories", set()))
    
    return digest



# Signal helpers now live in response_signals.py to keep this module focused on
# byte/string patching and decompilation digesting.
from .response_signals import (
    auto_blackboard_write,
    build_session_resume,
    build_signal_directives,
    generate_hypotheses,
    get_ghost_chain,
)
