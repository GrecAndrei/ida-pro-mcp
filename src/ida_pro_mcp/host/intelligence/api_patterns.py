"""Deterministic API-pattern extraction helpers for intelligence context."""

from __future__ import annotations

import re
from typing import Any

_INTERESTING_APIS: dict[str, frozenset] = {
    "process_injection": frozenset({
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThread", "RtlCreateUserThread", "NtWriteVirtualMemory",
    }),
    "memory_exec": frozenset({"VirtualAlloc", "VirtualProtect", "mmap", "mprotect"}),
    "network": frozenset({
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSASocket", "WSAConnect", "WSASend", "WSARecv",
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReadData",
        "URLDownloadToFile",
    }),
    "crypto_winapi": frozenset({
        "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptDeriveKey",
        "CryptGenKey", "CryptImportKey", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash",
    }),
    "persistence": frozenset({
        "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegOpenKey",
        "CreateService", "OpenService", "StartService", "ChangeServiceConfig",
    }),
    "anti_debug": frozenset({
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString", "NtSetInformationThread",
    }),
    "privilege": frozenset({
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    }),
    "process_spawn": frozenset({
        "CreateProcess", "CreateProcessW", "CreateProcessA",
        "ShellExecute", "ShellExecuteEx", "WinExec", "NtCreateProcess",
    }),
    "file_ops": frozenset({
        "CreateFile", "CreateFileW", "ReadFile", "WriteFile", "DeleteFile",
        "MoveFile", "CopyFile", "FindFirstFile",
    }),
}

ALL_INTERESTING_APIS: frozenset = frozenset().union(*_INTERESTING_APIS.values())

_API_COMBOS: list[tuple[frozenset, list[dict[str, Any]]]] = [
    (frozenset({"VirtualAllocEx", "WriteProcessMemory"}), [
        {"tool": "annotation", "action": "mark_dangerous",
         "reason": "VirtualAllocEx + WriteProcessMemory = classic process injection"},
        {"tool": "graph", "action": "call_chain",
         "reason": "Trace injection chain to find where shellcode originates"},
        {"tool": "code", "action": "callers", "reason": "Find what triggers this injection"},
    ]),
    (frozenset({"CreateRemoteThread"}), [
        {"tool": "annotation", "action": "mark_dangerous", "reason": "CreateRemoteThread — remote code execution"},
        {"tool": "code", "action": "callers", "reason": "Trace where the target process handle comes from"},
    ]),
    (frozenset({"CryptEncrypt"}) | frozenset({"BCryptEncrypt"}) | frozenset({"CryptHashData"}), [
        {"tool": "crypto_id", "action": "identify", "reason": "Windows CNG/CryptoAPI in use — identify algorithm"},
    ]),
    (frozenset({"WSASocket"}) | frozenset({"InternetOpen"}) | frozenset({"WinHttpOpen"}), [
        {"tool": "string_ops", "action": "find_urls", "reason": "Network API — extract hardcoded URLs"},
        {"tool": "string_ops", "action": "find_ips", "reason": "Extract hardcoded IP addresses"},
    ]),
    (frozenset({"socket", "connect"}), [
        {"tool": "string_ops", "action": "find_ips", "reason": "Raw socket — find target IPs"},
    ]),
    (frozenset({"RegSetValueEx"}) | frozenset({"CreateService"}), [
        {"tool": "search", "action": "api", "pattern": "*Reg*",
         "reason": "Registry/service persistence — find related writes across binary"},
    ]),
    (frozenset({"IsDebuggerPresent"}) | frozenset({"CheckRemoteDebuggerPresent"})
     | frozenset({"NtQueryInformationProcess"}), [
        {"tool": "annotation", "action": "mark_dangerous", "reason": "Anti-debugging — patch or note for analysis bypass"},
    ]),
    (frozenset({"AdjustTokenPrivileges"}), [
        {"tool": "annotation", "action": "mark_dangerous", "reason": "Token privilege manipulation — privilege escalation"},
        {"tool": "graph", "action": "call_chain", "reason": "Trace escalation path"},
    ]),
    (frozenset({"CreateProcess", "CreateProcessW"}) | frozenset({"ShellExecuteEx"}), [
        {"tool": "string_ops", "action": "find_commands", "reason": "Process spawning — extract command-line arguments"},
        {"tool": "code", "action": "callers", "reason": "Find what triggers process creation"},
    ]),
]

_STRING_LIT_RE = re.compile(r'"([^"]{4,120})"')
_HEX_CONST_RE = re.compile(r'\b(0x[0-9A-Fa-f]{6,})\b')
_CRYPTO_CONSTS = frozenset({
    "0x67452301", "0xefcdab89", "0x98badcfe",
    "0x6a09e667", "0xbb67ae85", "0x3c6ef372",
    "0x428a2f98", "0x71374491", "0xd76aa478", "0xe8c7b756",
})


def extract_api_calls(pseudocode: str) -> list[str]:
    found: list[str] = []
    seen: set = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b", pseudocode):
        name = match.group(1)
        if name in ALL_INTERESTING_APIS and name not in seen:
            seen.add(name)
            found.append(name)
    return found[:30]


def extract_string_refs(pseudocode: str) -> list[str]:
    raw = _STRING_LIT_RE.findall(pseudocode)
    interesting = [
        s for s in raw
        if any(kw in s.lower() for kw in (
            "http", "https", "ftp", "\\\\", "cmd", "powershell", ".exe", ".dll",
            ".bat", ".ps1", "hkey", "software\\", "run", "service",
            "password", "admin", "token",
        )) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}", s)
    ]
    return (interesting or raw)[:8]


def detect_crypto_constants(pseudocode: str) -> list[str]:
    hits = [h.lower() for h in _HEX_CONST_RE.findall(pseudocode) if h.lower() in _CRYPTO_CONSTS]
    return list(set(hits))[:5]


def actions_from_apis(apis: list[str], addr: str) -> list[dict[str, Any]]:
    api_set = frozenset(apis)
    actions: list[dict[str, Any]] = []
    seen: set = set()
    for required, combo_actions in _API_COMBOS:
        if required & api_set:
            for act in combo_actions:
                key = f"{act['tool']}:{act['action']}"
                if key not in seen:
                    seen.add(key)
                    item = dict(act)
                    if addr and act.get("tool") in (
                        "annotation", "graph", "crypto_id", "code", "string_ops"
                    ):
                        item.setdefault("addr", addr)
                    actions.append(item)
    return actions[:6]


def actions_from_schemaboot(attrs: dict[str, Any], addr: str) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    xor = attrs.get("xor_count", 0)
    entropy = attrs.get("entropy", 0.0)
    cyclomatic = attrs.get("cyclomatic_complexity", 0)
    xrefs_in = attrs.get("incoming_xrefs", 0)

    if xor > 5:
        actions.append({
            "tool": "crypto_id", "action": "identify", "addr": addr,
            "reason": f"{xor} XOR instructions — possible custom encryption or obfuscation",
        })
    if entropy > 6.0:
        actions.append({
            "tool": "entropy", "action": "region", "addr": addr,
            "reason": f"Entropy {entropy:.1f} — may process packed or encrypted data",
        })
    if cyclomatic > 15:
        actions.append({
            "tool": "code", "action": "blocks", "addr": addr,
            "reason": f"Cyclomatic complexity {cyclomatic} — possible state machine or protocol parser",
        })
    if xrefs_in == 0:
        actions.append({
            "tool": "search", "action": "data_ref", "addr": addr,
            "reason": "No direct callers — may be invoked via function pointer or vtable",
        })
    elif xrefs_in > 20:
        actions.append({
            "tool": "code", "action": "callers", "addr": addr,
            "reason": f"{xrefs_in} callers — widely used utility, renaming will improve the whole analysis",
        })
    return actions[:4]
