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
      - behavior_classification: Inferred behavior tags (MemRL-compatible)
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
    
    # Behavior classification (MemRL-compatible tags)
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


# ============================================================================
# Session Resume Injection
# ============================================================================

def build_session_resume(
    session_manager,
    sid: str,
    blackboard_entries: Optional[List[dict]] = None,
) -> Optional[dict]:
    """
    Build a session resume context block for reconnecting LLMs.
    
    Injects previous analysis state so the LLM doesn't start from scratch.
    """
    if not session_manager or not sid:
        return None
    
    session = session_manager.get_session(sid)
    if not session:
        return None
    
    resume = {}
    
    # Previous progress
    skills_data = session_manager._load_skills(sid)
    activity_log = skills_data.get("activity_log", [])
    hypotheses = skills_data.get("hypotheses", [])
    skills = skills_data.get("skills", {})
    
    # What was analyzed
    decompiled = set()
    for entry in activity_log:
        if entry.get("action") in ("decompile", "semantic_decompile"):
            addr = entry.get("result", "")
            if addr and addr.startswith("0x"):
                decompiled.add(addr)
    
    if decompiled:
        resume["previously_decompiled"] = sorted(list(decompiled))
    
    # Active hypotheses
    pending = [h for h in hypotheses if h.get("status") == "pending"]
    if pending:
        resume["pending_hypotheses"] = [
            {"id": h["id"], "statement": h["statement"]} for h in pending[:5]
        ]
    
    confirmed = [h for h in hypotheses if h.get("status") == "confirmed"]
    if confirmed:
        resume["confirmed_findings"] = [
            {"id": h["id"], "statement": h["statement"]} for h in confirmed[:5]
        ]
    
    # Skills available
    high_q_skills = {k: v for k, v in skills.items() if v.get("q_value", 0) > 0.5}
    if high_q_skills:
        resume["available_skills"] = [
            {"name": v.get("name", k), "description": v.get("description", "")[:100]}
            for k, v in list(high_q_skills.items())[:5]
        ]
    
    # Progress
    total_actions = len(activity_log)
    if total_actions > 0:
        resume["analysis_progress"] = {
            "total_actions": total_actions,
            "phase": session.phase,
            "estimated_completion": f"{min(99, total_actions // 5)}% of typical analysis",
        }
    
    # Notebook recent
    notebook = getattr(session_manager, '_load_notebook', lambda x: "")(sid)
    if notebook:
        last_lines = notebook.split("\n")[-10:]
        resume["last_notebook_entry"] = "\n".join(last_lines)
    
    return resume if resume else None


# ============================================================================
# Auto-Hypothesis Engine
# ============================================================================

_HYPOTHESIS_TEMPLATES = {
    "c2_communication": {
        "statement": "This function is likely a C2 beacon: calls Sleep in a loop with send/recv",
        "confidence": 0.75,
        "suggested_actions": ["trace network calls", "extract C2 URLs", "check sleep intervals"],
    },
    "crypto_symmetric": {
        "statement": "This function implements symmetric encryption (AES/ChaCha20 pattern detected)",
        "confidence": 0.7,
        "suggested_actions": ["identify key schedule", "extract constants", "check key length"],
    },
    "process_injection": {
        "statement": "This function performs process injection via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread",
        "confidence": 0.85,
        "suggested_actions": ["identify target process", "extract injected payload", "trace memory allocations"],
    },
    "persistence": {
        "statement": "This function establishes persistence via registry Run key or service installation",
        "confidence": 0.7,
        "suggested_actions": ["extract registry paths", "identify service name", "check startup conditions"],
    },
    "anti_debug": {
        "statement": "This function contains anti-debugging checks",
        "confidence": 0.8,
        "suggested_actions": ["identify check type", "find bypass points", "check for timing checks"],
    },
}


def generate_hypotheses(
    tool: str,
    action: str,
    result: dict,
    addr: Optional[str] = None,
    behavior_tags: Optional[List[str]] = None,
) -> List[dict]:
    """
    Generate structured hypothesis statements from behavior_tags and API calls in result.

    Returns list of dicts: {statement, confidence, evidence, suggested_actions}
    """
    if not behavior_tags:
        return []

    hypotheses = []
    apis = []
    if isinstance(result, dict):
        apis = result.get("api_calls", [])
        if not apis:
            pseudocode = result.get("pseudocode", "")
            if pseudocode:
                apis = [m.group(0) for m in _WIN32_API_PATTERN.finditer(pseudocode)]

    for tag in behavior_tags:
        template = _HYPOTHESIS_TEMPLATES.get(tag)
        if not template:
            continue
        evidence = [f"behavior_tag={tag}", f"tool={tool}:{action}"]
        if addr:
            evidence.append(f"addr={addr}")
        if apis:
            evidence.append(f"apis={','.join(apis[:5])}")
        hypotheses.append({
            "statement": template["statement"],
            "confidence": template["confidence"],
            "evidence": evidence,
            "suggested_actions": template["suggested_actions"],
        })

    return hypotheses


# ============================================================================
# Auto-Blackboard
# ============================================================================

def auto_blackboard_write(
    tool: str,
    action: str,
    result: dict,
    addr: Optional[str] = None,
) -> Optional[List[dict]]:
    """
    Determine if this tool result should be auto-written to the blackboard.
    
    Returns a list of blackboard entries to write, or None.
    """
    entries = []
    
    if not result or not result.get("ok"):
        return None
    
    # Decompiled a function → write finding
    if tool == "code" and action in ("decompile", "semantic_decompile") and addr:
        digest = digest_decompiled(result.get("pseudocode", ""), func_addr=addr)
        apis = digest.get("api_calls", [])[:5]
        patterns = digest.get("patterns", [])[:3]
        security = digest.get("security_notes", [])[:2]
        
        summary_parts = [f"Decompiled function at {addr}."]
        if apis:
            summary_parts.append(f"Uses: {', '.join(apis)}.")
        if patterns:
            summary_parts.append(f"Patterns: {'; '.join(patterns)}.")
        if security:
            summary_parts.append(f"⚠ {'; '.join(security)}.")
        
        entries.append({
            "category": "decompile",
            "addr": addr,
            "name": f"Analysis of {addr}",
            "notes": " ".join(summary_parts),
            "tags": list(set(digest.get("api_categories", []))),
            "priority": 5 if security else 4,
        })

        # Auto-hypothesis generation from behavior tags
        behavior_tags = digest.get("behavior_tags", [])
        if behavior_tags:
            hypotheses = generate_hypotheses(tool, action, result, addr, behavior_tags)
            if hypotheses:
                try:
                    from ida_pro_mcp.ida_mcp.tools.blackboard import BlackboardStore
                    store = BlackboardStore()
                    for hyp in hypotheses:
                        store.write(
                            title=hyp['statement'][:120],
                            content=json.dumps(hyp),
                            category='hypothesis',
                            addr=addr or '',
                            tags=['auto', 'hypothesis'] + behavior_tags[:3],
                            confidence=hyp['confidence'],
                            source='auto_hypothesis',
                            source_type='engine_classifier',
                            evidence=[{"type": "classifier", "value": t,
                                       "weight": hyp['confidence'], "ts": __import__('time').time()}
                                      for t in behavior_tags[:3]],
                        )
                    # Update KG: if behavior_tags suggest a known system type, add to kg_systems
                    _update_kg_from_hypothesis(store.db_path, addr or '', behavior_tags, hypotheses)
                except Exception:
                    pass
    
    # Found strings with suspicious patterns
    if tool == "data" and action == "strings":
        matches = result.get("strings", result.get("matches", []))
        if isinstance(matches, list):
            suspicious = [s for s in matches if any(
                pattern in str(s).lower() 
                for pattern in ["http", ".com", ".exe", ".dll", "password", "admin", "cmd", "powershell", "user-agent"]
            )]
            if suspicious:
                entries.append({
                    "category": "strings",
                    "name": "Suspicious strings found",
                    "notes": f"{len(suspicious)} suspicious strings: {', '.join(str(s)[:50] for s in suspicious[:5])}",
                    "tags": ["strings", "suspicious"],
                    "priority": 4,
                })
    
    # Found interesting imports
    if tool == "data" and action == "imports":
        imports = result.get("imports", [])
        if isinstance(imports, list) and len(imports) > 0:
            suspicious_apis = [imp for imp in imports if isinstance(imp, (dict, str))]
            if len(suspicious_apis) > 20:
                entries.append({
                    "category": "imports",
                    "name": "Import analysis",
                    "notes": f"Binary imports {len(imports)} APIs from {len(set(str(i).split('.')[0] if isinstance(i, str) else i.get('module','') for i in imports[:50]))} modules.",
                    "tags": ["imports"],
                    "priority": 3,
                })
    
    # Found crypto constants
    if tool == "crypto_id" and action in ("detect", "scan", "identify"):
        consts = result.get("constants", result.get("detected", []))
        if consts and len(consts) > 0:
            entries.append({
                "category": "crypto",
                "name": "Cryptographic constants detected",
                "notes": f"Found {len(consts)} crypto patterns: {', '.join(str(c)[:40] for c in consts[:5])}.",
                "tags": ["crypto"],
                "priority": 5,
            })
    
    # Found C2 indicators
    if tool == "string_ops" and any(a in action for a in ("find_urls", "find_ips", "find_c2")):
        hits = result.get("matches", result.get("results", []))
        if hits and len(hits) > 0:
            entries.append({
                "category": "c2",
                "name": "C2/network indicators found",
                "notes": f"Found {len(hits)} URL/IP/C2 indicators.",
                "tags": ["c2", "network", "critical"],
                "priority": 5,
            })
    
    return entries if entries else None


# ============================================================================
# Ghost Tool Chains
# ============================================================================

# Maps trigger (tool, action) to companion tool calls to pre-execute
GHOST_CHAINS: Dict[Tuple[str, str], List[Tuple[str, dict]]] = {
    # Decompile triggers
    ("code", "decompile"): [
        ("code", {"action": "callers", "addr": "__ADDR__"}),
        ("code", {"action": "callees", "addr": "__ADDR__"}),
        ("code", {"action": "strings_in_func", "addr": "__ADDR__"}),
    ],
    ("code", "semantic_decompile"): [
        ("code", {"action": "callers", "addr": "__ADDR__"}),
        ("code", {"action": "callees", "addr": "__ADDR__"}),
        ("ctree", {"action": "find_calls", "addr": "__ADDR__"}),
    ],
    # Function info triggers
    ("funcs", "info"): [
        ("code", {"action": "blocks", "addr": "__ADDR__"}),
        ("code", {"action": "xrefs_to", "addr": "__ADDR__"}),
    ],
    # Data listing triggers
    ("data", "strings"): [
        ("string_ops", {"action": "find_urls", "context": "data_strings_result"}),
        ("string_ops", {"action": "find_ips", "context": "data_strings_result"}),
    ],
    ("data", "imports"): [
        ("imports_deep", {"action": "summary", "context": "data_imports_result"}),
    ],
    # Import analysis triggers
    ("imports_deep", "thunks"): [
        ("imports_deep", {"action": "delay", "context": "imports_deep_result"}),
    ],
    # Search triggers
    ("search", "find"): [
        ("search", {"action": "name", "query": "__QUERY__"}),
    ],
}

# Tools that ghost chains should NOT trigger for (to avoid infinite recursion)
_NO_GHOST_CHAIN_FOR = {"binary_info", "idb", "calc", "wiki", "memory", "debug", "misc"}


def get_ghost_chain(tool: str, action: str, args: dict) -> List[Tuple[str, dict]]:
    """
    Get list of companion tool calls to pre-execute for a given trigger.
    
    Returns empty list if no ghost chain defined.
    """
    if tool in _NO_GHOST_CHAIN_FOR:
        return []
    
    chain = GHOST_CHAINS.get((tool, action), [])
    if not chain:
        return []
    
    result = []
    addr = args.get("addr", "")
    query = args.get("query") or args.get("pattern", "")
    
    for ghost_tool, ghost_args in chain:
        resolved_args = dict(ghost_args)
        # Substitute placeholders
        for k, v in resolved_args.items():
            if isinstance(v, str):
                v = v.replace("__ADDR__", str(addr))
                v = v.replace("__QUERY__", str(query))
                resolved_args[k] = v
            if v == "__ADDR__":
                resolved_args[k] = addr
            if v == "__QUERY__":
                resolved_args[k] = query
        
        # Skip if the resolved args don't have the required addr/query
        if not addr and any(v == "" for k, v in resolved_args.items() if k in ("addr", "query", "pattern")):
            continue
        
        result.append((ghost_tool, resolved_args))
    
    return result


# ── KG integration ────────────────────────────────────────────────────────────

# Map behavior tags to system names for KG auto-population
_TAG_TO_SYSTEM = {
    "crypto_symmetric": "Crypto subsystem",
    "crypto_asymmetric": "Crypto subsystem",
    "crypto_hash": "Crypto subsystem",
    "network_http": "Network stack",
    "network_socket": "Network stack",
    "network_dns": "Network stack",
    "memory_alloc": "Memory management",
    "memory_free": "Memory management",
    "file_io": "File I/O",
    "process_exec": "Process management",
    "auth_check": "Authentication",
    "auth_bypass": "Authentication",
    "firmware_init": "Firmware initialization",
    "interrupt_handler": "Interrupt handling",
    "dma_transfer": "DMA subsystem",
}


def _update_kg_from_hypothesis(db_path: str, addr: str,
                                behavior_tags: list, hypotheses: list) -> None:
    """
    When auto-hypothesis fires, update the KnowledgeGraph:
    - Add addr to the appropriate system (based on behavior_tags)
    - If a gap matches the behavior, mark it as having a candidate
    """
    if not db_path or not addr:
        return
    try:
        import importlib.util, os as _os
        _kg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                 "knowledge_graph.py")
        if not _os.path.exists(_kg_path):
            return
        spec = importlib.util.spec_from_file_location("_re_kg", _kg_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        kg = mod.KnowledgeGraph(db_path)
    except Exception:
        return

    # Add addr to matching system
    for tag in behavior_tags:
        sys_name = _TAG_TO_SYSTEM.get(tag)
        if not sys_name:
            continue
        # Find or create the system
        existing = [s for s in kg.list_systems() if s["name"] == sys_name]
        if existing:
            kg.add_member_to_system(existing[0]["id"], addr)
        else:
            kg.add_system(sys_name, members=[addr],
                          description=f"Auto-detected from {tag}",
                          tags=[tag], confidence=0.6)
        break  # one system per hypothesis

    # Check if any open gap matches these behavior tags
    try:
        gaps = kg.list_gaps(resolved=False)
        for gap in gaps:
            hints_text = " ".join(gap.get("hints", [])).lower()
            expected_text = gap.get("expected", "").lower()
            for tag in behavior_tags:
                if tag.replace("_", " ") in expected_text or tag in hints_text:
                    kg.add_gap_candidate(gap["id"], addr)
                    break
    except Exception:
        pass
