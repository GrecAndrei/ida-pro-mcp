"""
Signal injection and auto-blackboard helpers extracted from response_enrichment.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Common Windows API patterns used by hypothesis generation.
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


# ==========================================================================
# Session Resume Injection
# ==========================================================================


def build_session_resume(
    session_manager,
    sid: str,
    blackboard_entries: Optional[List[dict]] = None,
) -> Optional[dict]:
    """Build a session resume context block for reconnecting LLMs."""
    if not session_manager or not sid:
        return None

    session = session_manager.get_session(sid)
    if not session:
        return None

    resume = {}
    skills_data = session_manager._load_skills(sid)
    activity_log = skills_data.get("activity_log", [])
    hypotheses = skills_data.get("hypotheses", [])
    skills = skills_data.get("skills", {})

    decompiled = set()
    for entry in activity_log:
        if entry.get("action") in ("decompile", "semantic_decompile"):
            addr = ""
            raw = entry.get("result", "")
            if isinstance(raw, str):
                r = raw.strip()
                if r.startswith("0x"):
                    addr = r
                elif r.startswith("{"):
                    try:
                        parsed = json.loads(r)
                        addrs = parsed.get("addresses") if isinstance(parsed, dict) else None
                        if isinstance(addrs, list) and addrs:
                            first = str(addrs[0]).strip()
                            if first.startswith("0x"):
                                addr = first
                    except Exception:
                        pass
            elif isinstance(raw, dict):
                addrs = raw.get("addresses")
                if isinstance(addrs, list) and addrs:
                    first = str(addrs[0]).strip()
                    if first.startswith("0x"):
                        addr = first
            if addr:
                decompiled.add(addr)

    if decompiled:
        resume["previously_decompiled"] = sorted(list(decompiled))

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

    high_q_skills = {k: v for k, v in skills.items() if v.get("q_value", 0) > 0.5}
    if high_q_skills:
        resume["available_skills"] = [
            {"name": v.get("name", k), "description": v.get("description", "")[:100]}
            for k, v in list(high_q_skills.items())[:5]
        ]

    total_actions = len(activity_log)
    if total_actions > 0:
        resume["analysis_progress"] = {
            "total_actions": total_actions,
            "phase": session.phase,
            "estimated_completion": f"{min(99, total_actions // 5)}% of typical analysis",
        }

    notebook = getattr(session_manager, '_load_notebook', lambda x: "")(sid)
    if notebook:
        last_lines = notebook.split("\n")[-10:]
        resume["last_notebook_entry"] = "\n".join(last_lines)

    return resume if resume else None


# ==========================================================================
# Auto-Hypothesis Engine
# ==========================================================================

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


# ==========================================================================
# Auto-Blackboard
# ==========================================================================


def auto_blackboard_write(
    tool: str,
    action: str,
    result: dict,
    addr: Optional[str] = None,
) -> Optional[List[dict]]:
    entries = []

    if not result or not result.get("ok"):
        return None

    if tool == "code" and action in ("decompile", "semantic_decompile") and addr:
        from .response_enrichment import digest_decompiled

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

        behavior_tags = digest.get("behavior_tags", [])
        if behavior_tags:
            hypotheses = generate_hypotheses(tool, action, result, addr, behavior_tags)
            if hypotheses:
                try:
                    from .blackboard_store import BlackboardStore
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
                    _update_kg_from_hypothesis(store.db_path, addr or '', behavior_tags, hypotheses)
                except Exception:
                    pass

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


# ==========================================================================
# Ghost Tool Chains
# ==========================================================================

GHOST_CHAINS: Dict[Tuple[str, str], List[Tuple[str, dict]]] = {
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
    ("funcs", "info"): [
        ("code", {"action": "blocks", "addr": "__ADDR__"}),
        ("code", {"action": "xrefs_to", "addr": "__ADDR__"}),
    ],
    ("data", "strings"): [
        ("string_ops", {"action": "find_urls", "context": "data_strings_result"}),
        ("string_ops", {"action": "find_ips", "context": "data_strings_result"}),
    ],
    ("data", "imports"): [
        ("imports_deep", {"action": "summary", "context": "data_imports_result"}),
    ],
    ("imports_deep", "thunks"): [
        ("imports_deep", {"action": "delay", "context": "imports_deep_result"}),
    ],
    ("search", "find"): [
        ("search", {"action": "name", "query": "__QUERY__"}),
    ],
}

_NO_GHOST_CHAIN_FOR = {"binary_info", "idb", "calc", "wiki", "memory", "debug", "misc"}


def get_ghost_chain(tool: str, action: str, args: dict) -> List[Tuple[str, dict]]:
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
        for k, v in resolved_args.items():
            if isinstance(v, str):
                v = v.replace("__ADDR__", str(addr))
                v = v.replace("__QUERY__", str(query))
                resolved_args[k] = v
            if v == "__ADDR__":
                resolved_args[k] = addr
            if v == "__QUERY__":
                resolved_args[k] = query
        if not addr and any(v == "" for k, v in resolved_args.items() if k in ("addr", "query", "pattern")):
            continue
        result.append((ghost_tool, resolved_args))

    return result


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

    for tag in behavior_tags:
        sys_name = _TAG_TO_SYSTEM.get(tag)
        if not sys_name:
            continue
        existing = [s for s in kg.list_systems() if s["name"] == sys_name]
        if existing:
            kg.add_member_to_system(existing[0]["id"], addr)
        else:
            kg.add_system(sys_name, members=[addr],
                          description=f"Auto-detected from {tag}",
                          tags=[tag], confidence=0.6)
        break

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


_TAINT_SOURCES = frozenset({"recv", "recvfrom", "read", "fread", "fgets", "gets",
                             "getenv", "scanf", "ReadFile", "RegQueryValue"})
_DANGEROUS_SINKS = frozenset({"memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
                               "gets", "system", "execve", "popen", "printf"})


def build_signal_directives(
    tool_name: str,
    action_name: str,
    payload: Dict,
    func_addr: str = "",
) -> List[Dict]:
    """
    Examine a tool response payload and return a list of specific, actionable
    directives — exact tool calls with addresses — that the LLM should execute next.

    Each directive:
      {"priority": "high|medium", "call": "tool(action='...', addr='...')", "reason": "..."}

    Priority high = the LLM MUST do this before concluding.
    Priority medium = strongly recommended.
    """
    directives: List[Dict] = []
    addr = func_addr or ""

    # --- code(decompile/smart_decompile/analyze/explain) ---
    if tool_name == "code" and action_name in (
        "decompile", "smart_decompile", "analyze", "explain", "semantic_decompile"
    ):
        pseudo = payload.get("pseudocode") or payload.get("code") or ""
        api_calls = payload.get("api_calls", [])
        dangerous = payload.get("dangerous_patterns", [])
        behavior_tags = payload.get("behavior_tags", [])

        # Taint: network input + dangerous sink
        sources_found = [s for s in _TAINT_SOURCES if s in pseudo or s in api_calls]
        sinks_found = [s for s in _DANGEROUS_SINKS if s in pseudo or s in api_calls]
        if sources_found and sinks_found and addr:
            directives.append({
                "priority": "high",
                "call": f"taint(action='trace', addr='{addr}', source='{sources_found[0]}')",
                "reason": f"Network input ({sources_found[0]}) + dangerous sink ({sinks_found[0]}) detected — trace data flow NOW",
            })

        # Dangerous patterns: explain them
        if (dangerous or sinks_found) and addr:
            directives.append({
                "priority": "high",
                "call": f"llm_helpers(action='dangerous_pattern_explainer', addr='{addr}')",
                "reason": f"Dangerous patterns found: {', '.join(dangerous[:3] or sinks_found[:3])}",
            })

        # Crypto signals
        crypto_hints = payload.get("crypto_hints", [])
        if crypto_hints and addr:
            directives.append({
                "priority": "medium",
                "call": f"crypto_id(action='identify', addr='{addr}')",
                "reason": f"Crypto signals: {', '.join(crypto_hints[:3])}",
            })

        # No blackboard entry yet
        bb_ctx = payload.get("blackboard_context")
        if not bb_ctx and addr:
            directives.append({
                "priority": "medium",
                "call": f"blackboard(action='write', addr='{addr}', category='hypothesis', title='...', confidence=0.7)",
                "reason": "No blackboard entry for this function — record findings now to enable label propagation",
            })

        # API contract if many callers
        callers = payload.get("callers", [])
        n_callers = len(callers) if isinstance(callers, list) else 0
        if n_callers >= 5 and addr:
            directives.append({
                "priority": "medium",
                "call": f"llm_helpers(action='api_contract_extractor', addr='{addr}')",
                "reason": f"Hot function ({n_callers} callers) — extract its contract to understand all call sites",
            })

    # --- taint(report/trace) with findings ---
    elif tool_name == "taint" and action_name in ("report", "trace"):
        findings = payload.get("findings", payload.get("vulns", []))
        if findings:
            top = findings[0]
            sink_addr = top.get("sink_addr") or top.get("path", [None])[-1] or ""
            vuln_type = top.get("vuln_type", "vulnerability")
            directives.append({
                "priority": "high",
                "call": f"llm_helpers(action='dangerous_pattern_explainer', addr='{sink_addr or addr}')",
                "reason": f"{vuln_type} confirmed — get full exploitation analysis",
            })
            if sink_addr:
                directives.append({
                    "priority": "high",
                    "call": f"blackboard(action='write', addr='{sink_addr}', category='vuln', "
                            f"title='{vuln_type} at {sink_addr}', confidence=0.85)",
                    "reason": "Record confirmed vulnerability to blackboard",
                })

    # --- search(find/nl/behavior/decompiled) with results ---
    elif tool_name == "search" and action_name in ("find", "nl", "behavior", "decompiled"):
        items = payload.get("items", [])
        if items:
            top_addr = items[0].get("addr") or items[0].get("address") or items[0].get("ea", "")
            if top_addr:
                directives.append({
                    "priority": "medium",
                    "call": f"code(action='smart_decompile', addrs='{top_addr}')",
                    "reason": f"Top search result at {top_addr} — smart_decompile for full analysis",
                })

    # --- blackboard(frontier) ---
    elif tool_name == "blackboard" and action_name == "frontier":
        items = payload.get("items", [])
        if items:
            top = items[0]
            top_addr = top.get("addr", "")
            if top_addr:
                directives.append({
                    "priority": "high",
                    "call": f"code(action='smart_decompile', addrs='{top_addr}')",
                    "reason": f"Highest-priority frontier target: {top.get('name', top_addr)} "
                              f"(score={top.get('score', 0):.3f})",
                })

    # --- blackboard(coverage) with low coverage ---
    elif tool_name == "blackboard" and action_name == "coverage":
        pct = payload.get("coverage_pct", 100)
        unvisited = payload.get("unvisited", 0)
        if pct < 30 and unvisited > 0:
            directives.append({
                "priority": "high",
                "call": "blackboard(action='frontier', limit=10)",
                "reason": f"Only {pct}% coverage ({unvisited} unvisited functions) — get frontier targets",
            })

    # --- classify(function) or classify(all_functions) ---
    elif tool_name == "classify":
        if action_name == "function":
            fn_addr = payload.get("address", addr)
            category = payload.get("category", "")
            if category in ("crypto", "network", "process_exec") and fn_addr:
                directives.append({
                    "priority": "medium",
                    "call": f"llm_helpers(action='function_role_classifier', addr='{fn_addr}')",
                    "reason": f"High-value category '{category}' — get full role classification",
                })

    # --- data(functions) — orient phase ---
    elif tool_name == "data" and action_name == "functions":
        total = payload.get("total", 0)
        if total > 50:
            directives.append({
                "priority": "medium",
                "call": "blackboard(action='coverage')",
                "reason": f"Binary has {total} functions — check coverage before choosing what to analyze",
            })
            directives.append({
                "priority": "medium",
                "call": "blackboard(action='frontier', limit=10)",
                "reason": "Get ranked list of most-promising unanalyzed functions",
            })
    elif tool_name == "idb" and action_name == "overview":
        if payload.get("firmware_detected"):
            directives.append({
                "priority": "high",
                "call": "firmware_view(action='triage_snapshot')",
                "reason": "Firmware-like binary detected — run one-shot load/vector/MMIO orientation first",
            })
            directives.append({
                "priority": "medium",
                "call": "llm_helpers(action='guided_analysis')",
                "reason": "Use guided firmware workflow so rebasing/entry-point steps are not skipped",
            })

    # --- firmware_view results ---
    elif tool_name == "firmware_view":
        if action_name == "scan_region":
            regions = payload.get("regions", [])
            code_regions = [r for r in regions if isinstance(r, dict) and "code" in str(r.get("type", "")).lower()]
            if regions:
                directives.append({
                    "priority": "high",
                    "call": "firmware_view(action='carve_plan')",
                    "reason": f"scan_region found {len(regions)} regions — get retyping plan before applying changes",
                })
                directives.append({
                    "priority": "medium",
                    "call": "firmware_view(action='pointer_sweep')",
                    "reason": "Find pointer tables and vtables in the scanned regions",
                })
        elif action_name == "carve_plan":
            directives.append({
                "priority": "high",
                "call": "firmware_view(action='smart_carve', apply=false)",
                "reason": "Dry-run the carve plan to preview what will be created",
            })
        elif action_name == "smart_carve" and not payload.get("applied", True):
            directives.append({
                "priority": "high",
                "call": "firmware_view(action='smart_carve', apply=true)",
                "reason": "Dry-run complete — apply the carve plan to create functions/structs/strings",
            })
        elif action_name in ("smart_carve", "auto_retype") and payload.get("applied"):
            directives.append({
                "priority": "medium",
                "call": "search(action='func_by_sig', pattern='no_callers')",
                "reason": "After retyping, find interrupt handlers and entry points (no_callers functions)",
            })
            directives.append({
                "priority": "medium",
                "call": "taint(action='report')",
                "reason": "Check for MMIO/UART input → dangerous sink paths",
            })
        elif action_name == "detect_load_address":
            candidates = payload.get("candidates", [])
            if candidates:
                best = candidates[0]
                directives.append({
                    "priority": "high",
                    "call": f"firmware_view(action='detect_vector_table')",
                    "reason": f"Load address identified as {best.get('base')} ({best.get('method')}) — now find entry points",
                })
            elif not candidates:
                directives.append({
                    "priority": "medium",
                    "call": "firmware_view(action='scan_region')",
                    "reason": "Could not determine load address — profile regions to find structure",
                })

        elif action_name == "detect_vector_table":
            entry_points = payload.get("entry_points", [])
            vectors = payload.get("vectors", [])
            reset_handler = next((v.get("handler") for v in vectors if "Reset" in v.get("name", "")), None)
            if reset_handler:
                directives.append({
                    "priority": "high",
                    "call": f"code(action='smart_decompile', addrs='{reset_handler}')",
                    "reason": f"Reset_Handler at {reset_handler} — this is the firmware entry point",
                })
            if entry_points:
                directives.append({
                    "priority": "high",
                    "call": "firmware_view(action='detect_mmio')",
                    "reason": "Entry points found — now identify MMIO peripheral registers",
                })

        elif action_name == "detect_mmio":
            peripherals = payload.get("peripherals", [])
            chip = payload.get("likely_chip_family", "")
            if peripherals:
                directives.append({
                    "priority": "high",
                    "call": "taint(action='report')",
                    "reason": f"MMIO peripherals identified ({chip}) — trace UART/DMA inputs to dangerous sinks",
                })
                directives.append({
                    "priority": "medium",
                    "call": "firmware_view(action='scan_region')",
                    "reason": "MMIO map complete — now profile binary regions for structure",
                })
        elif action_name == "triage_snapshot":
            summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
            vectors = int(summary.get("vector_entries", 0) or 0)
            mmio = int(summary.get("mmio_regions", 0) or 0)
            load = int(summary.get("load_candidates", 0) or 0)
            if load == 0:
                directives.append({
                    "priority": "high",
                    "call": "firmware_view(action='scan_region')",
                    "reason": "No load-address candidates detected — profile regions to recover structure",
                })
            if vectors > 0:
                directives.append({
                    "priority": "high",
                    "call": "search(action='func_by_sig', pattern='no_callers')",
                    "reason": "Vector entries found — enumerate likely handlers/entry points for triage",
                })
            if mmio > 0:
                directives.append({
                    "priority": "high",
                    "call": "taint(action='report')",
                    "reason": "MMIO discovered — trace peripheral input flow to risky sinks",
                })
            else:
                directives.append({
                    "priority": "medium",
                    "call": "firmware_view(action='detect_mmio')",
                    "reason": "MMIO map missing — run peripheral discovery to orient driver analysis",
                })

        elif action_name == "pointer_sweep":
            tables = payload.get("tables", payload.get("count", 0))
            if tables:
                directives.append({
                    "priority": "medium",
                    "call": "firmware_view(action='table_candidates', limit=50)",
                    "reason": f"Pointer sweep found tables — identify dispatch/jump tables",
                })

    return directives
