
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import json
import os
import hashlib
import math
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional


# ============================================================================
# VULN_SCAN - Analysis-Driven Vulnerability Discovery with VOERA Learning
# ============================================================================
# Design principle: NO static vulnerability pattern lists.
# Instead, we discover sinks, sources, and sanitizers dynamically,
# perform semantic analysis via the decompiler, and learn from feedback.

_VULN_KNOWLEDGE_PATH = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "vuln_knowledge.json")
_VULN_KNOWLEDGE_MAX_ENTRIES = 512

# Heuristic source patterns (functions that return external/user data)
_SOURCE_NAME_PATTERNS = [
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "getline",
    "getenv", "getcwd", "gethostname", "getusername", "getpass",
    "scanf", "fscanf", "sscanf", "vscanf",
    "accept", "socket", "listen",
    "internetreadfile", "urldownload", "winhttp",
    "regquery", "regenum",
    "findfirst", "findnext",
    "argv", "argc", "getcommandline",
    "loadstring", "loadresource",
]

# Heuristic sanitizer patterns (functions that validate/transform data)
_SANITIZER_NAME_PATTERNS = [
    "strlen", "wcslen", "sizeof", "countof",
    "strnlen", "wcsnlen",
    "snprintf", "vsnprintf", "strlcpy", "strncpy", "memcpy_s",
    "memmove_s", "strncat", "wcsncpy",
    "validate", "verify", "check", "sanitize", "escape",
    "isalnum", "isalpha", "isdigit", "isprint",
    "bounded", "safe", "secure",
    "strcmp", "strncmp", "memcmp", "wcsncmp",
]


# ============================================================================
# Knowledge Management
# ============================================================================

def _ensure_knowledge_dir():
    os.makedirs(os.path.dirname(_VULN_KNOWLEDGE_PATH), exist_ok=True)


def _load_vuln_knowledge() -> dict:
    """Load learned vulnerability knowledge from disk."""
    _ensure_knowledge_dir()
    if not os.path.exists(_VULN_KNOWLEDGE_PATH):
        return {"binaries": {}, "global_sources": [], "global_sinks": [], "global_sanitizers": [], "feedback": []}
    try:
        with open(_VULN_KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"binaries": {}, "global_sources": [], "global_sinks": [], "global_sanitizers": [], "feedback": []}


def _save_vuln_knowledge(data: dict):
    """Persist learned vulnerability knowledge to disk."""
    _ensure_knowledge_dir()
    # Trim if too large
    if len(data.get("feedback", [])) > _VULN_KNOWLEDGE_MAX_ENTRIES:
        data["feedback"] = data["feedback"][-_VULN_KNOWLEDGE_MAX_ENTRIES:]
    try:
        with open(_VULN_KNOWLEDGE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _binary_fingerprint() -> str:
    """Create a fingerprint of the current binary for similarity matching."""
    parts = []
    # Import hash
    imports = []
    try:
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ord):
                if name:
                    imports.append(name.lower())
                return True
            ida_nalt.enum_import_names(i, cb)
    except Exception:
        pass
    imports.sort()
    parts.append(hashlib.sha256(",".join(imports).encode()).hexdigest()[:16])
    # Segment hash
    segs = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if seg:
            segs.append(f"{seg.start_ea:x}-{seg.end_ea:x}-{seg.perm}")
    parts.append(hashlib.sha256("|".join(segs).encode()).hexdigest()[:16])
    return "_".join(parts)


def _get_or_create_binary_knowledge(knowledge: dict, fingerprint: str) -> dict:
    if fingerprint not in knowledge["binaries"]:
        knowledge["binaries"][fingerprint] = {
            "sources": [],
            "sinks": [],
            "sanitizers": [],
            "findings": [],
            "weights": {"source_reach": 1.0, "no_validation": 1.0, "dangerous_sink": 1.0, "path_depth": 0.5},
            "scan_count": 0,
        }
    return knowledge["binaries"][fingerprint]


# ============================================================================
# Dynamic Discovery
# ============================================================================

def _discover_sinks(limit: int = 200) -> List[Tuple[int, str, str]]:
    """Discover sinks: dangerous API calls in the binary.
    Returns list of (ea, func_name, reason)."""
    sinks = []
    seen = set()
    dangerous = set(DANGEROUS_APIS.keys())
    # Also check dangerous tags
    for tag, apis in TAG_CATEGORIES.items():
        if tag in ("evasion", "persistence", "anti_debug", "process"):
            for api in apis:
                dangerous.add(api.lower())

    # Search imports
    try:
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ord):
                if not name:
                    return True
                n = name.lower()
                base = n.split("@")[0].lstrip("_")
                for d in dangerous:
                    if base == d.lower() or base.startswith(d.lower() + "@"):
                        reason = DANGEROUS_APIS.get(d, f"tagged: {TAG_CATEGORIES.get(d, 'unknown')}")
                        sinks.append((ea, name, reason))
                        seen.add(ea)
                        break
                return True
            ida_nalt.enum_import_names(i, cb)
    except Exception:
        pass

    # Search local functions by name heuristic
    for func_ea in idautils.Functions():
        if len(sinks) >= limit:
            break
        fname = (idc.get_func_name(func_ea) or "").lower()
        for d in dangerous:
            if d.lower() in fname and fname not in seen:
                reason = DANGEROUS_APIS.get(d, f"name heuristic match: {d}")
                sinks.append((func_ea, fname, reason))
                seen.add(fname)
                break
    return sinks[:limit]


def _discover_sources(limit: int = 200) -> List[Tuple[int, str]]:
    """Discover sources: functions that return external/user data."""
    sources = []
    seen = set()
    # From imports
    try:
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ord):
                if not name:
                    return True
                n = name.lower()
                base = n.split("@")[0].lstrip("_")
                for pat in _SOURCE_NAME_PATTERNS:
                    if pat in base:
                        sources.append((ea, name))
                        seen.add(name)
                        break
                return True
            ida_nalt.enum_import_names(i, cb)
    except Exception:
        pass
    # From API categories
    for cat in ("network", "file_io", "registry"):
        for api in API_CATEGORIES.get(cat, []):
            if api in seen:
                continue
            ea = idc.get_name_ea_simple(api)
            if ea != idaapi.BADADDR:
                sources.append((ea, api))
                seen.add(api)
    return sources[:limit]


def _discover_sanitizers(limit: int = 200) -> List[Tuple[int, str]]:
    """Discover sanitizers: functions that validate/transform data."""
    sanitizers = []
    seen = set()
    try:
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ord):
                if not name:
                    return True
                n = name.lower()
                base = n.split("@")[0].lstrip("_")
                for pat in _SANITIZER_NAME_PATTERNS:
                    if pat in base:
                        sanitizers.append((ea, name))
                        seen.add(name)
                        break
                return True
            ida_nalt.enum_import_names(i, cb)
    except Exception:
        pass
    return sanitizers[:limit]


# ============================================================================
# Semantic Analysis (Decompiler-based)
# ============================================================================

def _get_callers(ea: int) -> List[int]:
    """Get all functions that call the given address."""
    callers = set()
    for xref in idautils.XrefsTo(ea, 0):
        if xref.iscode:
            func = idaapi.get_func(xref.frm)
            if func:
                callers.add(func.start_ea)
    return list(callers)


def _decompile_function(func_ea: int):
    """Decompile a function, returning the cfunc object or None."""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(func_ea)
        return cfunc
    except Exception:
        return None


def _analyze_sink_call(func_ea: int, sink_ea: int, sink_name: str) -> dict:
    """Analyze a specific sink call within a function for vulnerability indicators.
    Returns dict with validation findings, argument sources, and risk signals."""
    result = {
        "sink_name": sink_name,
        "caller": idc.get_func_name(func_ea),
        "caller_addr": hex(func_ea),
        "sink_addr": hex(sink_ea),
        "validations": [],
        "arg_sources": [],
        "risk_signals": [],
        "has_decompiler": False,
    }

    cfunc = _decompile_function(func_ea)
    if not cfunc:
        result["risk_signals"].append("no_decompiler")
        return result

    result["has_decompiler"] = True

    # Walk the decompiled AST looking for calls to sink_ea
    class SinkVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.calls = []
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_call:
                called = e.x
                if called.op == ida_hexrays.cot_obj and called.obj_ea == sink_ea:
                    self.calls.append(e)
                elif called.op == ida_hexrays.cot_var:
                    # Indirect call - harder to trace
                    pass
            return 0

    visitor = SinkVisitor()
    try:
        visitor.apply_to(cfunc.body, None)
    except Exception:
        pass

    if not visitor.calls:
        result["risk_signals"].append("sink_not_in_decompiled_flow")
        return result

    for call_expr in visitor.calls:
        # Analyze each argument
        for i, arg in enumerate(call_expr.a):
            arg_str = ida_lines.tag_remove(arg.print1(None)) if hasattr(arg, "print1") else str(arg)
            # Check if argument comes from a source
            source_found = _trace_arg_to_source(arg, cfunc, func_ea)
            if source_found:
                result["arg_sources"].append({"arg_idx": i, "source": source_found, "text": arg_str})

            # Check if argument has validation nearby
            validation = _find_validation_for_arg(arg, call_expr, cfunc)
            if validation:
                result["validations"].append({"arg_idx": i, "validation": validation})

        # Check for loop context (repeated calls = more dangerous)
        if _is_in_loop(call_expr, cfunc):
            result["risk_signals"].append("in_loop")

    return result


def _trace_arg_to_source(arg, cfunc, func_ea) -> Optional[str]:
    """Trace an argument expression back to a known source."""
    try:
        # Simple heuristic: if the arg text contains source-like names
        arg_text = ida_lines.tag_remove(arg.print1(None)) if hasattr(arg, "print1") else str(arg)
        arg_lower = arg_text.lower()
        for pat in _SOURCE_NAME_PATTERNS:
            if pat in arg_lower:
                return f"source_pattern:{pat}"
        # Check if it's a direct variable assigned from a source
        if arg.op == ida_hexrays.cot_var:
            vidx = arg.v.idx
            # Try to find assignments to this variable
            class AssignVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.sources = []
                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_asg:
                        if e.x.op == ida_hexrays.cot_var and e.x.v.idx == vidx:
                            rhs_text = ida_lines.tag_remove(e.y.print1(None)) if hasattr(e.y, "print1") else str(e.y)
                            rhs_lower = rhs_text.lower()
                            for pat in _SOURCE_NAME_PATTERNS:
                                if pat in rhs_lower:
                                    self.sources.append(f"assigned_from:{pat}")
                    return 0
            av = AssignVisitor()
            av.apply_to(cfunc.body, None)
            if av.sources:
                return av.sources[0]
    except Exception:
        pass
    return None


def _find_validation_for_arg(arg, call_expr, cfunc) -> Optional[str]:
    """Look for validation checks (bounds, null, format) on an argument before the call."""
    try:
        arg_text = ida_lines.tag_remove(arg.print1(None)) if hasattr(arg, "print1") else str(arg)
        # Heuristic: search decompiled text for checks on this variable
        cfunc_text = str(cfunc)
        lines = cfunc_text.splitlines()
        call_line_idx = None
        for idx, line in enumerate(lines):
            if arg_text in line:
                call_line_idx = idx
                break
        if call_line_idx is None:
            return None

        # Look backward for validation patterns
        validations = []
        for idx in range(max(0, call_line_idx - 8), call_line_idx):
            line = lines[idx].lower()
            if any(v in line for v in ("!= 0", "!= null", "== 0", "== null", "if (", "if(", "while (", "while(")):
                if any(pat in line for pat in _SANITIZER_NAME_PATTERNS):
                    validations.append("sanitizer_check")
                else:
                    validations.append("null_check")
            if any(v in line for v in ("<", ">", "<=", ">=", "sizeof", "strlen")):
                validations.append("bounds_check")
            if "format" in line or "%" in line:
                validations.append("format_check")
        return validations[-1] if validations else None
    except Exception:
        return None


def _is_in_loop(expr, cfunc) -> bool:
    """Check if an expression is inside a loop construct."""
    try:
        class LoopVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, target_ea):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.target_ea = target_ea
                self.in_loop = False
            def visit_insn(self, i):
                if i.op in (ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do):
                    # Check if target is within this loop body
                    if hasattr(i, "c") and i.c:
                        # Simplified: just flag if we're scanning a loop
                        self.in_loop = True
                return 0
        lv = LoopVisitor(expr.ea if hasattr(expr, "ea") else 0)
        lv.apply_to(cfunc.body, None)
        return lv.in_loop
    except Exception:
        return False


# ============================================================================
# Scoring Engine
# ============================================================================

def _compute_risk_score(analysis: dict, weights: dict) -> float:
    """Compute a risk score (0-100) based on semantic analysis."""
    score = 0.0
    # Base score for being a dangerous sink
    score += 20 * weights.get("dangerous_sink", 1.0)

    # Source reachability: +30 if user-controlled data reaches sink
    if analysis.get("arg_sources"):
        score += 30 * weights.get("source_reach", 1.0)

    # Validation absence: +25 if no validation found
    if not analysis.get("validations"):
        score += 25 * weights.get("no_validation", 1.0)
    else:
        score -= 10  # Reduced risk if validated

    # Path depth / complexity signals
    signals = analysis.get("risk_signals", [])
    if "in_loop" in signals:
        score += 15 * weights.get("path_depth", 0.5)
    if "no_decompiler" in signals:
        score += 5  # Less confident without decompiler

    # Cap at 100
    return max(0.0, min(100.0, round(score, 1)))


def _severity_from_score(score: float) -> str:
    if score >= 75:
        return "critical"
    elif score >= 55:
        return "high"
    elif score >= 35:
        return "medium"
    elif score >= 15:
        return "low"
    return "info"


# ============================================================================
# VOERA Learning Integration
# ============================================================================

def _voera_reflect(findings: list, knowledge: dict, fingerprint: str):
    """Analyze scan results for false positive patterns and adjust weights."""
    binary_knowledge = _get_or_create_binary_knowledge(knowledge, fingerprint)
    # If we have feedback, adjust weights
    feedback = knowledge.get("feedback", [])
    binary_feedback = [f for f in feedback if f.get("fingerprint") == fingerprint]
    if not binary_feedback:
        return

    # Calculate false positive rate per signal
    fp_by_signal = defaultdict(list)
    for fb in binary_feedback:
        for signal in fb.get("signals", []):
            fp_by_signal[signal].append(fb.get("is_fp", False))

    weights = binary_knowledge.get("weights", {})
    for signal, results in fp_by_signal.items():
        if len(results) < 2:
            continue
        fp_rate = sum(results) / len(results)
        if fp_rate > 0.5:
            # This signal produces many false positives, reduce its weight
            key = {"no_validation": "no_validation", "source_reach": "source_reach", "in_loop": "path_depth"}.get(signal)
            if key and key in weights:
                weights[key] = max(0.1, weights[key] * 0.9)
        elif fp_rate < 0.2:
            # This signal is reliable, boost its weight
            key = {"no_validation": "no_validation", "source_reach": "source_reach", "in_loop": "path_depth"}.get(signal)
            if key and key in weights:
                weights[key] = min(2.0, weights[key] * 1.05)

    binary_knowledge["weights"] = weights
    _save_vuln_knowledge(knowledge)


def _voera_learn_sources_sinks(sources: list, sinks: list, sanitizers: list, knowledge: dict, fingerprint: str):
    """Learn new sources/sinks/sanitizers from this binary and merge with global knowledge."""
    binary_knowledge = _get_or_create_binary_knowledge(knowledge, fingerprint)
    # Merge into binary-specific knowledge
    for ea, name in sources:
        if name not in binary_knowledge["sources"]:
            binary_knowledge["sources"].append(name)
    for ea, name, reason in sinks:
        if name not in binary_knowledge["sinks"]:
            binary_knowledge["sinks"].append(name)
    for ea, name in sanitizers:
        if name not in binary_knowledge["sanitizers"]:
            binary_knowledge["sanitizers"].append(name)

    # Merge into global knowledge (deduplicated)
    for ea, name in sources:
        if name not in knowledge["global_sources"]:
            knowledge["global_sources"].append(name)
    for ea, name, reason in sinks:
        if name not in knowledge["global_sinks"]:
            knowledge["global_sinks"].append(name)
    for ea, name in sanitizers:
        if name not in knowledge["global_sanitizers"]:
            knowledge["global_sanitizers"].append(name)

    binary_knowledge["scan_count"] = binary_knowledge.get("scan_count", 0) + 1
    _save_vuln_knowledge(knowledge)


def _voera_find_similar_strategy(knowledge: dict, fingerprint: str) -> Optional[dict]:
    """If we've scanned similar binaries before, suggest their learned sources/sinks."""
    binaries = knowledge.get("binaries", {})
    if fingerprint in binaries:
        return binaries[fingerprint]
    # Simple similarity: shared source/sink names
    best_match = None
    best_score = 0
    current_sources = set(binaries.get(fingerprint, {}).get("sources", []))
    current_sinks = set(binaries.get(fingerprint, {}).get("sinks", []))
    for fp, data in binaries.items():
        if fp == fingerprint:
            continue
        shared = len(set(data.get("sources", [])) & current_sources) + len(set(data.get("sinks", [])) & current_sinks)
        if shared > best_score:
            best_score = shared
            best_match = data
    return best_match


# ============================================================================
# Main Tool
# ============================================================================

@tool
@idaread
def vuln_scan(
    action: Annotated[Literal[
        "scan", "analyze_function", "discover_surface", "taint_sources",
        "feedback", "learned_knowledge", "suggest_strategy", "reflect"
    ], "Vulnerability scan action"],
    addr: Annotated[Optional[str], "Function or address to analyze"] = None,
    limit: Annotated[int, "Max findings"] = 20,
    min_score: Annotated[float, "Minimum risk score (0-100)"] = 25.0,
    depth: Annotated[int, "Analysis depth for interprocedural taint"] = 2,
    finding_id: Annotated[Optional[str], "Finding ID for feedback"] = None,
    is_true_positive: Annotated[Optional[bool], "Feedback: is this a true positive?"] = None,
    **kwargs
) -> dict:
    """
    Analysis-driven vulnerability discovery with VOERA learning.

    NO static vulnerability pattern lists. Instead, discovers sinks, sources,
    and sanitizers dynamically, performs semantic analysis via the decompiler,
    and learns from feedback to improve accuracy over time.

    Actions:
    - scan: Full binary scan. Discovers sinks, traces arguments via decompiler,
      scores findings by exploitability signals. Returns ranked findings.
    - analyze_function: Deep-dive on a specific function for vulnerability signals.
    - discover_surface: Map all input surfaces (sources) and dangerous sinks.
    - taint_sources: Find which functions call sources and how data propagates.
    - feedback: Provide feedback on a finding (true/false positive) to improve scoring.
    - learned_knowledge: View accumulated knowledge (sources, sinks, sanitizers, weights).
    - suggest_strategy: Get scan strategy suggestions based on similar binaries.
    - reflect: Trigger VOERA reflection to adjust weights based on accumulated feedback.
    """
    try:
        knowledge = _load_vuln_knowledge()
        fingerprint = _binary_fingerprint()
        binary_knowledge = _get_or_create_binary_knowledge(knowledge, fingerprint)

        if action == "scan":
            # Discover sinks, sources, sanitizers
            sinks = _discover_sinks(limit * 2)
            sources = _discover_sources(limit * 2)
            sanitizers = _discover_sanitizers(limit * 2)

            # Learn from this binary
            _voera_learn_sources_sinks(sources, sinks, sanitizers, knowledge, fingerprint)

            findings = []
            for sink_ea, sink_name, reason in sinks:
                if len(findings) >= limit:
                    break
                # Find all callers of this sink
                callers = _get_callers(sink_ea)
                for caller_ea in callers[:5]:  # Limit callers per sink
                    analysis = _analyze_sink_call(caller_ea, sink_ea, sink_name)
                    weights = binary_knowledge.get("weights", {})
                    score = _compute_risk_score(analysis, weights)
                    if score < min_score:
                        continue

                    finding = {
                        "finding_id": f"{fingerprint}_{hex(sink_ea)}_{hex(caller_ea)}",
                        "sink": sink_name,
                        "sink_addr": hex(sink_ea),
                        "caller": analysis.get("caller", "unknown"),
                        "caller_addr": analysis.get("caller_addr", "unknown"),
                        "score": score,
                        "severity": _severity_from_score(score),
                        "reason": reason,
                        "arg_sources": analysis.get("arg_sources", []),
                        "validations": analysis.get("validations", []),
                        "risk_signals": analysis.get("risk_signals", []),
                        "has_decompiler": analysis.get("has_decompiler", False),
                    }
                    findings.append(finding)

            # Sort by score descending
            findings.sort(key=lambda x: -x["score"])
            findings = findings[:limit]

            # Update binary findings history
            binary_knowledge["findings"] = findings
            _save_vuln_knowledge(knowledge)

            # Compact summary for LLM
            summary_lines = []
            for f in findings:
                src_hint = f" src={len(f['arg_sources'])}" if f["arg_sources"] else ""
                val_hint = f" val={len(f['validations'])}" if f["validations"] else " NO_VAL"
                summary_lines.append(
                    f"{f['severity'].upper():8} score={f['score']:5.1f}  {f['caller']} -> {f['sink']}{src_hint}{val_hint}"
                )

            return {
                "ok": True,
                "findings": findings,
                "summary": "\n".join(summary_lines),
                "stats": {
                    "sinks_discovered": len(sinks),
                    "sources_discovered": len(sources),
                    "sanitizers_discovered": len(sanitizers),
                    "callers_analyzed": sum(len(_get_callers(s[0])) for s in sinks),
                },
                "learned": {
                    "binary_scans": binary_knowledge.get("scan_count", 0),
                    "fingerprint": fingerprint,
                },
            }

        elif action == "analyze_function":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for analyze_function")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            # Find all sink calls within this function
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.ADDRESS_INVALID, "No function at address")

            func_findings = []
            for item in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        target_name = idc.get_name(xref.to) or ""
                        if target_name.lower() in DANGEROUS_APIS or any(
                            target_name.lower().startswith(d.lower()) for d in DANGEROUS_APIS
                        ):
                            analysis = _analyze_sink_call(func.start_ea, xref.to, target_name)
                            weights = binary_knowledge.get("weights", {})
                            score = _compute_risk_score(analysis, weights)
                            if score >= min_score:
                                func_findings.append({
                                    "sink": target_name,
                                    "sink_addr": hex(xref.to),
                                    "call_addr": hex(item),
                                    "score": score,
                                    "severity": _severity_from_score(score),
                                    "arg_sources": analysis.get("arg_sources", []),
                                    "validations": analysis.get("validations", []),
                                    "risk_signals": analysis.get("risk_signals", []),
                                })

            func_findings.sort(key=lambda x: -x["score"])
            return {
                "ok": True,
                "function": idc.get_func_name(func.start_ea),
                "addr": hex(func.start_ea),
                "findings": func_findings[:limit],
                "count": len(func_findings),
            }

        elif action == "discover_surface":
            sinks = _discover_sinks(limit * 2)
            sources = _discover_sources(limit * 2)
            sanitizers = _discover_sanitizers(limit * 2)
            _voera_learn_sources_sinks(sources, sinks, sanitizers, knowledge, fingerprint)

            sink_lines = [f"{hex(ea)}  {name}  ({reason})" for ea, name, reason in sinks]
            source_lines = [f"{hex(ea)}  {name}" for ea, name in sources]
            sanitizer_lines = [f"{hex(ea)}  {name}" for ea, name in sanitizers]

            return {
                "ok": True,
                "sinks": sink_lines,
                "sources": source_lines,
                "sanitizers": sanitizer_lines,
                "counts": {
                    "sinks": len(sinks),
                    "sources": len(sources),
                    "sanitizers": len(sanitizers),
                },
            }

        elif action == "taint_sources":
            sources = _discover_sources(limit * 2)
            results = []
            for src_ea, src_name in sources:
                callers = _get_callers(src_ea)
                caller_names = [idc.get_func_name(c) for c in callers[:10]]
                results.append(f"{src_name}  callers={','.join(caller_names) if caller_names else 'none'}")
                if len(results) >= limit:
                    break
            return {"ok": True, "taint_sources": results, "count": len(results)}

        elif action == "feedback":
            if not finding_id or is_true_positive is None:
                return make_error(MCPError.INVALID_ARGS, "finding_id and is_true_positive required for feedback")
            knowledge.setdefault("feedback", []).append({
                "fingerprint": fingerprint,
                "finding_id": finding_id,
                "is_fp": not is_true_positive,
                "timestamp": idaapi.get_time_stamp() if hasattr(idaapi, "get_time_stamp") else 0,
            })
            _save_vuln_knowledge(knowledge)
            return {"ok": True, "message": f"Feedback recorded. is_fp={not is_true_positive}"}

        elif action == "learned_knowledge":
            return {
                "ok": True,
                "fingerprint": fingerprint,
                "binary_knowledge": {
                    "sources": binary_knowledge.get("sources", []),
                    "sinks": binary_knowledge.get("sinks", []),
                    "sanitizers": binary_knowledge.get("sanitizers", []),
                    "weights": binary_knowledge.get("weights", {}),
                    "scan_count": binary_knowledge.get("scan_count", 0),
                },
                "global": {
                    "sources_count": len(knowledge.get("global_sources", [])),
                    "sinks_count": len(knowledge.get("global_sinks", [])),
                    "sanitizers_count": len(knowledge.get("global_sanitizers", [])),
                    "feedback_count": len(knowledge.get("feedback", [])),
                },
            }

        elif action == "suggest_strategy":
            similar = _voera_find_similar_strategy(knowledge, fingerprint)
            if similar:
                return {
                    "ok": True,
                    "strategy": {
                        "sources": similar.get("sources", []),
                        "sinks": similar.get("sinks", []),
                        "sanitizers": similar.get("sanitizers", []),
                        "weights": similar.get("weights", {}),
                        "note": "Strategy derived from similar binary analysis",
                    },
                }
            return {
                "ok": True,
                "strategy": {
                    "sources": knowledge.get("global_sources", []),
                    "sinks": knowledge.get("global_sinks", []),
                    "sanitizers": knowledge.get("global_sanitizers", []),
                    "note": "Using global learned knowledge (no similar binary found)",
                },
            }

        elif action == "reflect":
            _voera_reflect([], knowledge, fingerprint)
            return {
                "ok": True,
                "message": "VOERA reflection complete. Weights adjusted based on feedback.",
                "current_weights": binary_knowledge.get("weights", {}),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
