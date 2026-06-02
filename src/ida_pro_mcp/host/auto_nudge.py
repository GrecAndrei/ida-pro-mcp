"""
Auto-nudge middleware: Injects contextual suggestions into every tool response.

Solves 6 persistent LLM behavioral patterns:
  1. Address arithmetic in head -> auto-resolve hex expressions
  2. Tool amnesia -> track what was already called
  3. Wrong tool selection -> suggest correct action on error
  4. No context awareness -> auto-resolve rip-relative addresses
  5. No progress awareness -> inject dashboard metrics
  6. Tool blindness -> remind LLM of available relevant tools

Works by intercepting tool responses in server.py _prepare_response_payload()
and adding a _nudge field with computed suggestions.
"""

from __future__ import annotations

import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple


# Matches hex addresses in various forms
HEX_ADDR_RE = re.compile(r'\b(0x[0-9a-fA-F]+)\b')
# Matches rip-relative and other base+offset expressions  
RIP_RELATIVE_RE = re.compile(r'(rip|eax|ebx|ecx|edx|esi|edi|rsp|rbp|rsi|rdi|r[0-9]+)\s*([+-])\s*(0x[0-9a-fA-F]+)', re.IGNORECASE)
# Matches hex arithmetic: 0x1000 + 0x200, 0x1000 - 0x80, etc
HEX_ARITH_RE = re.compile(r'(0x[0-9a-fA-F]+)\s*([+\-])\s*(0x[0-9a-fA-F]+)')
# Matches size calculations: sizeof(...), align(...), offset(...)
SIZE_CALC_RE = re.compile(r'(sizeof|align|offset)\s*\(\s*(.+?)\s*\)', re.IGNORECASE)


def resolve_hex_expression(expr: str) -> Optional[int]:
    """Try to resolve a hex arithmetic expression."""
    match = HEX_ARITH_RE.search(expr)
    if not match:
        return None
    try:
        a = int(match.group(1), 16)
        op = match.group(2)
        b = int(match.group(3), 16)
        if op == '+':
            return a + b
        else:
            return a - b
    except ValueError:
        return None


def extract_hex_addresses(text: str) -> List[str]:
    """Extract all hex addresses from text."""
    if not isinstance(text, str):
        return []
    return HEX_ADDR_RE.findall(text)


def detect_rip_relative(text: str) -> List[Dict[str, str]]:
    """Detect rip-relative and other base+offset expressions."""
    if not isinstance(text, str):
        return []
    results = []
    for match in RIP_RELATIVE_RE.finditer(text):
        results.append({
            "base": match.group(1),
            "offset": match.group(3),
            "full": match.group(0),
        })
    return results


def compute_rip_absolute(rip: int, offset_str: str) -> Optional[int]:
    """Compute absolute address from rip-relative expression."""
    try:
        offset = int(offset_str, 16)
        # rip points to next instruction, typically rip+offset = next_instruction + offset
        return rip + offset
    except ValueError:
        return None


class AutoNudge:
    """
    Injects _nudge field into tool responses with contextual suggestions.
    
    Tracks call history per session to detect redundant patterns.
    Computes hex arithmetic to prevent LLM calculation errors.
    Resolves rip-relative addresses automatically.
    Suggests relevant tools based on response content.
    """

    def __init__(self):
        # Per-session call history: sid -> {tool:action -> count}
        self._call_history: Dict[str, Dict[str, int]] = {}
        # Per-session decompile cache: sid -> [addresses]
        self._decompile_cache: Dict[str, List[str]] = {}
        # Per-session search queries: sid -> [queries]
        self._search_cache: Dict[str, List[str]] = {}
        # Maximum entries per cache
        self._max_cache = 100

    def _session_key(self, idb: str) -> str:
        """Generate a stable session key."""
        return idb or "_global"

    def record_call(self, idb: str, tool: str, action: str, addr: Optional[str] = None, query: Optional[str] = None):
        """Record a tool call for history tracking."""
        key = self._session_key(idb)
        call_key = f"{tool}:{action}"
        self._call_history.setdefault(key, {})
        self._call_history[key][call_key] = self._call_history[key].get(call_key, 0) + 1

        if addr and action in ("decompile", "semantic_decompile", "disasm", "blocks"):
            self._decompile_cache.setdefault(key, [])
            if addr not in self._decompile_cache[key]:
                self._decompile_cache[key].append(addr)
                if len(self._decompile_cache[key]) > self._max_cache:
                    self._decompile_cache[key] = self._decompile_cache[key][-self._max_cache:]

        if query and action in ("find", "search", "text", "string", "bytes", "name"):
            self._search_cache.setdefault(key, [])
            if query not in self._search_cache[key]:
                self._search_cache[key].append(query)
                if len(self._search_cache[key]) > self._max_cache:
                    self._search_cache[key] = self._search_cache[key][-self._max_cache:]

    def compute_nudge(self, idb: str, tool: str, action: str, response: dict,
                      request_args: Optional[dict] = None) -> Optional[dict]:
        """
        Compute the _nudge field for a tool response.
        
        Returns a dict to be injected as response['_nudge'], or None if nothing to add.
        """
        key = self._session_key(idb)
        nudge = {}
        request_args = request_args or {}

        # 1. Auto-resolve hex arithmetic in the request
        addr_val = request_args.get("addr", "")
        if isinstance(addr_val, str):
            resolved = resolve_hex_expression(addr_val)
            if resolved is not None:
                nudge.setdefault("resolved_addresses", {})[addr_val] = hex(resolved)
        
        end_val = request_args.get("end", "")
        if isinstance(end_val, str):
            resolved = resolve_hex_expression(end_val)
            if resolved is not None:
                nudge.setdefault("resolved_addresses", {})[end_val] = hex(resolved)

        # 2. Detect rip-relative expressions in decompiled pseudocode
        if action in ("decompile", "semantic_decompile"):
            pseudocode = response.get("pseudocode", "") or response.get("output", "")
            if isinstance(pseudocode, str):
                rip_exprs = detect_rip_relative(pseudocode)
                if rip_exprs:
                    # Only show first 5 to avoid overwhelming
                    nudge["rip_relative_expressions"] = [
                        {"expression": e["full"], "note": "Use calc(action='resolve', expr='" + e["full"] + "') to compute absolute address"}
                        for e in rip_exprs[:5]
                    ]

        # 3. Detect redundant calls
        if addr_val and action in ("decompile", "semantic_decompile", "disasm"):
            dc = self._decompile_cache.get(key, [])
            count = dc.count(addr_val)
            if count >= 3:
                nudge["redundant"] = f"You have decompiled {addr_val} {count} times already"

        if request_args.get("query") or request_args.get("pattern"):
            q = request_args.get("query") or request_args.get("pattern")
            sc = self._search_cache.get(key, [])
            count = sc.count(str(q))
            if count >= 3:
                nudge["redundant"] = f"You have searched for '{q}' {count} times already"

        # 4. Smart tool suggestions (Z-score normalized, behavior-tag aware, preference-informed)
        suggestions = suggest_smart_tools(
            tool, action, response,
            behavior_tags=response.get("_digest", {}).get("behavior_tags", []) if isinstance(response, dict) else [],
        )
        if suggestions:
            nudge["suggested"] = suggestions[:8]
        
        if response.get("ok") is False and response.get("error"):
            err_msg = str(response.get("error", ""))
            if "unknown action" in err_msg.lower():
                nudge.setdefault("suggested", []).append(
                    "Use wiki.read(topic='" + tool + "') to see available actions."
                )
            if "not found" in err_msg.lower():
                nudge.setdefault("suggested", []).append(
                    "The address may not be mapped. Try data.functions to list available functions."
                )

        # 5. Progress reminder
        if action in ("decompile", "semantic_decompile"):
            total_analyzed = len(self._decompile_cache.get(key, []))
            if total_analyzed > 0 and total_analyzed % 10 == 0:
                nudge["progress_note"] = f"You have decompiled {total_analyzed} functions. Check progress with session.dashboard()."

        return nudge if nudge else None


# Singleton for server-wide use
_auto_nudge = AutoNudge()


def get_nudge(idb: str, tool: str, action: str, response: dict, request_args: Optional[dict] = None) -> Optional[dict]:
    """Public API for auto-nudge injection."""
    return _auto_nudge.compute_nudge(idb, tool, action, response, request_args)


def record_tool_call(idb: str, tool: str, action: str, addr: Optional[str] = None, query: Optional[str] = None):
    """Record a tool call for auto-nudge tracking."""
    _auto_nudge.record_call(idb, tool, action, addr, query)


def get_decompile_history(idb: str) -> List[str]:
    """Get list of previously decompiled addresses."""
    return _auto_nudge._decompile_cache.get(_auto_nudge._session_key(idb), [])


def get_search_history(idb: str) -> List[str]:
    """Get list of previous search queries."""
    return _auto_nudge._search_cache.get(_auto_nudge._session_key(idb), [])


# ============================================================================
# Smart Tool Suggestion (Z-score normalized, behavior-tag aware)
# ============================================================================

# Priority scoring: base * (1 + behavior_boost)
_TOOL_SUGGESTION_BASE = {
    # When analyzing a function
    "code:decompile": {"base": 0, "triggers": [], "next": [
        ("code:callers", 0.3), ("code:callees", 0.3), ("code:blocks", 0.2),
        ("ctree:get", 0.2), ("bridge_search:search", 0.3), ("stack_analysis:analyze_frame", 0.15),
        ("crypto_id:detect", 0.2), ("code:strings_in_func", 0.15),
    ]},
    "data:functions": {"base": 0, "triggers": [], "next": [
        ("code:decompile", 0.3), ("funcs:info", 0.2), ("search:find", 0.15),
        ("schemaboot:ingest", 0.1), ("idb:summary", 0.1),
    ]},
    "data:strings": {"base": 0, "triggers": [], "next": [
        ("string_ops:find_urls", 0.25), ("string_ops:find_ips", 0.2),
        ("string_ops:find_crypto", 0.2), ("search:string", 0.15),
        ("string_ops:find_emails", 0.1), ("string_ops:find_commands", 0.1),
    ]},
    "data:imports": {"base": 0, "triggers": [], "next": [
        ("imports_deep:thunks", 0.25), ("imports_deep:delay", 0.2),
        ("classify:categorize", 0.2), ("data:functions", 0.15),
    ]},
    "search:find": {"base": 0, "triggers": [], "next": [
        ("search:callers", 0.2), ("search:callees", 0.2),
        ("code:decompile", 0.15), ("funcs:info", 0.1),
    ]},
    "search:name": {"base": 0, "triggers": [], "next": [
        ("code:decompile", 0.3), ("funcs:info", 0.2), ("search:find", 0.15),
    ]},
    # When just looking at binary info
    "idb:summary": {"base": 0, "triggers": [], "next": [
        ("data:imports", 0.25), ("data:strings", 0.2), ("data:functions", 0.2),
        ("binary_info:headers", 0.15), ("binary_info:sections", 0.1),
        ("binary_info:compiler", 0.1), ("entropy:calculate", 0.1),
    ]},
    "binary_info:headers": {"base": 0, "triggers": [], "next": [
        ("binary_info:sections", 0.3), ("binary_info:compiler", 0.25),
        ("binary_info:checksums", 0.15), ("binary_info:relocations", 0.1),
    ]},
    # Bridgerag triggers
    "bridge_search:search": {"base": 0, "triggers": [], "next": [
        ("code:decompile", 0.35), ("graph:call_chain", 0.25),
        ("compare:functions", 0.15), ("code:decompile_chain", 0.1),
    ]},
}


def suggest_smart_tools(tool: str, action: str, response: dict, behavior_tags: Optional[List[str]] = None) -> List[str]:
    """
    Generate smart tool suggestions using embedding relevance ranking.

    Ranks candidate next calls by cosine similarity between the current
    context intent and candidate call descriptors, avoiding fixed boost tables.

    Returns list of formatted tool calls sorted by score.
    """
    behavior_tags = behavior_tags or []
    entry = _TOOL_SUGGESTION_BASE.get(f"{tool}:{action}", {})
    suggestions = entry.get("next", [])
    if not suggestions:
        return []
    context_bits: List[str] = [f"{tool}:{action}"]
    if isinstance(response, dict):
        digest = response.get("_digest") if isinstance(response.get("_digest"), dict) else {}
        intent = digest.get("intent")
        if intent:
            context_bits.append(str(intent))
        apis = digest.get("api_calls")
        if isinstance(apis, list) and apis:
            context_bits.append(" ".join(str(x) for x in apis[:8]))
    if behavior_tags:
        context_bits.append(" ".join(str(x) for x in behavior_tags[:8]))
    query_text = " | ".join(context_bits)

    candidate_texts = [
        f"{ta} next step for reverse engineering analysis"
        for ta, _ in suggestions
    ]

    ranked_with_sim: List[Tuple[str, float, float]] = []
    try:
        from .intelligence_core import BgeCodeEmbedder
        emb = BgeCodeEmbedder()
        qv = emb.embed(query_text[:1200])
        for (ta, base), ctext in zip(suggestions, candidate_texts):
            cv = emb.embed(ctext)
            sim = float(BgeCodeEmbedder.cosine(qv, cv))
            ranked_with_sim.append((ta, sim, float(base)))
    except Exception:
        # Deterministic fallback when embedder is unavailable.
        for ta, base in suggestions:
            ranked_with_sim.append((ta, 0.0, float(base)))

    ranked = sorted(
        ranked_with_sim,
        key=lambda x: (x[1], x[2], x[0]),
        reverse=True,
    )
    return [f"{ta}={round(sim, 4)}" for ta, sim, _ in ranked[:8]]


# ============================================================================
# Silent Tool Rerouting
# ============================================================================

# Maps (tool, action) that LLMs commonly get wrong to the correct (tool, action)
_REROUTE_MAP: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("search", "bytes"): ("search", "string"),
    ("search", "text"): ("search", "name"),
    ("search", "instruction"): ("search", "insns"),
    ("compare", "compare"): ("compare", "functions"),
}

# Rule-based reroutes: when the call signature matches one pattern but another is better
_RULE_REROUTES = [
    # memory.read with explicit disasm intent -> code.disasm
    # Keep typed reads (u8/u16/u32/...) in memory.read to avoid incorrect reroutes.
    (lambda t, a, args: t == "memory" and a == "read" and args.get("addr") and str(args.get("type", "")).lower() == "bytes" and bool(args.get("as_code") or args.get("disasm") or args.get("decode")),
     ("code", "disasm", {"addr": "__ADDR__", "limit": 50})),
]


def get_reroute(tool: str, action: str, args: dict) -> Optional[Tuple[str, dict]]:
    """
    Check if this tool call should be silently rerouted.
    
    Returns (corrected_tool, corrected_args) or None.
    """
    args = args or {}
    
    # Exact matches
    if (tool, action) in _REROUTE_MAP:
        new_tool, new_action = _REROUTE_MAP[(tool, action)]
        new_args = dict(args)
        new_args["action"] = new_action
        return (new_tool, new_args)
    
    # Rule-based reroutes
    for check_fn, (new_tool, new_action, template_args) in _RULE_REROUTES:
        if check_fn(tool, action, args):
            new_args = dict(args)
            new_args["action"] = new_action
            for k, v in template_args.items():
                if k not in new_args:
                    val = str(v).replace("__ADDR__", str(args.get("addr", "")))
                    new_args[k] = val
            return (new_tool, new_args)
    
    return None


# ============================================================================
# Blocking Stuck Detection
# ============================================================================

def _dynamic_stuck_thresholds(total_events: int) -> Dict[str, int]:
    """
    Adaptive deterministic thresholds from session activity volume.
    Avoids fixed heuristic constants while preserving safety.
    """
    base = max(3, min(8, int(round(max(1, total_events) ** 0.5))))
    return {
        "decompile_repeat": base,
        "search_repeat": base + 1,
        "tool_loop": max(2, base - 1),
    }


def check_stuck_blocking(idb: str, tool: str, action: str, args: dict) -> Optional[dict]:
    """
    Check if the LLM is stuck and should be forcefully redirected.
    
    Returns a blocking intervention dict, or None.
    """
    if os.environ.get("IDA_MCP_DISABLE_STUCK_DETECTION") == "1":
        return None
    key = _auto_nudge._session_key(idb)
    dc_cache = _auto_nudge._decompile_cache.get(key, [])
    search_cache = _auto_nudge._search_cache.get(key, [])
    call_history = _auto_nudge._call_history.get(key, {})
    total_events = sum(int(v or 0) for v in call_history.values())
    thresholds = _dynamic_stuck_thresholds(total_events)
    
    # Pattern 1: Same function decompiled repeatedly
    addr = args.get("addr", "")
    if action in ("decompile", "semantic_decompile", "disasm") and addr:
        count = dc_cache.count(addr)
        if count >= thresholds["decompile_repeat"]:
            # Find what they should look at instead
            callers_key = f"code:callers"
            callees_key = f"code:callees"
            callee_count = call_history.get(callees_key, 0)
            caller_count = call_history.get(callers_key, 0)
            
            suggestions = []
            if caller_count == 0:
                suggestions.append(f"code.callers(addr='{addr}') — find what calls this function")
            if callee_count == 0:
                suggestions.append(f"code.callees(addr='{addr}') — find what this function calls")
            suggestions.append(f"bridge_search.search from '{addr}' — find structurally related functions")
            suggestions.append(f"ctree.get(addr='{addr}') — examine the abstract syntax tree")
            
            return {
                "STUCK": True,
                "blocking": True,
                "reason": f"You have decompiled {addr} {count} times. Stop repeating.",
                "redirect": suggestions,
                "force_suggestion": f"The next call should be: {suggestions[0]}",
            }
    
    # Pattern 2: Same search repeated
    query = args.get("query") or args.get("pattern", "")
    if action in ("find", "search", "text", "string", "bytes", "name") and query:
        count = search_cache.count(str(query))
        if count >= thresholds["search_repeat"]:
            return {
                "STUCK": True,
                "blocking": True,
                "reason": f"You have searched for '{query}' {count} times. Same results every time.",
                "redirect": [
                    f"Try broader search: search(action='find', pattern='{query[:3]}*')",
                    "Try a different approach: data.functions to list all functions",
                    "Look at the imports for clues: data.imports",
                ],
            }
    
    # Pattern 3: Looping between two tools
    if hasattr(_auto_nudge, '_recent_tools'):
        recent = list(_auto_nudge._recent_tools.get(key, []))[-8:]
        recent.append((tool, action))
        _auto_nudge._recent_tools.setdefault(key, [])
        _auto_nudge._recent_tools[key] = recent[-10:]
        
        pairs = [(recent[i], recent[i + 1]) for i in range(len(recent) - 1)]
        for pair in set(pairs):
            if pairs.count(pair) >= thresholds["tool_loop"]:
                return {
                    "STUCK": True,
                    "blocking": True,
                    "reason": f"Looping between {pair[0][0]}.{pair[0][1]} <-> {pair[1][0]}.{pair[1][1]}",
                    "redirect": [
                        "Take a step back. Check session.dashboard() for progress.",
                        "Try pivoting: search for a different pattern, or look at a different part of the binary.",
                        "Use bridge_search.search to find related functions from a different starting point.",
                    ],
                }
    else:
        _auto_nudge._recent_tools = {key: [(tool, action)]}
    
    return None
