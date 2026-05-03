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
import numpy as np
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

        # 4. Smart tool suggestions (Z-score normalized, behavior-tag aware, MemRL-informed)
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
        ("ctree:get", 0.2), ("bridgerag:search", 0.3), ("stack_analysis:analyze_frame", 0.15),
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
    "bridgerag:search": {"base": 0, "triggers": [], "next": [
        ("code:decompile", 0.35), ("xref_analysis:call_chain", 0.25),
        ("compare:functions", 0.15), ("code:decompile_chain", 0.1),
    ]},
}


def suggest_smart_tools(tool: str, action: str, response: dict, behavior_tags: Optional[List[str]] = None) -> List[str]:
    """
    Generate smart tool suggestions using Z-score normalized scoring.
    
    Combines:
      1. Base priority from the workflow knowledge graph
      2. Behavior-tag boosts (e.g., crypto tag boosts crypto_id)
      3. Historical call frequency (tools the LLM has used but might forget)
    
    Returns list of formatted tool calls sorted by score.
    """
    behavior_tags = behavior_tags or []
    entry = _TOOL_SUGGESTION_BASE.get(f"{tool}:{action}", {})
    suggestions = entry.get("next", [])
    
    if not suggestions:
        return []
    
    scored = []
    for tool_action, base_score in suggestions:
        score = base_score
        
        # Behavior-tag boosts
        ta = tool_action.split(":")[0]
        if "crypto" in behavior_tags and ta in ("crypto_id",):
            score *= 1.5
        if "network" in behavior_tags and ta in ("bridgerag", "xref_analysis", "string_ops"):
            score *= 1.3
        if "process_injection" in behavior_tags and ta in ("cfg_analysis", "xref_analysis"):
            score *= 1.4
        if "anti_analysis" in behavior_tags and ta in ("deobfuscate",):
            score *= 1.6
        
        # Historical usage boost: tools the LLM has used more get boosted
        call_key = f"{tool}:{action}"
        call_history = _auto_nudge._call_history
        for idb_key in call_history:
            usage_count = call_history[idb_key].get(tool_action, 0)
            if usage_count > 0:
                # Tools used 0-2 times: no boost. 3-5 times: slight boost. 6+: moderate boost
                boost = min(0.3, usage_count * 0.05)
                score += boost
                break  # Only count from most recent session
        
        scored.append((tool_action, score))
    
    # Z-score normalization (from MemRL research)
    scores = np.array([s for _, s in scored])
    mean = scores.mean() if len(scores) > 0 else 0
    std = scores.std() if len(scores) > 0 else 1.0
    if std > 0:
        scores = (scores - mean) / std
    
    # Add memrl Q-value boost if available
    try:
        from ida_pro_mcp.ida_mcp.tools.memrl import MemRLBank
        bank = MemRLBank()
        stats = bank.get_statistics()
        if stats.get("total_memories", 0) > 0:
            top_mems = bank.get_top_memories(limit=20)
            for mem in top_mems:
                intent = mem.get("intent_key", "")
                for i, (ta, _) in enumerate(scored):
                    if intent and any(kw in intent.lower() for kw in ta.split(":")[-1].lower().split("_")):
                        q_val = mem.get("q_value", 0.5)
                        scores[i] += (q_val - 0.5) * 0.3  # Boost proportional to Q-value
    except Exception:
        pass
    
    # Sort by normalized score
    ranked = sorted(zip(scored, scores), key=lambda x: x[1], reverse=True)
    return [f"{ta[0]}={ta[1]}" for (ta, _), _ in ranked[:8]]


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

# Heuristic reroutes: when the call signature matches one pattern but another is better
_HEURISTIC_REROUTES = [
    # memory.read with code-like args -> code.disasm
    (lambda t, a, args: t == "memory" and a == "read" and 
     isinstance(args.get("size"), int) and 0 < args.get("size", 0) <= 4096 and args.get("addr"),
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
    
    # Heuristic reroutes
    for check_fn, (new_tool, new_action, template_args) in _HEURISTIC_REROUTES:
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

_STUCK_THRESHOLDS = {
    "decompile_repeat": 4,   # Same function 4+ times
    "search_repeat": 5,       # Same query 5+ times
    "tool_loop": 3,           # Same tools alternating 3+ times
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
    
    # Pattern 1: Same function decompiled repeatedly
    addr = args.get("addr", "")
    if action in ("decompile", "semantic_decompile", "disasm") and addr:
        count = dc_cache.count(addr)
        if count >= _STUCK_THRESHOLDS["decompile_repeat"]:
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
            suggestions.append(f"bridgerag.search from '{addr}' — find structurally related functions")
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
        if count >= _STUCK_THRESHOLDS["search_repeat"]:
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
            if pairs.count(pair) >= _STUCK_THRESHOLDS["tool_loop"]:
                return {
                    "STUCK": True,
                    "blocking": True,
                    "reason": f"Looping between {pair[0][0]}.{pair[0][1]} <-> {pair[1][0]}.{pair[1][1]}",
                    "redirect": [
                        "Take a step back. Check session.dashboard() for progress.",
                        "Try pivoting: search for a different pattern, or look at a different part of the binary.",
                        "Use bridgerag.search to find related functions from a different starting point.",
                    ],
                }
    else:
        _auto_nudge._recent_tools = {key: [(tool, action)]}
    
    return None
