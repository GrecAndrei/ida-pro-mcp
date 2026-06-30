"""
Auto-nudge middleware — minimal version.

Original 515-line implementation injected `_nudge` into every tool response with:
  - hex arithmetic resolution (redundant — the LLM can call `calc`)
  - rip-relative expression nagging
  - redundant-call detection (nagging)
  - embedding-similarity tool suggestions (random against template strings)
  - Markov-chain tool suggestions (predicts LLM behavior, not binary structure)
  - prefetch suite (recursive call to trace_analysis(prefetch_context))
  - progress_note

All removed. Kept:
  - Silent action reroutes (the (search, bytes) -> (search, string) map and the
    memory.read+disasm rule) — real safety against common LLM typos.
  - record_tool_call (used by server_runtime to feed UsageIntelligence).
  - Stuck detection — only the LOOP signal triggers a hard block; other signals
    are ignored. Redirect is a soft `suggestion`, not a `force_suggestion`.
"""
from __future__ import annotations

import os
import threading

# Silent action rewrites for tools LLMs commonly get wrong. These are
# deterministic and well-tested; the rule-based ones below are gated by
# the IDA_MCP_ENABLE_REROUTE_RULES env var (default on) so the static map
# can be disabled independently if it causes false positives.
_REROUTE_MAP: dict[tuple[str, str], tuple[str, str]] = {
    ("search", "bytes"): ("search", "string"),
    ("search", "text"): ("search", "name"),
    ("search", "instruction"): ("search", "insns"),
    ("compare", "compare"): ("compare", "functions"),
    # graph's old xref-style actions live on the dedicated xref_analysis tool
    # (which IDA exports). The IDA `graph` Literal only accepts callgraph/cfg/
    # dominators/xref_graph, so any other historical action must be rerouted.
    ("graph", "call_chain"): ("xref_analysis", "call_chain"),
    ("graph", "common_callers"): ("xref_analysis", "common_callers"),
    ("graph", "common_callees"): ("xref_analysis", "common_callees"),
    ("graph", "hub_functions"): ("xref_analysis", "hub_functions"),
    ("graph", "leaf_functions"): ("xref_analysis", "leaf_functions"),
    ("graph", "recursive"): ("xref_analysis", "recursive"),
    ("graph", "dominator"): ("xref_analysis", "dominator"),
    ("graph", "influence"): ("xref_analysis", "influence"),
    ("graph", "dependency_graph"): ("xref_analysis", "dependency_graph"),
    ("graph", "dead_functions"): ("xref_analysis", "dead_functions"),
}

# Rule-based reroute: memory.read with explicit disasm intent.
# Kept narrow — only fires when the caller explicitly passes a disasm flag,
# so typed reads (u8/u16/u32/...) are never incorrectly rerouted.
def _rule_disasm_reroute(t: str, a: str, args: dict) -> bool:
    if t != "memory" or a != "read":
        return False
    if str(args.get("type", "")).lower() != "bytes":
        return False
    return bool(args.get("as_code") or args.get("disasm") or args.get("decode"))


def get_reroute(tool: str, action: str, args: dict) -> tuple[str, dict] | None:
    """Return (corrected_tool, corrected_args) if the call should be rerouted, else None.

    The static _REROUTE_MAP always applies. The _rule_disasm_reroute rule is
    enabled by default but can be turned off with
    IDA_MCP_DISABLE_REROUTE_RULES=1 for callers that want pure static map.
    """
    args = args or {}

    if (tool, action) in _REROUTE_MAP:
        new_tool, new_action = _REROUTE_MAP[(tool, action)]
        new_args = dict(args)
        new_args["action"] = new_action
        return (new_tool, new_args)

    if os.environ.get("IDA_MCP_DISABLE_REROUTE_RULES") != "1" and _rule_disasm_reroute(
        tool, action, args
    ):
        new_args = dict(args)
        new_args["action"] = "disasm"
        new_args.setdefault("limit", 50)
        return ("code", new_args)

    return None


# ----------------------------------------------------------------------------
# Tool call recording — feeds UsageIntelligence. Cheap, side-effect free.
# ----------------------------------------------------------------------------

_recorder_lock = threading.Lock()
_recent_tools: dict[str, list] = {}  # sid -> [(tool, action), ...]
_RECENT_TOOLS_LIMIT = 16


def record_tool_call(idb: str, tool: str, action: str,
                     addr: str | None = None,
                     query: str | None = None) -> None:
    """Record a tool call. Feeds UsageIntelligence via its own observer;
    recording is intentionally idempotent and side-effect free.
    """
    key = idb or "_global"
    with _recorder_lock:
        recent = _recent_tools.setdefault(key, [])
        recent.append((tool, action or ""))
        if len(recent) > _RECENT_TOOLS_LIMIT:
            del recent[: len(recent) - _RECENT_TOOLS_LIMIT]  # ring-buffer trim
