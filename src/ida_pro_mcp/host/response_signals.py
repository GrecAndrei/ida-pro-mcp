"""
Signal injection helpers — minimal version.

Original 746-line implementation had:
  - `build_signal_directives` (deleted) — emitted the `_next_calls` shotgun
  - `_HYPOTHESIS_TEMPLATES` + `generate_hypotheses` (deleted) — canned lies
    that fired on any function with matching API names
  - `auto_blackboard_write` (deleted) — silently wrote entries on every
    decompile, with the canned-hypothesis loop
  - `GHOST_CHAINS` + `get_ghost_chain` (deleted) — the 7-phase runtime
    ghost-chain inlining that fired `_execute_tool` recursively per decompile

Kept:
  - `build_session_resume` — first 2 calls get a small session context block
    (the original `estimated_completion: f"{min(99, total_actions // 5)}%"`
    was removed; that formula is a marketing number).
  - `_update_kg_from_hypothesis` — knowledge-graph side-effect; still wired
    by the few remaining callers (manual hypothesis records, not auto).
  - `_TAG_TO_SYSTEM` — knowledge-graph tag map.

The host pipeline now exposes only:
  - `_digest` (auto-extracted API calls, patterns, security notes, behavior tags)
  - `llm_address_calculation` (decimal/RVA of hex addresses)
  - `llm_guardrail_mode` / `llm_guardrail_reason_tags` (safety)
  - `llm_address_lockstep_warnings` (cross-checks requested vs returned addresses)
  - `_session_resume` (first 2 calls)

If the LLM wants a recommendation, it calls
`intelligence(action="suggest", tool=..., action=...)` explicitly.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


# ==========================================================================
# Session Resume Injection
# ==========================================================================


def build_session_resume(
    session_manager,
    sid: str,
    blackboard_entries: Optional[List[dict]] = None,
) -> Optional[dict]:
    """Build a session resume context block for reconnecting LLMs.

    Only fires for the first 2 calls of a session. The original
    `analysis_progress.estimated_completion` was a fabricated
    `min(99, total_actions // 5)` percentage — removed because the LLM
    was treating it as ground truth.
    """
    if not session_manager or not sid:
        return None

    session = session_manager.get_session(sid)
    if not session:
        return None

    resume: Dict[str, Any] = {}
    skills_data = session_manager._load_skills(sid)
    activity_log = skills_data.get("activity_log", [])
    hypotheses = skills_data.get("hypotheses", [])
    skills = skills_data.get("skills", {})

    decompiled: set = set()
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

    if activity_log:
        resume["analysis_progress"] = {
            "total_actions": len(activity_log),
            "phase": session.phase,
        }

    notebook = getattr(session_manager, "_load_notebook", lambda x: "")(sid)
    if notebook:
        last_lines = notebook.split("\n")[-10:]
        resume["last_notebook_entry"] = "\n".join(last_lines)

    return resume if resume else None


# ==========================================================================
# Knowledge graph side-effect (called manually, not on every decompile)
# ==========================================================================

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
    """Add the function address to a knowledge-graph subsystem for the first
    matching behavior tag. Intended for explicit hypothesis writes (via
    blackboard(action="write", category="hypothesis", ...)) — not auto-fired
    on every decompile.
    """
    if not db_path or not addr:
        return
    try:
        import importlib.util
        _kg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "knowledge_graph.py",
        )
        if not os.path.exists(_kg_path):
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
