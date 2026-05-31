#!/usr/bin/env python3
"""Blackboard store and host-side orchestration helpers."""

import hashlib
import importlib.util
import json
import os
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .config import _bounded_int
from .errors import MCPError, make_error
from .schemas import TOOL_ACTIONS
from .symbol_db import SymbolDB


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LANE_CATEGORY = {
    "lane_now": "wm_now",
    "lane_hypotheses": "hypothesis",
    "lane_facts": "fact",
    "lane_queue": "frontier",
    "lane_dead_ends": "dead_end",
}


def _clip(text: Any, limit: int = 120) -> str:
    value = str(text or "").replace("\n", " ").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _entry_brief(entry: Dict[str, Any]) -> Dict[str, Any]:
    tags = entry.get("tags") or []
    evidence = entry.get("evidence") or []
    addr = str(entry.get("addr") or "").strip()
    title = str(entry.get("title") or "").strip()
    category = str(entry.get("category") or "general").strip()
    confidence = float(entry.get("confidence") or 0.0)
    status = "resolved" if entry.get("resolved") else "contradicted" if entry.get("contradicted") else "open"
    tag_list = tags if isinstance(tags, list) else []
    return {
        "entry_id": entry.get("id") or entry.get("entry_id"),
        "addr": addr or None,
        "title": title,
        "category": category,
        "confidence": round(confidence, 3),
        "source_type": str(entry.get("source_type") or "manual"),
        "status": status,
        "tags": tag_list[:8],
        "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "summary": _clip(
            f"{addr or 'no-addr'} | {category} | {title} | conf={confidence:.2f} | "
            f"{status} | tags={', '.join(tag_list[:4]) if tag_list else 'none'}",
            180,
        ),
        "content_preview": _clip(entry.get("content") or "", 180) if entry.get("content") else "",
    }


def _entry_collection_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    categories = Counter(str(e.get("category") or "general") for e in entries)
    source_types = Counter(str(e.get("source_type") or "manual") for e in entries)
    briefs = [_entry_brief(e) for e in entries[:10]]
    return {
        "count": len(entries),
        "categories": dict(categories),
        "source_types": dict(source_types),
        "top_titles": [b["title"] for b in briefs[:5] if b.get("title")],
        "briefs": briefs,
    }


def _target_collection_summary(targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not targets:
        return {"count": 0, "briefs": []}
    briefs = []
    for target in targets[:10]:
        addr = str(target.get("addr") or "").strip()
        title = str(target.get("title") or target.get("name") or "").strip()
        parts = [addr or "no-addr", title or "unnamed"]
        if target.get("confidence") is not None:
            parts.append(f"conf={float(target.get('confidence') or 0.0):.2f}")
        if target.get("priority_score") is not None:
            parts.append(f"priority={float(target.get('priority_score') or 0.0):.3f}")
        if target.get("semantic_similarity") is not None:
            parts.append(f"semantic={float(target.get('semantic_similarity') or 0.0):.3f}")
        if target.get("xref_count") is not None:
            parts.append(f"xrefs={int(target.get('xref_count') or 0)}")
        if target.get("entropy") is not None:
            parts.append(f"entropy={float(target.get('entropy') or 0.0):.2f}")
        briefs.append({
            "addr": addr or None,
            "title": title,
            "category": target.get("category"),
            "summary": " | ".join(parts),
        })
    best = targets[0]
    return {
        "count": len(targets),
        "best_addr": best.get("addr"),
        "best_title": best.get("title"),
        "briefs": briefs,
    }


def _frontier_collection_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not results:
        return {"count": 0, "briefs": []}
    briefs = []
    for row in results[:10]:
        addr = str(row.get("addr") or "").strip()
        name = str(row.get("name") or row.get("title") or "").strip()
        pieces = [addr or "no-addr", name or "unnamed"]
        if row.get("score") is not None:
            pieces.append(f"score={float(row.get('score') or 0.0):.3f}")
        if row.get("proximity") is not None:
            pieces.append(f"prox={float(row.get('proximity') or 0.0):.3f}")
        if row.get("nearest_label_title"):
            pieces.append(f"near={_clip(row.get('nearest_label_title'), 40)}")
        briefs.append({
            "addr": addr or None,
            "name": name,
            "summary": " | ".join(pieces),
        })
    return {"count": len(results), "briefs": briefs}


def _proposal_collection_summary(proposals: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not proposals:
        return {"count": 0, "briefs": []}
    briefs = []
    for p in proposals[:10]:
        briefs.append({
            "proposal_id": p.get("proposal_id"),
            "addr": p.get("addr"),
            "title": p.get("title"),
            "summary": _clip(
                f"{p.get('proposal_id')} | {p.get('addr') or 'no-addr'} | "
                f"{p.get('title') or ''} | conf={float(p.get('confidence') or 0.0):.2f}",
                180,
            ),
        })
    return {"count": len(proposals), "briefs": briefs}


def _coerce_str_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [p.strip() for p in value.split("|") if p.strip()]
    return []


_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")
_SYMBOL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,63}\b")
_ADDR_NAME_RE = re.compile(
    r"(?P<addr>0x[0-9a-fA-F]{4,16})\s*(?:->|:|=|-)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]{2,63})"
)
_EVIDENCE_TOOL_HINTS = {
    "code",
    "search",
    "xref_analysis",
    "firmware_view",
    "types",
    "data",
    "funcs",
    "memory",
    "calc",
    "blackboard",
}


class ServerBlackboardMixin:
    def _phase_state(self) -> Dict[str, Any]:
        state = getattr(self, "_blackboard_phase_state", None)
        if not isinstance(state, dict):
            state = {
                "phase": "scout",
                "auto_transition": True,
                "recent_actions": [],
                "seen_addrs": [],
                "last_transition_reason": "init",
            }
            setattr(self, "_blackboard_phase_state", state)
        return state

    def _phase_snapshot(self, state: Dict[str, Any], store) -> Dict[str, Any]:
        seen = state.get("seen_addrs") or []
        recent = state.get("recent_actions") or []
        contradictions = 0
        try:
            stats = store.stats() or {}
            contradictions = int(stats.get("contradicted") or 0)
        except Exception:
            contradictions = 0
        return {
            "phase": str(state.get("phase") or "scout"),
            "auto_transition": bool(state.get("auto_transition", True)),
            "seen_addrs_count": len(seen),
            "recent_actions": recent[-10:],
            "last_transition_reason": str(state.get("last_transition_reason") or ""),
            "contradicted_entries": contradictions,
        }

    def _phase_transition(self, state: Dict[str, Any], phase: str, reason: str) -> None:
        phase = str(phase or "").strip().lower()
        if phase not in {"scout", "prove", "commit", "finalize"}:
            return
        state["phase"] = phase
        state["last_transition_reason"] = reason[:160]

    def _phase_log_action(self, state: Dict[str, Any], action: str, addr: str = "") -> None:
        recent = state.get("recent_actions")
        if not isinstance(recent, list):
            recent = []
        recent.append(str(action or ""))
        if len(recent) > 24:
            recent = recent[-24:]
        state["recent_actions"] = recent
        if addr:
            seen = state.get("seen_addrs")
            if not isinstance(seen, list):
                seen = []
            if addr not in seen:
                seen.append(addr)
            state["seen_addrs"] = seen[-200:]

    def _phase_find_loop(self, state: Dict[str, Any]) -> bool:
        recent = state.get("recent_actions") or []
        if len(recent) < 6:
            return False
        tail = recent[-6:]
        uniq = set(tail)
        return len(uniq) <= 2 and tail.count(tail[-1]) >= 3

    def _phase_contracts(self, phase: str) -> Dict[str, Any]:
        phase = str(phase or "scout")
        contracts = {
            "scout": {
                "write_policy": "optional",
                "requirements": ["explore_addresses", "gather_broad_signals"],
                "must_have": [],
            },
            "prove": {
                "write_policy": "evidence_required",
                "requirements": ["decision_card_with_evidence", "completed_trace_task"],
                "must_have": ["evidence_for", "trace_done"],
            },
            "commit": {
                "write_policy": "spec_required",
                "requirements": ["strict_proposal_spec", "verification_plan"],
                "must_have": ["proposal_spec_valid"],
            },
            "finalize": {
                "write_policy": "reconcile_required",
                "requirements": ["resolve_contradictions", "compile_snapshot"],
                "must_have": ["contradictions_reconciled"],
            },
        }
        return contracts.get(phase, contracts["scout"])

    def _phase_escape_route(self, store, limit: int = 3) -> List[Dict[str, Any]]:
        targets = store.next_target(limit=limit)
        out = []
        for t in targets[:limit]:
            addr = str(t.get("addr") or "").strip()
            if not addr:
                continue
            out.append(
                {
                    "mission": f"Break loop by tracing {addr}",
                    "addr": addr,
                    "call": {"tool": "blackboard", "args": {"action": "trace_ingest", "text": f"Investigate {addr} callers/callees"}},
                    "followup": {"tool": "blackboard", "args": {"action": "trace_run", "limit": 1}},
                }
            )
        return out

    def _phase_tick(self, state: Dict[str, Any], store, limit: int = 3) -> Dict[str, Any]:
        phase = str(state.get("phase") or "scout")
        loop = self._phase_find_loop(state)
        contracts = self._phase_contracts(phase)
        prove_ready = self._phase_has_prove_receipts(store)
        stats = store.stats() or {}
        contradictions = int(stats.get("contradicted") or 0)
        recommendations = []
        if phase == "prove" and not prove_ready:
            recommendations.append("Add evidence-backed decision_card and run trace_ingest/trace_run.")
        if phase == "commit":
            recommendations.append("Create strict proposal specs and verify before accept.")
        if phase == "finalize" and contradictions > 0:
            recommendations.append("Resolve contradictions before commit actions.")
        escape = self._phase_escape_route(store, limit=limit) if loop else []
        if loop and phase == "scout":
            self._phase_transition(state, "prove", "auto: loop detected via phase_tick")
            phase = "prove"
            contracts = self._phase_contracts(phase)
            recommendations.append("Loop detected: switched to prove phase with guided missions.")
        return {
            "ok": True,
            "phase": self._phase_snapshot(state, store),
            "contracts": contracts,
            "loop_detected": loop,
            "prove_receipts_ready": prove_ready,
            "contradictions": contradictions,
            "escape_route_targets": escape,
            "recommendations": recommendations[:6],
        }

    def _phase_has_prove_receipts(self, store) -> bool:
        cards = store.list(category="hypothesis", include_resolved=True, include_contradicted=False, limit=80)
        has_evidence_card = False
        for c in cards:
            tags = c.get("tags") or []
            if not (isinstance(tags, list) and "decision_card" in tags):
                continue
            try:
                payload = json.loads(str(c.get("content") or "{}"))
            except Exception:
                payload = {}
            ev_for = payload.get("evidence_for") or []
            if isinstance(ev_for, list) and self._evidence_has_tool_citation(ev_for):
                has_evidence_card = True
                break
        if not has_evidence_card:
            return False
        tasks = store.list(category="trace_task", include_resolved=True, include_contradicted=True, limit=120)
        for t in tasks:
            tags = t.get("tags") or []
            if isinstance(tags, list) and "status:done" in tags:
                return True
        return False

    def _evidence_has_tool_citation(self, evidence_for: List[Any]) -> bool:
        for item in evidence_for or []:
            txt = str(item or "").strip().lower()
            if not txt:
                continue
            if ":" in txt:
                head = txt.split(":", 1)[0].strip()
                if head in _EVIDENCE_TOOL_HINTS:
                    return True
            for tool_name in _EVIDENCE_TOOL_HINTS:
                if f"{tool_name}(" in txt or f"{tool_name} " in txt:
                    return True
        return False

    def _phase_auto_transition(self, state: Dict[str, Any], action: str, args: Dict[str, Any], store) -> None:
        if not bool(state.get("auto_transition", True)):
            return
        phase = str(state.get("phase") or "scout")
        if phase == "scout":
            seen_count = len(state.get("seen_addrs") or [])
            if seen_count >= 3:
                self._phase_transition(state, "prove", "auto: >=3 unique addresses discovered")
        proposal_type = str(args.get("proposal_type") or args.get("type") or "").strip().lower()
        if action in {"proposal_create", "proposal_accept", "accept_proposal"} and phase in {"scout", "commit"}:
            if proposal_type in {"rename", "patch"} or action in {"proposal_accept", "accept_proposal"}:
                self._phase_transition(state, "commit", f"auto: {action} requested")
        if action in {"memory_compile", "phase_finalize"}:
            self._phase_transition(state, "finalize", f"auto: {action} requested")

    def _phase_contract_check(self, state: Dict[str, Any], action: str, args: Dict[str, Any], store) -> Optional[Dict[str, Any]]:
        phase = str(state.get("phase") or "scout")
        if phase == "scout":
            return None
        if phase == "prove":
            if action in {"proposal_create", "proposal_accept", "accept_proposal"} and not self._phase_has_prove_receipts(store):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "prove phase requires evidence cards and completed trace tasks before proposal operations",
                    hint="Create a decision_card with evidence_for, run trace_ingest + trace_run, then retry.",
                )
            return None
        if phase == "commit":
            if action == "proposal_create":
                proposal_type = str(args.get("proposal_type") or args.get("type") or "").strip().lower()
                if proposal_type in {"rename", "patch"}:
                    spec = args.get("spec")
                    if isinstance(spec, str):
                        try:
                            spec = json.loads(spec)
                        except Exception:
                            spec = {}
                    err = self._validate_proposal_spec(proposal_type, spec if isinstance(spec, dict) else {})
                    if err:
                        return make_error(MCPError.INVALID_ARGS, f"commit phase requires strict spec: {err}")
            return None
        if phase == "finalize":
            if action in {"proposal_create", "proposal_accept", "accept_proposal"}:
                stats = store.stats() or {}
                contradicted = int(stats.get("contradicted") or 0)
                if contradicted > 0:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "finalize phase blocked: unresolved contradictions remain",
                        hint=f"Resolve/contradict reconciliation required before commit actions. contradicted={contradicted}",
                    )
            return None
        return None

    def _phase_preflight_for_tool(self, tool_name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            if str(tool_name or "").strip().lower() == "blackboard":
                return None
            store = self._get_blackboard_store()
            if store is None:
                return None
            phase_state = self._phase_state()
            action = str((args or {}).get("action") or "").strip().lower()
            addr = str((args or {}).get("addr") or (args or {}).get("address") or "").strip()
            logical = f"{tool_name}:{action or 'call'}"
            self._phase_log_action(phase_state, logical, addr=addr)
            self._phase_auto_transition(phase_state, logical, args or {}, store)
            phase = str(phase_state.get("phase") or "scout")
            if phase == "scout":
                return None
            if phase == "prove":
                risky = {"modify", "bulk", "segments", "funcs", "annotation"}
                if str(tool_name or "") in risky and not self._phase_has_prove_receipts(store):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "prove phase requires evidence cards and completed trace tasks before write-surface tools",
                        hint="Use decision_card evidence_for with tool citations (e.g. 'code:caller graph') + trace_ingest/trace_run first.",
                    )
                return None
            if phase == "commit":
                if str(tool_name or "") in {"modify", "bulk"}:
                    ack = bool((args or {}).get("_phase_commit_ack", False))
                    if not ack:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "commit phase requires explicit acknowledgement for write-surface tools",
                            hint="Retry with _phase_commit_ack=true after proposal verification.",
                        )
                return None
            if phase == "finalize":
                if str(tool_name or "") in {"modify", "bulk", "segments", "funcs", "annotation"}:
                    stats = store.stats() or {}
                    contradicted = int(stats.get("contradicted") or 0)
                    if contradicted > 0:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "finalize phase blocked: unresolved contradictions remain",
                            hint=f"Resolve contradictions before write operations. contradicted={contradicted}",
                        )
                return None
        except Exception:
            return None
        return None

    def _phase_followup_for_response(self, tool_name: str) -> Optional[Dict[str, Any]]:
        try:
            if str(tool_name or "").strip().lower() == "blackboard":
                return None
            store = self._get_blackboard_store()
            phase_state = self._phase_state()
            phase = str(phase_state.get("phase") or "scout")
            if phase == "prove" and (store is None or not self._phase_has_prove_receipts(store)):
                return {
                    "must_call_before_answer": True,
                    "required_followup_call": {"tool": "blackboard", "action": "decision_card"},
                    "phase_gate": {"phase": "prove", "reason": "missing_tool_cited_evidence_or_trace"},
                }
            if phase == "commit":
                return {
                    "must_call_before_answer": True,
                    "required_followup_call": {"tool": "blackboard", "action": "proposal_create"},
                    "phase_gate": {"phase": "commit", "reason": "proposal_spec_required"},
                }
            if phase == "finalize":
                stats = store.stats() or {}
                contradicted = int(stats.get("contradicted") or 0)
                if contradicted > 0:
                    return {
                        "must_call_before_answer": True,
                        "required_followup_call": {"tool": "blackboard", "action": "memory_compile"},
                        "phase_gate": {"phase": "finalize", "reason": f"contradictions={contradicted}"},
                    }
        except Exception:
            return None
        return None

    def _evidence_gravity(self, store, source_entry_id: str, addr: str, source_text: str = "") -> Dict[str, Any]:
        addr = str(addr or "").strip()
        if not addr or not hasattr(self, "_execute_tool"):
            return {"ok": False, "reason": "no_addr_or_runtime"}
        pulls = []
        probes = [
            ("xref_analysis", {"action": "influence", "addr": addr, "depth": 2, "limit": 8}),
            ("code", {"action": "callers", "addr": addr, "limit": 8}),
            ("code", {"action": "callees", "addr": addr, "limit": 8}),
            ("code", {"action": "strings_in_func", "addr": addr, "limit": 8}),
            ("search", {"action": "find", "query": addr, "limit": 5}),
        ]
        for tool, targs in probes:
            try:
                res = self._execute_tool(tool, targs)
                pulls.append({"tool": tool, "args": targs, "ok": bool(isinstance(res, dict) and not res.get("error")), "result": res})
            except Exception as exc:
                pulls.append({"tool": tool, "args": targs, "ok": False, "error": str(exc)})
        embedding_neighbors = []
        # Embedding-aware gravity: pull semantic neighbors around the address/text seed.
        try:
            query = (source_text or "").strip() or addr
            sims = store.semantic_search(
                query=query,
                top_k=5,
                threshold=0.35,
                include_resolved=True,
                include_contradicted=False,
            )
            if isinstance(sims, list):
                for s in sims[:5]:
                    embedding_neighbors.append(
                        {
                            "entry_id": s.get("id"),
                            "addr": s.get("addr"),
                            "title": s.get("title"),
                            "category": s.get("category"),
                            "confidence": s.get("confidence"),
                        }
                    )
        except Exception:
            embedding_neighbors = []
        summary = {
            "source_entry_id": source_entry_id,
            "addr": addr,
            "pulls": pulls[:10],
            "embedding_neighbors": embedding_neighbors,
            "source_text_preview": _clip(source_text or "", 240),
        }
        gravity_id = store.write(
            title=f"evidence gravity {addr}",
            content=json.dumps(summary, ensure_ascii=True),
            category="evidence_gravity",
            addr=addr,
            tags=["evidence_gravity", "auto_enrich"],
            confidence=0.66,
            source="evidence_gravity",
            source_type="gravity",
        )
        return {"ok": True, "entry_id": gravity_id, "pull_count": len(pulls), "embedding_neighbor_count": len(embedding_neighbors)}

    def _quest_board(self, store, entry_id: str = "", limit: int = 20) -> Dict[str, Any]:
        seeds = []
        if entry_id:
            e = store.read(entry_id)
            if e:
                seeds = [e]
        if not seeds:
            seeds = store.list(include_resolved=False, include_contradicted=False, limit=max(20, limit))
        quests = []
        for e in seeds[: max(20, limit)]:
            eid = str(e.get("id") or "")
            addr = str(e.get("addr") or "")
            cat = str(e.get("category") or "")
            title = str(e.get("title") or "")
            if addr:
                quests.append({"quest_type": "trace_caller", "entry_id": eid, "addr": addr, "call": {"tool": "trace_ingest", "args": {"entry_id": eid}}})
                quests.append({"quest_type": "verify_this", "entry_id": eid, "addr": addr, "call": {"tool": "search", "args": {"query": addr}}})
                quests.append({"quest_type": "rename_candidate", "entry_id": eid, "addr": addr, "call": {"tool": "proposal_create", "args": {"proposal_type": "rename", "title": f"rename {addr}", "spec": {"renames": [{"addr": addr, "name": "sub_candidate"}]}}}})
            quests.append({"quest_type": "disprove_hypothesis", "entry_id": eid, "addr": addr, "call": {"tool": "contradict", "args": {"entry_id": eid, "reason": "counter-evidence required"}}})
            if cat in {"hypothesis", "fact"}:
                quests.append({"quest_type": "merge_duplicate", "entry_id": eid, "addr": addr, "call": {"tool": "merge", "args": {"addr": addr, "category": cat}}})
            if len(quests) >= limit:
                break
        return {"ok": True, "count": len(quests[:limit]), "quests": quests[:limit]}

    def _quest_complete(self, store, quest_id: str, quest_type: str, status: str, result_text: str, evidence: List[str], entry_id: str = "", addr: str = "") -> Dict[str, Any]:
        qid = str(quest_id or "").strip() or f"quest-{int(time.time() * 1000)}"
        qtype = str(quest_type or "").strip() or "generic"
        st = str(status or "completed").strip().lower()
        if st not in {"completed", "failed", "skipped"}:
            st = "completed"
        payload = {
            "quest_id": qid,
            "quest_type": qtype,
            "status": st,
            "result": str(result_text or "").strip(),
            "evidence": evidence[:10],
            "entry_id": str(entry_id or "").strip(),
            "addr": str(addr or "").strip(),
        }
        eid = store.write(
            title=f"quest {qtype} {qid} {st}",
            content=json.dumps(payload, ensure_ascii=True),
            category="quest_log",
            addr=str(addr or "").strip(),
            tags=[f"quest:{qtype}", f"status:{st}", "quest_completion"],
            confidence=0.75 if st == "completed" else 0.4,
            source="quest_complete",
            source_type="quest",
        )
        return {"ok": True, "entry_id": eid, "quest": payload}

    def _memory_compile(self, store, limit: int = 30, notes_path: str = "") -> Dict[str, Any]:
        entries = store.list(include_resolved=True, include_contradicted=True, limit=max(200, limit * 4))
        facts = []
        open_h = []
        dead = []
        for e in entries:
            conf = float(e.get("confidence") or 0.0)
            cat = str(e.get("category") or "")
            contradicted = bool(e.get("contradicted"))
            resolved = bool(e.get("resolved"))
            if contradicted or cat == "dead_end":
                dead.append(_entry_brief(e))
                continue
            if conf >= 0.75 or cat == "fact":
                facts.append(_entry_brief(e))
            elif not resolved and cat in {"hypothesis", "wm_now", "frontier"}:
                open_h.append(_entry_brief(e))
        proposals = self._proposal_entries(store, status="proposed", limit=120)
        rename_batch = []
        for p in proposals:
            try:
                payload = json.loads(str(p.get("content") or "{}"))
            except Exception:
                payload = {}
            if str(payload.get("proposal_type") or "") != "rename":
                continue
            rename_batch.append(
                {
                    "proposal_id": p.get("id"),
                    "title": p.get("title"),
                    "spec": (payload.get("spec") or {}).get("renames", [])[:5],
                }
            )
        frontier = store.next_target(limit=limit)
        quest_logs = store.list(category="quest_log", include_resolved=True, include_contradicted=True, limit=400)
        quest_total = len(quest_logs)
        quest_completed = 0
        quest_failed = 0
        for q in quest_logs:
            tags = q.get("tags") or []
            if isinstance(tags, list) and "status:completed" in tags:
                quest_completed += 1
            elif isinstance(tags, list) and "status:failed" in tags:
                quest_failed += 1
        quest_completion_rate = (quest_completed / quest_total) if quest_total else 0.0
        contradictions = int((store.stats() or {}).get("contradicted") or 0)
        phase_quality_score = max(
            0.0,
            min(
                100.0,
                40.0
                + min(25.0, float(len(facts)) * 1.2)
                + min(25.0, float(len(rename_batch)) * 1.5)
                + min(20.0, quest_completion_rate * 20.0)
                - min(20.0, float(contradictions) * 3.0),
            ),
        )
        compiled = {
            "facts": facts[:limit],
            "open_hypotheses": open_h[:limit],
            "dead_ends": dead[:limit],
            "rename_batch": rename_batch[:limit],
            "next_frontier": frontier[:limit],
            "quest_metrics": {
                "total": quest_total,
                "completed": quest_completed,
                "failed": quest_failed,
                "completion_rate": round(quest_completion_rate, 3),
            },
            "phase_quality": {
                "score": round(phase_quality_score, 2),
                "contradictions": contradictions,
            },
        }
        notes_written = ""
        if notes_path:
            try:
                lines = [
                    "# Memory Compiler Snapshot",
                    "",
                    f"- phase_quality_score: {compiled['phase_quality']['score']}",
                    f"- contradictions: {compiled['phase_quality']['contradictions']}",
                    f"- quest_completion_rate: {compiled['quest_metrics']['completion_rate']}",
                    "",
                    "## Facts",
                ]
                if compiled["facts"]:
                    for f in compiled["facts"][:limit]:
                        lines.append(f"- {f.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Open Hypotheses"])
                if compiled["open_hypotheses"]:
                    for h in compiled["open_hypotheses"][:limit]:
                        lines.append(f"- {h.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Dead Ends"])
                if compiled["dead_ends"]:
                    for d in compiled["dead_ends"][:limit]:
                        lines.append(f"- {d.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Rename Batch"])
                if compiled["rename_batch"]:
                    for rb in compiled["rename_batch"][:limit]:
                        lines.append(f"- [{rb.get('proposal_id')}] {rb.get('title')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Next Frontier"])
                if compiled["next_frontier"]:
                    for nf in compiled["next_frontier"][:limit]:
                        lines.append(
                            f"- {nf.get('addr') or 'no-addr'} | {nf.get('title') or nf.get('name') or ''} | priority={nf.get('priority_score')}"
                        )
                else:
                    lines.append("- (none)")
                os.makedirs(os.path.dirname(os.path.abspath(notes_path)) or ".", exist_ok=True)
                with open(notes_path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines).strip() + "\n")
                notes_written = os.path.abspath(notes_path)
            except Exception:
                notes_written = ""
        cid = store.write(
            title="memory compiler snapshot",
            content=json.dumps(compiled, ensure_ascii=True),
            category="wm_now",
            addr="",
            tags=["memory_compiler", "snapshot"],
            confidence=0.82,
            source="memory_compile",
            source_type="compiler",
        )
        return {"ok": True, "entry_id": cid, "notes_path": notes_written or None, **compiled}

    def _bb_policy_state(self) -> Dict[str, Any]:
        state = getattr(self, "_blackboard_policy_state", None)
        if not isinstance(state, dict):
            state = {
                "strict_mode": False,
                "max_staleness_calls": 6,
                "require_working_set": True,
                "require_decision_or_write": True,
                "enforce_phases": ["commit", "finalize"],
                "call_seq": 0,
                "last_working_set_call": -1,
                "last_write_call": -1,
                "last_decision_call": -1,
            }
            setattr(self, "_blackboard_policy_state", state)
        return state

    def _bb_policy_bump(self) -> Dict[str, Any]:
        state = self._bb_policy_state()
        state["call_seq"] = int(state.get("call_seq", 0)) + 1
        return state

    def _bb_policy_mark(self, state: Dict[str, Any], marker: str) -> None:
        seq = int(state.get("call_seq", 0))
        if marker == "working_set":
            state["last_working_set_call"] = seq
        elif marker == "write":
            state["last_write_call"] = seq
        elif marker == "decision":
            state["last_decision_call"] = seq

    def _bb_policy_snapshot(self, state: Dict[str, Any]) -> Dict[str, Any]:
        seq = int(state.get("call_seq", 0))
        last_ws = int(state.get("last_working_set_call", -1))
        last_write = int(state.get("last_write_call", -1))
        last_decision = int(state.get("last_decision_call", -1))
        staleness = {
            "working_set_calls_ago": (seq - last_ws) if last_ws >= 0 else None,
            "write_calls_ago": (seq - last_write) if last_write >= 0 else None,
            "decision_calls_ago": (seq - last_decision) if last_decision >= 0 else None,
        }
        return {
            "strict_mode": bool(state.get("strict_mode", False)),
            "max_staleness_calls": int(state.get("max_staleness_calls", 6)),
            "require_working_set": bool(state.get("require_working_set", True)),
            "require_decision_or_write": bool(state.get("require_decision_or_write", True)),
            "enforce_phases": list(state.get("enforce_phases") or []),
            "call_seq": seq,
            "last_working_set_call": last_ws,
            "last_write_call": last_write,
            "last_decision_call": last_decision,
            "staleness": staleness,
        }

    def _bb_policy_enforced_for_phase(self, state: Dict[str, Any], phase: str) -> bool:
        if not bool(state.get("strict_mode", False)):
            return False
        phases = state.get("enforce_phases")
        if isinstance(phases, list) and phases:
            return str(phase or "").strip().lower() in {str(p).strip().lower() for p in phases}
        # Backward-compatible fallback: enforce everywhere if list is absent/empty.
        return True

    def _bb_policy_check(self, state: Dict[str, Any]) -> Dict[str, Any]:
        snapshot = self._bb_policy_snapshot(state)
        reasons = []
        max_age = int(snapshot["max_staleness_calls"])
        seq = int(snapshot["call_seq"])
        last_ws = int(snapshot["last_working_set_call"])
        last_write = int(snapshot["last_write_call"])
        last_decision = int(snapshot["last_decision_call"])

        if snapshot["require_working_set"]:
            if last_ws < 0:
                reasons.append("missing_working_set")
            elif seq - last_ws > max_age:
                reasons.append("stale_working_set")
        if snapshot["require_decision_or_write"]:
            most_recent = max(last_write, last_decision)
            if most_recent < 0:
                reasons.append("missing_decision_or_write")
            elif seq - most_recent > max_age:
                reasons.append("stale_decision_or_write")

        ok = not reasons
        recommendation = (
            "Run blackboard working_set, then write/decision_card before continuing."
            if not ok
            else "State fresh enough for strict execution."
        )
        return {
            "ok": ok,
            "reasons": reasons,
            "recommendation": recommendation,
            "policy": snapshot,
        }

    def _verified_proposal_addrs(self, store, limit: int = 400) -> set:
        out = set()
        try:
            proposals = store.list(
                category="proposal",
                include_resolved=True,
                include_contradicted=True,
                limit=limit,
            )
            for p in proposals:
                tags = p.get("tags") or []
                if not (isinstance(tags, list) and "status:verified" in tags):
                    continue
                if p.get("addr"):
                    out.add(str(p.get("addr")))
                payload = {}
                try:
                    payload = json.loads(str(p.get("content") or "{}"))
                except Exception:
                    payload = {}
                spec = payload.get("spec") or {}
                for row in spec.get("renames", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
                for row in spec.get("patches", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
                for row in spec.get("types", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
        except Exception:
            pass
        return out

    def _lane_fetch(self, store, lane: str, limit: int) -> List[Dict[str, Any]]:
        category = _LANE_CATEGORY.get(lane, "general")
        if lane == "lane_queue":
            targets = store.next_target(limit=limit)
            verified_addrs = self._verified_proposal_addrs(store)
            items = []
            for t in targets:
                addr = str(t.get("addr") or "")
                priority = float(t.get("priority_score") or 0.0)
                if addr and addr in verified_addrs:
                    priority += 0.2
                items.append({
                    "id": str(t.get("entry_id") or ""),
                    "category": "frontier",
                    "title": str(t.get("title") or t.get("name") or ""),
                    "content": str(t.get("summary") or ""),
                    "addr": addr,
                    "confidence": float(t.get("confidence") or 0.0),
                    "source_type": str(t.get("source_type") or "queue"),
                    "priority_score": round(priority, 4),
                    "tags": ["queue"] + (["proposal_verified_boost"] if addr in verified_addrs else []),
                })
            items.sort(key=lambda x: float(x.get("priority_score") or 0.0), reverse=True)
            return items
        kwargs = {
            "category": category,
            "limit": limit,
            "include_resolved": lane == "lane_dead_ends",
            "include_contradicted": False,
        }
        if lane != "lane_dead_ends":
            kwargs["min_confidence"] = 0.0
        return store.list(**kwargs)

    def _state_health(self, store) -> Dict[str, Any]:
        stats = store.stats() or {}
        total = int(stats.get("total_entries") or 0)
        by_cat = stats.get("by_category") or {}
        unresolved = int(stats.get("unresolved") or 0)
        contradicted = int(stats.get("contradicted") or 0)
        avg_conf = float(stats.get("avg_confidence") or 0.0)
        now_count = int(by_cat.get("wm_now", 0) or 0)
        hyp_count = int(by_cat.get("hypothesis", 0) or 0)
        fact_count = int(by_cat.get("fact", 0) or 0)
        dead_count = int(by_cat.get("dead_end", 0) or 0)
        score = 100
        if total == 0:
            score -= 40
        if now_count == 0:
            score -= 20
        if hyp_count > 0 and fact_count == 0:
            score -= 10
        if avg_conf < 0.45:
            score -= 10
        if contradicted > max(2, unresolved // 2):
            score -= 10
        if dead_count == 0:
            score -= 5
        score = max(0, min(100, score))
        if now_count == 0:
            fix = "Write a `lane_now` decision card with the active objective and next verification step."
        elif fact_count == 0:
            fix = "Promote one high-confidence hypothesis into `lane_facts` after verification."
        elif avg_conf < 0.45:
            fix = "Calibrate weak entries and resolve or contradict stale low-confidence cards."
        else:
            fix = "Run `working_set` and follow the top `lane_queue` target."
        return {
            "state_health": score,
            "signals": {
                "total_entries": total,
                "wm_now": now_count,
                "hypotheses": hyp_count,
                "facts": fact_count,
                "dead_ends": dead_count,
                "avg_confidence": round(avg_conf, 3),
                "contradicted": contradicted,
            },
            "recommended_action": fix,
        }

    def _notes_export(self, store, notes_path: str, limit: int = 20) -> Dict[str, Any]:
        lanes = ["lane_now", "lane_hypotheses", "lane_facts", "lane_queue", "lane_dead_ends"]
        lines = ["# RE Notes", "", "Generated from blackboard working set.", ""]
        for lane in lanes:
            lines.append(f"## {lane}")
            entries = self._lane_fetch(store, lane, limit)
            if not entries:
                lines.append("- (empty)")
                lines.append("")
                continue
            for e in entries[:limit]:
                brief = _entry_brief(e)
                lines.append(
                    f"- [{brief.get('entry_id') or ''}] {brief.get('summary')}"
                )
                if brief.get("content_preview"):
                    lines.append(f"  - note: {brief.get('content_preview')}")
            lines.append("")
        os.makedirs(os.path.dirname(os.path.abspath(notes_path)) or ".", exist_ok=True)
        with open(notes_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines).strip() + "\n")
        return {"ok": True, "path": os.path.abspath(notes_path), "lines": len(lines)}

    def _notes_import(
        self,
        store,
        notes_path: str,
        lane: str = "lane_hypotheses",
        confidence: float = 0.65,
        auto_trace: bool = False,
        trace_depth: int = 2,
        trace_limit: int = 8,
    ) -> Dict[str, Any]:
        if not os.path.exists(notes_path):
            return make_error(MCPError.NOT_FOUND, f"Notes file not found: {notes_path}")
        category = _LANE_CATEGORY.get(lane, "hypothesis")
        imported = 0
        trace_tasks = []
        with open(notes_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line.startswith("- "):
                    continue
                text = line[2:].strip()
                if not text or text.startswith("(empty)"):
                    continue
                title = text[:140]
                if store.exists_similar("", category, title):
                    continue
                store.write(
                    title=title,
                    content=text,
                    category=category,
                    addr="",
                    tags=["notes_import", lane],
                    confidence=float(confidence),
                    source="notes_import",
                    source_type="human_notes",
                )
                imported += 1
                task_id = self._maybe_auto_trace_from_text(
                    store,
                    source_entry_id="",
                    source_text=text,
                    auto_trace=auto_trace,
                    depth=trace_depth,
                    limit=trace_limit,
                )
                if task_id:
                    trace_tasks.append(task_id)
        return {
            "ok": True,
            "path": os.path.abspath(notes_path),
            "imported": imported,
            "lane": lane,
            "trace_tasks_created": len(trace_tasks),
            "trace_task_ids": trace_tasks[:20],
        }

    def _validate_rename_spec(self, spec: Dict[str, Any]) -> Optional[str]:
        if not isinstance(spec, dict):
            return "rename_spec must be an object"
        renames = spec.get("renames")
        if not isinstance(renames, list) or not renames:
            return "rename_spec.renames must be a non-empty list"
        for idx, row in enumerate(renames):
            if not isinstance(row, dict):
                return f"rename_spec.renames[{idx}] must be an object"
            addr = str(row.get("addr") or "").strip()
            name = str(row.get("name") or "").strip()
            if not addr:
                return f"rename_spec.renames[{idx}].addr required"
            if not name:
                return f"rename_spec.renames[{idx}].name required"
        return None

    def _validate_patch_spec(self, spec: Dict[str, Any]) -> Optional[str]:
        if not isinstance(spec, dict):
            return "patch_spec must be an object"
        patches = spec.get("patches")
        if not isinstance(patches, list) or not patches:
            return "patch_spec.patches must be a non-empty list"
        for idx, row in enumerate(patches):
            if not isinstance(row, dict):
                return f"patch_spec.patches[{idx}] must be an object"
            addr = str(row.get("addr") or "").strip()
            asm = str(row.get("asm") or row.get("bytes") or "").strip()
            if not addr:
                return f"patch_spec.patches[{idx}].addr required"
            if not asm:
                return f"patch_spec.patches[{idx}].asm or .bytes required"
        return None

    def _validate_proposal_spec(self, proposal_type: str, spec: Dict[str, Any]) -> Optional[str]:
        if proposal_type == "rename":
            return self._validate_rename_spec(spec)
        if proposal_type == "patch":
            return self._validate_patch_spec(spec)
        if proposal_type == "type":
            if not isinstance(spec, dict):
                return "type_spec must be an object"
            items = spec.get("types")
            if not isinstance(items, list) or not items:
                return "type_spec.types must be a non-empty list"
            return None
        return None

    def _proposal_entries(self, store, status: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        entries = store.list(category="proposal", include_resolved=True, include_contradicted=True, limit=limit)
        if status:
            status = status.strip().lower()
            filtered = []
            for e in entries:
                tags = e.get("tags") or []
                if isinstance(tags, list) and f"status:{status}" in tags:
                    filtered.append(e)
            return filtered
        return entries

    def _proposal_status_replace(self, tags: List[str], new_status: str) -> List[str]:
        clean = [t for t in tags if not str(t).startswith("status:")]
        clean.append(f"status:{new_status}")
        return clean

    def _proposal_execute(self, proposal_type: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        if not hasattr(self, "_execute_tool"):
            return {"ok": True, "applied": 0, "note": "Execution hook unavailable in this runtime."}
        applied = []
        failed = []
        if proposal_type == "rename":
            for row in spec.get("renames", []):
                res = self._execute_tool("modify", {"action": "set_name", "addr": row.get("addr"), "name": row.get("name")})
                if isinstance(res, dict) and res.get("ok"):
                    applied.append({"addr": row.get("addr"), "name": row.get("name")})
                else:
                    failed.append({"addr": row.get("addr"), "name": row.get("name"), "error": res})
        elif proposal_type == "patch":
            for row in spec.get("patches", []):
                args = {"action": "patch_asm", "addr": row.get("addr"), "asm": row.get("asm")}
                if row.get("bytes"):
                    args = {"action": "patch_bytes", "addr": row.get("addr"), "data": row.get("bytes")}
                res = self._execute_tool("modify", args)
                if isinstance(res, dict) and res.get("ok"):
                    applied.append({"addr": row.get("addr")})
                else:
                    failed.append({"addr": row.get("addr"), "error": res})
        elif proposal_type == "type":
            for row in spec.get("types", []):
                res = self._execute_tool("modify", {"action": "set_type", "addr": row.get("addr"), "type_str": row.get("type_str")})
                if isinstance(res, dict) and res.get("ok"):
                    applied.append({"addr": row.get("addr"), "type_str": row.get("type_str")})
                else:
                    failed.append({"addr": row.get("addr"), "type_str": row.get("type_str"), "error": res})
        return {"ok": not failed, "applied": len(applied), "failed": failed, "applied_items": applied}

    def _proposal_verify(self, proposal_type: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        checks = []
        passed = 0
        total = 0
        if proposal_type == "rename":
            for row in spec.get("renames", []):
                addr = str(row.get("addr") or "")
                name = str(row.get("name") or "")
                total += 1
                ok = False
                detail = "no_runtime_check"
                if hasattr(self, "_execute_tool"):
                    try:
                        probe = self._execute_tool("search", {"action": "find", "query": name, "limit": 10})
                        text = json.dumps(probe, ensure_ascii=True).lower()
                        ok = name.lower() in text and addr.lower() in text
                        detail = "search_find_name+addr"
                    except Exception as exc:
                        detail = f"search_error:{exc}"
                checks.append({"kind": "rename", "addr": addr, "name": name, "ok": ok, "detail": detail})
                if ok:
                    passed += 1
        elif proposal_type == "patch":
            for row in spec.get("patches", []):
                addr = str(row.get("addr") or "")
                asm = str(row.get("asm") or row.get("bytes") or "")
                total += 1
                ok = False
                detail = "no_runtime_check"
                if hasattr(self, "_execute_tool"):
                    try:
                        probe = self._execute_tool("code", {"action": "disasm", "addr": addr, "limit": 8})
                        text = json.dumps(probe, ensure_ascii=True).lower()
                        asm_tok = asm.split()[0].lower() if asm else ""
                        ok = addr.lower() in text and (asm_tok in text if asm_tok else True)
                        detail = "code_disasm_addr+asm"
                    except Exception as exc:
                        detail = f"disasm_error:{exc}"
                checks.append({"kind": "patch", "addr": addr, "asm": asm, "ok": ok, "detail": detail})
                if ok:
                    passed += 1
        elif proposal_type == "type":
            for row in spec.get("types", []):
                addr = str(row.get("addr") or "")
                type_str = str(row.get("type_str") or "")
                total += 1
                ok = False
                detail = "no_runtime_check"
                if hasattr(self, "_execute_tool"):
                    try:
                        probe = self._execute_tool("types", {"action": "get", "addr": addr})
                        text = json.dumps(probe, ensure_ascii=True).lower()
                        ok = type_str.lower() in text
                        detail = "types_get_match"
                    except Exception as exc:
                        detail = f"types_error:{exc}"
                checks.append({"kind": "type", "addr": addr, "type_str": type_str, "ok": ok, "detail": detail})
                if ok:
                    passed += 1
        if total == 0:
            return {"ok": False, "checks": checks, "count": 0, "passed": 0, "message": "No verification checks generated."}
        return {
            "ok": passed == total,
            "checks": checks,
            "count": total,
            "passed": passed,
            "failed": total - passed,
        }

    def _extract_trace_entities(self, text: str) -> Dict[str, Any]:
        addrs = sorted(set(m.group(0) for m in _ADDR_RE.finditer(text or "")))
        symbols = []
        for m in _SYMBOL_RE.finditer(text or ""):
            s = m.group(0)
            if s.lower().startswith("lane_"):
                continue
            if s.lower().startswith("status"):
                continue
            if s.startswith("0x"):
                continue
            symbols.append(s)
        symbols = sorted(set(symbols))[:50]
        pairs = []
        for m in _ADDR_NAME_RE.finditer(text or ""):
            addr = m.group("addr")
            name = m.group("name")
            if addr and name:
                pairs.append({"addr": addr, "name": name})
        seen = set()
        uniq_pairs = []
        for p in pairs:
            key = (p["addr"], p["name"])
            if key in seen:
                continue
            seen.add(key)
            uniq_pairs.append(p)
        return {"addrs": addrs, "symbols": symbols, "addr_name_pairs": uniq_pairs}

    def _create_trace_task(self, store, source_entry_id: str, source_text: str, depth: int, limit: int) -> str:
        entities = self._extract_trace_entities(source_text)
        payload = {
            "source_entry_id": source_entry_id,
            "depth": depth,
            "limit": limit,
            "entities": entities,
            "status": "pending",
        }
        title = f"trace_task from {source_entry_id or 'text'} ({len(entities.get('addrs', []))} addrs)"
        return store.write(
            title=title,
            content=json.dumps(payload, ensure_ascii=True),
            category="trace_task",
            addr=(entities.get("addrs") or [""])[0],
            tags=["trace_task", "status:pending"],
            confidence=0.7,
            source="trace_ingest",
            source_type="trace",
        )

    def _maybe_auto_trace_from_text(
        self,
        store,
        source_entry_id: str,
        source_text: str,
        auto_trace: bool = True,
        depth: int = 2,
        limit: int = 8,
    ) -> Optional[str]:
        if not auto_trace:
            return None
        entities = self._extract_trace_entities(source_text or "")
        if not entities.get("addrs") and not entities.get("addr_name_pairs"):
            return None
        return self._create_trace_task(
            store,
            source_entry_id=source_entry_id,
            source_text=source_text,
            depth=depth,
            limit=limit,
        )

    def _set_task_status(self, store, entry: Dict[str, Any], status: str, payload: Dict[str, Any]) -> None:
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        new_tags = [t for t in tags if not str(t).startswith("status:")]
        new_tags.append(f"status:{status}")
        store.update(entry.get("id"), tags=new_tags, content=json.dumps(payload, ensure_ascii=True))

    def _auto_proposals_from_trace(self, store, trace_entry_id: str, pairs: List[Dict[str, str]]) -> int:
        created = 0
        for p in pairs:
            spec = {"renames": [{"addr": p.get("addr"), "name": p.get("name")}]}
            err = self._validate_rename_spec(spec)
            if err:
                continue
            title = f"rename proposal from trace {trace_entry_id}: {p.get('addr')} -> {p.get('name')}"
            if store.exists_similar(str(p.get("addr") or ""), "proposal", title):
                continue
            content = json.dumps(
                {
                    "proposal_type": "rename",
                    "spec": spec,
                    "verification_spec": {"kind": "symbol_name_match"},
                    "status": "proposed",
                    "source_trace_task": trace_entry_id,
                },
                ensure_ascii=True,
            )
            store.write(
                title=title,
                content=content,
                category="proposal",
                addr=str(p.get("addr") or ""),
                tags=["proposal_lifecycle", "status:proposed", "proposal_type:rename", "trace_auto"],
                confidence=0.68,
                source="trace_auto",
                source_type="proposal",
            )
            created += 1
        return created

    def _run_trace_task(self, store, entry: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
        entities = payload.get("entities") or {}
        addrs = entities.get("addrs") or []
        symbols = entities.get("symbols") or []
        pairs = list(entities.get("addr_name_pairs") or [])
        depth = int(payload.get("depth") or 2)
        limit = int(payload.get("limit") or 8)
        collected = []
        for addr in addrs[:limit]:
            if hasattr(self, "_execute_tool"):
                try:
                    xr = self._execute_tool(
                        "xref_analysis",
                        {"action": "influence", "addr": addr, "depth": depth, "limit": 12, "include_items": True},
                    )
                    if isinstance(xr, dict):
                        collected.append({"kind": "xref", "addr": addr, "result": xr})
                except Exception as exc:
                    collected.append({"kind": "xref_error", "addr": addr, "error": str(exc)})
        for sym in symbols[:5]:
            if hasattr(self, "_execute_tool"):
                try:
                    sr = self._execute_tool("search", {"action": "find", "query": sym, "limit": 5})
                    if isinstance(sr, dict):
                        collected.append({"kind": "symbol", "symbol": sym, "result": sr})
                except Exception as exc:
                    collected.append({"kind": "symbol_error", "symbol": sym, "error": str(exc)})

        # Derive additional addr->name pairs from simplistic evidence text
        for item in collected:
            text = json.dumps(item, ensure_ascii=True)
            parsed = self._extract_trace_entities(text)
            for pair in parsed.get("addr_name_pairs", []):
                if pair not in pairs:
                    pairs.append(pair)

        derived_summary = {
            "trace_task_id": entry.get("id"),
            "evidence_count": len(collected),
            "addrs": addrs[:limit],
            "symbols": symbols[:8],
            "pairs": pairs[:20],
        }
        store.write(
            title=f"trace evidence {entry.get('id')}",
            content=json.dumps(derived_summary, ensure_ascii=True),
            category="hypothesis",
            addr=(addrs or [""])[0],
            tags=["trace_derived", "evidence"],
            confidence=0.62,
            source="trace_run",
            source_type="trace",
        )
        proposal_count = self._auto_proposals_from_trace(store, str(entry.get("id")), pairs[:20])
        return {
            "ok": True,
            "evidence_count": len(collected),
            "derived_pairs": len(pairs),
            "proposals_created": proposal_count,
        }

    def _get_blackboard_store(self):
        """
        Return a BlackboardStore scoped to the current session's IDB path.
        Creates a new store object per session so binaries don't share findings.
        Falls back to the cached global store when no session is active.
        """
        try:
            if type(self)._blackboard_module is None:
                import importlib.util
                bb_path = os.path.join(SCRIPT_DIR, "..", "ida_mcp", "tools", "blackboard.py")
                bb_path = os.path.abspath(bb_path)
                spec = importlib.util.spec_from_file_location("_host_blackboard", bb_path)
                mod = importlib.util.module_from_spec(spec)
                mod.__dict__["tool"] = lambda f: f
                mod.__dict__["idaread"] = lambda f: f
                mod.__dict__["idawrite"] = lambda f: f
                mod.__dict__["IDAError"] = Exception
                spec.loader.exec_module(mod)
                type(self)._blackboard_module = mod
            mod = type(self)._blackboard_module
            # Per-binary scoping: derive path from current session IDB
            idb = None
            if self.current_session and getattr(self.current_session, "idb_path", None):
                idb = self.current_session.idb_path + ".blackboard.db"
            return mod.BlackboardStore(db_path=idb)
        except Exception:
            # Last-resort fallback: global store
            if type(self)._blackboard_store is None:
                try:
                    type(self)._blackboard_store = type(self)._blackboard_module.BlackboardStore()
                except Exception:
                    return None
            return type(self)._blackboard_store

    def _binary_sha256(self, binary_path: str) -> str:
        try:
            if not binary_path or not os.path.exists(binary_path):
                return ""
            h = hashlib.sha256()
            with open(binary_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _export_session_hypotheses_to_symbol_db(self, sid: str, session_obj=None) -> int:
        try:
            sess = session_obj or self.session_mgr.get_session(sid)
            if not sess:
                return 0
            hyps = self.session_mgr.get_high_confidence_hypotheses(sid, min_confidence=0.8)
            if not hyps:
                return 0
            bin_hash = self._binary_sha256(str(getattr(sess, "binary_path", "") or ""))
            chip = str((getattr(sess, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            baseaddr = 0
            try:
                raw_base = (getattr(sess, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            sdb = SymbolDB()
            count = 0
            for h in hyps:
                text = str(h.get("statement") or h.get("title") or "").strip()
                if not text:
                    continue
                m = re.search(r"0x[0-9a-fA-F]+", text)
                if not m:
                    continue
                try:
                    addr = int(m.group(0), 16)
                except Exception:
                    continue
                addr_offset = addr - baseaddr if baseaddr and addr >= baseaddr else addr
                conf = float(h.get("confidence", 0.8) or 0.8)
                rid = sdb.upsert_hypothesis(
                    binary_hash=bin_hash,
                    chip_family=chip,
                    addr_offset=int(addr_offset),
                    hypothesis_text=text,
                    confidence=conf,
                    source_session=sid,
                    source_binary=str(getattr(sess, "binary_path", "") or ""),
                )
                if rid:
                    count += 1
            return int(count)
        except Exception:
            return 0

    def _import_cross_session_hypotheses(self, session_obj) -> int:
        try:
            if not session_obj:
                return 0
            bin_hash = self._binary_sha256(str(getattr(session_obj, "binary_path", "") or ""))
            chip = str((getattr(session_obj, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            sdb = SymbolDB()
            hits = sdb.query_hypotheses(binary_hash=bin_hash, chip_family=chip, limit=200)
            if not hits:
                return 0
            baseaddr = 0
            try:
                raw_base = (getattr(session_obj, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            bb_path = str(getattr(session_obj, "idb_path", "") or "") + ".blackboard.db"
            store = type(self)._blackboard_module.BlackboardStore(db_path=bb_path) if type(self)._blackboard_module else self._get_blackboard_store()
            if store is None:
                return 0
            imported = 0
            for row in hits:
                title = str(row.get("hypothesis_text") or "").strip()
                if not title:
                    continue
                off = int(row.get("addr_offset", 0) or 0)
                addr = hex((baseaddr + off) if baseaddr else off)
                if store.exists_similar(addr, "hypothesis", title):
                    continue
                store.write(
                    title=title,
                    content=f"Imported from prior session ({row.get('source_session', '')})",
                    category="hypothesis",
                    addr=addr,
                    tags=["cross_session", "symboldb"],
                    confidence=float(row.get("confidence", 0.8) or 0.8),
                    source="symbol_db.import",
                    source_type="cross_session",
                )
                imported += 1
            return int(imported)
        except Exception:
            return 0

    def _handle_blackboard(self, args: dict) -> dict:
        """Host-side blackboard handler so it works without IDA runtime."""
        policy_state = self._bb_policy_bump()
        phase_state = self._phase_state()
        action = str(args.get("action") or "list").strip().lower()
        policy_only_actions = {"policy_set", "policy_status", "policy_check", "phase_status", "phase_set"}
        store = None
        if action not in policy_only_actions:
            store = self._get_blackboard_store()
            if store is None:
                return make_error(MCPError.IO_ERROR, "BlackboardStore unavailable")
        self._phase_log_action(phase_state, action, addr=str(args.get("addr") or "").strip())
        if store is not None:
            self._phase_auto_transition(phase_state, action, args if isinstance(args, dict) else {}, store)
            phase_block = self._phase_contract_check(phase_state, action, args if isinstance(args, dict) else {}, store)
        else:
            phase_block = None
        if phase_block and action not in {"phase_status", "phase_set", "working_set", "list", "read", "search", "state_health", "policy_set", "policy_status", "policy_check"}:
            return phase_block
        if self._phase_find_loop(phase_state):
            self._phase_transition(phase_state, "prove", "auto: loop detected, injecting escape-route")
        if action == "policy_set":
            strict_mode = bool(args.get("strict_mode", policy_state.get("strict_mode", False)))
            max_age = _bounded_int(args.get("max_staleness_calls", policy_state.get("max_staleness_calls", 6)), 6, min_value=1, max_value=100)
            require_ws = bool(args.get("require_working_set", policy_state.get("require_working_set", True)))
            require_dw = bool(args.get("require_decision_or_write", policy_state.get("require_decision_or_write", True)))
            enforce_phases = args.get("enforce_phases", policy_state.get("enforce_phases", ["commit", "finalize"]))
            if isinstance(enforce_phases, str):
                enforce_phases = [p.strip() for p in enforce_phases.split(",") if p.strip()]
            if not isinstance(enforce_phases, list) or not enforce_phases:
                enforce_phases = ["commit", "finalize"]
            policy_state["strict_mode"] = strict_mode
            policy_state["max_staleness_calls"] = max_age
            policy_state["require_working_set"] = require_ws
            policy_state["require_decision_or_write"] = require_dw
            policy_state["enforce_phases"] = [str(p).strip().lower() for p in enforce_phases]
            check = self._bb_policy_check(policy_state)
            check["ok"] = True
            check["note"] = "Policy updated."
            return check
        if action == "policy_status":
            return {"ok": True, "policy": self._bb_policy_snapshot(policy_state), "phase": self._phase_snapshot(phase_state, store)}
        if action == "policy_check":
            out = self._bb_policy_check(policy_state)
            out["phase"] = self._phase_snapshot(phase_state, store)
            return out
        if action == "phase_status":
            return {"ok": True, "phase": self._phase_snapshot(phase_state, store)}
        if action == "phase_set":
            phase = str(args.get("phase") or "").strip().lower()
            if phase not in {"scout", "prove", "commit", "finalize"}:
                return make_error(MCPError.INVALID_ARGS, "phase must be one of: scout, prove, commit, finalize")
            auto = bool(args.get("auto_transition", phase_state.get("auto_transition", True)))
            phase_state["auto_transition"] = auto
            self._phase_transition(phase_state, phase, "manual set")
            return {"ok": True, "phase": self._phase_snapshot(phase_state, store)}
        if action == "phase_tick":
            limit = _bounded_int(args.get("limit", 3), 3, min_value=1, max_value=20)
            return self._phase_tick(phase_state, store, limit=limit)
        if action == "quest_board":
            entry_id = str(args.get("entry_id") or "").strip()
            limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200)
            return self._quest_board(store, entry_id=entry_id, limit=limit)
        if action == "quest_complete":
            quest_id = str(args.get("quest_id") or "").strip()
            quest_type = str(args.get("quest_type") or "").strip()
            status = str(args.get("status") or "completed")
            result_text = str(args.get("result") or args.get("notes") or "")
            evidence = _coerce_str_list(args.get("evidence"))
            entry_id = str(args.get("entry_id") or "").strip()
            addr = str(args.get("addr") or "").strip()
            return self._quest_complete(
                store,
                quest_id=quest_id,
                quest_type=quest_type,
                status=status,
                result_text=result_text,
                evidence=evidence,
                entry_id=entry_id,
                addr=addr,
            )
        if action in {"memory_compile", "phase_finalize"}:
            result = self._memory_compile(
                store,
                limit=_bounded_int(args.get("limit", 30), 30, min_value=5, max_value=200),
                notes_path=str(args.get("notes_path") or args.get("path") or "").strip(),
            )
            result["phase"] = self._phase_snapshot(phase_state, store)
            return result
        strict_guard_actions = {"proposal_accept", "trace_run", "accept_proposal"}
        current_phase = str((phase_state or {}).get("phase") or "scout")
        if self._bb_policy_enforced_for_phase(policy_state, current_phase) and action in strict_guard_actions:
            check = self._bb_policy_check(policy_state)
            if not check.get("ok"):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Strict policy gate failed before execution",
                    hint=json.dumps(
                        {
                            "reasons": check.get("reasons", []),
                            "recommendation": check.get("recommendation"),
                        },
                        ensure_ascii=True,
                    ),
                )
        if action == "write":
            title = str(args.get("name") or args.get("title") or "").strip()
            if not title:
                return make_error(MCPError.INVALID_ARGS, "name/title required for write")
            # Parse Cartographer-μ metadata if provided
            bridges_raw = str(args.get("bridges") or "")
            bridges = [b.strip() for b in bridges_raw.split(",") if b.strip()]
            schema_str = str(args.get("schema") or "")
            schema = {}
            if schema_str:
                try:
                    schema = json.loads(schema_str)
                except Exception:
                    pass
            vector = args.get("vector")
            quantized = args.get("quantized")
            q_signs = args.get("q_signs")
            norm = float(args.get("norm", 0.0))
            q_value = float(args.get("q_value", 0.5))
            call_idx = int(args.get("call_idx", 0))
            raw_tags = args.get("tags")
            if isinstance(raw_tags, list):
                tags = [str(t).strip() for t in raw_tags if str(t).strip()]
            elif isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            else:
                tags = []

            eid = store.write(
                title=title,
                content=str(args.get("notes") or args.get("content") or ""),
                category=str(args.get("category") or "general"),
                addr=str(args.get("addr") or ""),
                tags=tags,
                confidence=float(args.get("confidence", 0.5)),
                bridges=bridges,
                schema=schema,
                vector=vector,
                quantized=quantized,
                q_signs=q_signs,
                norm=norm,
                q_value=q_value,
                call_idx=call_idx,
            )
            self._bb_policy_mark(policy_state, "write")
            gravity = self._evidence_gravity(store, source_entry_id=eid, addr=str(args.get("addr") or ""), source_text=str(args.get("notes") or args.get("content") or ""))
            return {"ok": True, "entry_id": eid, "action": "write", "gravity": gravity, "phase": self._phase_snapshot(phase_state, store)}
        if action == "decision_card":
            claim = str(args.get("claim") or args.get("title") or "").strip()
            if not claim:
                return make_error(MCPError.INVALID_ARGS, "claim/title required for decision_card")
            lane = str(args.get("lane") or "lane_hypotheses").strip()
            category = _LANE_CATEGORY.get(lane, "hypothesis")
            evidence_for = _coerce_str_list(args.get("evidence_for"))
            evidence_against = _coerce_str_list(args.get("evidence_against"))
            next_step = str(args.get("next_step") or args.get("next_verification_step") or "").strip()
            expires_hours = int(args.get("expires_hours") or 0)
            card = {
                "claim": claim,
                "evidence_for": evidence_for,
                "evidence_against": evidence_against,
                "next_verification_step": next_step,
                "expires_after_hours": expires_hours,
                "created_by": "decision_card",
            }
            tag_list = [lane, "decision_card"]
            addr = str(args.get("addr") or "").strip()
            conf = float(args.get("confidence", 0.65))
            content = json.dumps(card, ensure_ascii=True)
            eid = store.write(
                title=claim,
                content=content,
                category=category,
                addr=addr,
                tags=tag_list,
                confidence=conf,
                source="decision_card",
                source_type="decision_card",
            )
            self._bb_policy_mark(policy_state, "decision")
            auto_trace = bool(args.get("auto_trace", True))
            trace_depth = _bounded_int(args.get("trace_depth", 2), 2, min_value=1, max_value=6)
            trace_limit = _bounded_int(args.get("trace_limit", 8), 8, min_value=1, max_value=50)
            trace_task_id = self._maybe_auto_trace_from_text(
                store,
                source_entry_id=eid,
                source_text=f"{claim}\n{card.get('next_verification_step') or ''}\n{addr}",
                auto_trace=auto_trace,
                depth=trace_depth,
                limit=trace_limit,
            )
            gravity = self._evidence_gravity(store, source_entry_id=eid, addr=addr, source_text=claim)
            return {
                "ok": True,
                "entry_id": eid,
                "lane": lane,
                "card": card,
                "trace_task_id": trace_task_id,
                "gravity": gravity,
                "phase": self._phase_snapshot(phase_state, store),
                "note": "Decision card stored. Use working_set to verify it appears in the active lane.",
            }
        if action == "proposal_create":
            proposal_type = str(args.get("proposal_type") or args.get("type") or "").strip().lower()
            if proposal_type not in {"rename", "patch", "type"}:
                return make_error(MCPError.INVALID_ARGS, "proposal_type must be one of: rename, patch, type")
            title = str(args.get("title") or f"{proposal_type} proposal").strip()
            spec_raw = args.get("spec")
            if isinstance(spec_raw, str):
                try:
                    spec_raw = json.loads(spec_raw)
                except Exception:
                    return make_error(MCPError.INVALID_ARGS, "spec must be a JSON object")
            if not isinstance(spec_raw, dict):
                return make_error(MCPError.INVALID_ARGS, "spec must be an object")
            err = self._validate_proposal_spec(proposal_type, spec_raw)
            if err:
                return make_error(MCPError.INVALID_ARGS, err)
            content = json.dumps(
                {
                    "proposal_type": proposal_type,
                    "spec": spec_raw,
                    "verification_spec": args.get("verification_spec") or {},
                    "status": "proposed",
                },
                ensure_ascii=True,
            )
            confidence = float(args.get("confidence", 0.7))
            tags = [f"proposal_type:{proposal_type}", "status:proposed", "proposal_lifecycle"]
            eid = store.write(
                title=title,
                content=content,
                category="proposal",
                addr=str(args.get("addr") or "").strip(),
                tags=tags,
                confidence=confidence,
                source="proposal_create",
                source_type="proposal",
            )
            return {"ok": True, "proposal_id": eid, "status": "proposed", "proposal_type": proposal_type, "phase": self._phase_snapshot(phase_state, store)}
        if action == "proposal_list":
            status = str(args.get("status") or "").strip().lower()
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=500)
            entries = self._proposal_entries(store, status=status, limit=limit)
            parsed = []
            for e in entries:
                payload = {}
                try:
                    payload = json.loads(str(e.get("content") or "{}"))
                except Exception:
                    payload = {}
                parsed.append(
                    {
                        "proposal_id": e.get("id"),
                        "title": e.get("title"),
                        "confidence": e.get("confidence"),
                        "status": next((t.split(":", 1)[1] for t in (e.get("tags") or []) if str(t).startswith("status:")), "unknown"),
                        "proposal_type": payload.get("proposal_type") or "unknown",
                        "spec": payload.get("spec") or {},
                    }
                )
            return {"ok": True, "count": len(parsed), "proposals": parsed, "phase": self._phase_snapshot(phase_state, store)}
        if action == "proposal_accept":
            proposal_id = str(args.get("proposal_id") or args.get("entry_id") or "").strip()
            if not proposal_id:
                return make_error(MCPError.INVALID_ARGS, "proposal_id required")
            entry = store.read(proposal_id)
            if not entry or str(entry.get("category") or "") != "proposal":
                return make_error(MCPError.NOT_FOUND, f"Proposal '{proposal_id}' not found")
            payload = {}
            try:
                payload = json.loads(str(entry.get("content") or "{}"))
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "Proposal content is not valid JSON")
            proposal_type = str(payload.get("proposal_type") or "").strip().lower()
            spec = payload.get("spec") or {}
            err = self._validate_proposal_spec(proposal_type, spec)
            if err:
                return make_error(MCPError.INVALID_ARGS, f"Proposal spec invalid: {err}")
            dry_run = bool(args.get("dry_run", False))
            tags = entry.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            if dry_run:
                verify = self._proposal_verify(proposal_type, spec)
                new_tags = self._proposal_status_replace(tags, "accepted")
                store.update(proposal_id, tags=new_tags)
                return {
                    "ok": True,
                    "proposal_id": proposal_id,
                    "status": "accepted",
                    "dry_run": True,
                    "verification": verify,
                }
            exec_res = self._proposal_execute(proposal_type, spec)
            verify = self._proposal_verify(proposal_type, spec)
            status = "verified" if (exec_res.get("ok") and verify.get("ok")) else "failed"
            new_tags = self._proposal_status_replace(tags, status)
            meta = payload
            meta["status"] = status
            meta["last_apply"] = exec_res
            meta["last_verify"] = verify
            store.update(proposal_id, tags=new_tags, content=json.dumps(meta, ensure_ascii=True))
            store.write(
                title=f"proposal_feedback {proposal_id} {status}",
                content=json.dumps(
                    {
                        "proposal_id": proposal_id,
                        "proposal_type": proposal_type,
                        "status": status,
                        "execution_ok": bool(exec_res.get("ok")),
                        "verification_ok": bool(verify.get("ok")),
                        "verification": verify,
                    },
                    ensure_ascii=True,
                ),
                category="proposal_feedback",
                addr=str(entry.get("addr") or ""),
                tags=[f"proposal_id:{proposal_id}", f"status:{status}", "proposal_feedback"],
                confidence=1.0 if status == "verified" else 0.3,
                source="proposal_accept",
                source_type="proposal_feedback",
            )
            return {
                "ok": bool(exec_res.get("ok") and verify.get("ok")),
                "proposal_id": proposal_id,
                "status": status,
                "execution": exec_res,
                "verification": verify,
                "phase": self._phase_snapshot(phase_state, store),
            }
        if action == "proposal_reject":
            proposal_id = str(args.get("proposal_id") or args.get("entry_id") or "").strip()
            if not proposal_id:
                return make_error(MCPError.INVALID_ARGS, "proposal_id required")
            entry = store.read(proposal_id)
            if not entry or str(entry.get("category") or "") != "proposal":
                return make_error(MCPError.NOT_FOUND, f"Proposal '{proposal_id}' not found")
            reason = str(args.get("reason") or "rejected_by_llm").strip()
            tags = entry.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            new_tags = self._proposal_status_replace(tags, "rejected")
            ok = store.update(proposal_id, tags=new_tags)
            if not ok:
                return make_error(MCPError.IO_ERROR, f"Failed to reject proposal '{proposal_id}'")
            store.write(
                title=f"Rejected proposal {proposal_id}",
                content=reason,
                category="dead_end",
                addr=str(entry.get("addr") or ""),
                tags=["proposal_rejected"],
                confidence=1.0,
                source="proposal_reject",
                source_type="proposal",
            )
            return {"ok": True, "proposal_id": proposal_id, "status": "rejected", "reason": reason, "phase": self._phase_snapshot(phase_state, store)}
        if action == "trace_ingest":
            source_entry_id = str(args.get("entry_id") or args.get("source_entry_id") or "").strip()
            source_text = str(args.get("text") or "").strip()
            if source_entry_id and not source_text:
                src = store.read(source_entry_id)
                if not src:
                    return make_error(MCPError.NOT_FOUND, f"Entry '{source_entry_id}' not found")
                source_text = f"{src.get('title') or ''}\n{src.get('content') or ''}"
            if not source_text:
                return make_error(MCPError.INVALID_ARGS, "trace_ingest requires text or entry_id")
            depth = _bounded_int(args.get("depth", 2), 2, min_value=1, max_value=6)
            limit = _bounded_int(args.get("limit", 8), 8, min_value=1, max_value=50)
            task_id = self._create_trace_task(store, source_entry_id, source_text, depth=depth, limit=limit)
            return {"ok": True, "trace_task_id": task_id, "status": "pending", "phase": self._phase_snapshot(phase_state, store)}
        if action == "trace_status":
            status = str(args.get("status") or "").strip().lower()
            limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=500)
            tasks = store.list(
                category="trace_task",
                include_resolved=True,
                include_contradicted=True,
                limit=limit,
            )
            if status:
                tasks = [t for t in tasks if f"status:{status}" in (t.get("tags") or [])]
            summaries = []
            for t in tasks:
                payload = {}
                try:
                    payload = json.loads(str(t.get("content") or "{}"))
                except Exception:
                    payload = {}
                summaries.append(
                    {
                        "trace_task_id": t.get("id"),
                        "title": t.get("title"),
                        "status": next((x.split(":", 1)[1] for x in (t.get("tags") or []) if str(x).startswith("status:")), "unknown"),
                        "addrs": (payload.get("entities") or {}).get("addrs", [])[:10],
                        "symbols": (payload.get("entities") or {}).get("symbols", [])[:10],
                        "result": payload.get("result") or {},
                    }
                )
            return {"ok": True, "count": len(summaries), "tasks": summaries, "phase": self._phase_snapshot(phase_state, store)}
        if action == "trace_run":
            limit = _bounded_int(args.get("limit", 3), 3, min_value=1, max_value=20)
            pending = [
                e for e in store.list(
                    category="trace_task",
                    include_resolved=True,
                    include_contradicted=True,
                    limit=200,
                )
                if isinstance(e.get("tags"), list) and "status:pending" in e.get("tags")
            ]
            ran = []
            for entry in pending[:limit]:
                payload = {}
                try:
                    payload = json.loads(str(entry.get("content") or "{}"))
                except Exception:
                    payload = {}
                self._set_task_status(store, entry, "running", payload)
                result = self._run_trace_task(store, entry, payload)
                payload["status"] = "done" if result.get("ok") else "failed"
                payload["result"] = result
                self._set_task_status(store, entry, payload["status"], payload)
                ran.append({"trace_task_id": entry.get("id"), **result})
            return {"ok": True, "ran": len(ran), "results": ran, "phase": self._phase_snapshot(phase_state, store)}
        if action == "working_set":
            limit = _bounded_int(args.get("limit", 10), 10, min_value=1, max_value=50)
            lanes = {}
            for lane in ("lane_now", "lane_hypotheses", "lane_facts", "lane_queue", "lane_dead_ends"):
                lane_entries = self._lane_fetch(store, lane, limit)
                lanes[lane] = {
                    "count": len(lane_entries),
                    "items": [_entry_brief(e) for e in lane_entries[:limit]],
                }
            self._bb_policy_mark(policy_state, "working_set")
            if self._phase_find_loop(phase_state):
                escape = store.next_target(limit=3)
            else:
                escape = []
            return {
                "ok": True,
                "lanes": lanes,
                "state_health": self._state_health(store),
                "policy_check": self._bb_policy_check(policy_state),
                "phase": self._phase_snapshot(phase_state, store),
                "escape_route_targets": escape,
                "note": "Read lane_now and lane_queue first, then verify/resolve hypothesis cards.",
            }
        if action == "state_health":
            return {"ok": True, **self._state_health(store), "phase": self._phase_snapshot(phase_state, store)}
        if action == "notes_export":
            notes_path = str(args.get("notes_path") or args.get("path") or "re_notes.md").strip()
            limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=100)
            return self._notes_export(store, notes_path, limit=limit)
        if action == "notes_import":
            notes_path = str(args.get("notes_path") or args.get("path") or "re_notes.md").strip()
            lane = str(args.get("lane") or "lane_hypotheses").strip()
            confidence = float(args.get("confidence", 0.65))
            auto_trace = bool(args.get("auto_trace", False))
            trace_depth = _bounded_int(args.get("trace_depth", 2), 2, min_value=1, max_value=6)
            trace_limit = _bounded_int(args.get("trace_limit", 8), 8, min_value=1, max_value=50)
            return self._notes_import(
                store,
                notes_path,
                lane=lane,
                confidence=confidence,
                auto_trace=auto_trace,
                trace_depth=trace_depth,
                trace_limit=trace_limit,
            )
        if action == "list":
            entries = store.list(
                category=str(args.get("category") or "").strip() or None,
                addr=str(args.get("addr") or "").strip() or None,
                tag=str(args.get("tag") or "").strip() or None,
                min_confidence=float(args.get("min_confidence", 0.0)),
                limit=_bounded_int(args.get("limit", 100), 100, min_value=1, max_value=1000),
                offset=_bounded_int(args.get("offset", 0), 0, min_value=0),
            )
            return {"ok": True, "entries": entries, "count": len(entries), "summary": _entry_collection_summary(entries)}
        if action == "search":
            query = str(args.get("query") or args.get("pattern") or "").strip()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query/pattern required for blackboard search")
            entries = store.semantic_search(
                query=query,
                top_k=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500),
                threshold=float(args.get("threshold", 0.4)),
                category=str(args.get("category") or "").strip() or None,
                include_resolved=bool(args.get("include_resolved", True)),
                include_contradicted=bool(args.get("include_contradicted", False)),
            )
            return {"ok": True, "query": query, "entries": entries, "count": len(entries), "summary": _entry_collection_summary(entries)}
        if action == "read":
            entry = store.read(str(args.get("entry_id") or ""))
            if entry is None:
                return make_error(MCPError.INVALID_ARGS, "Entry not found")
            return {"ok": True, "entry": entry, "summary": _entry_brief(entry)}
        if action == "update":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            updates = {
                k: v
                for k, v in (args or {}).items()
                if k
                not in {
                    "action",
                    "entry_id",
                }
            }
            if not updates:
                return make_error(MCPError.INVALID_ARGS, "No update fields provided")
            ok = store.update(entry_id, **updates)
            return {"ok": ok, "action": "update", "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found or no valid fields")
        if action == "delete":
            ok = store.delete(str(args.get("entry_id") or ""))
            return {"ok": ok, "action": "delete"}
        if action == "clear":
            count = store.clear(category=str(args.get("category") or "").strip() or None)
            return {"ok": True, "deleted": count}
        if action == "stats":
            return {"ok": True, **store.stats()}
        if action == "merge":
            result = store.auto_merge(
                addr=str(args.get("addr") or "").strip(),
                category=str(args.get("category") or "").strip(),
                similarity_threshold=float(args.get("similarity_threshold", 0.85)),
            )
            return {"ok": True, **result}
        if action == "prune":
            result = store.prune(
                max_entries=_bounded_int(args.get("max_entries", 1000), 1000, min_value=1, max_value=100000),
                min_q_value=float(args.get("min_q_value", 0.0)),
                older_than_days=int(args.get("older_than_days", 0)),
            )
            return {"ok": True, **result}
        if action == "contradict":
            eid = str(args.get("entry_id") or "").strip()
            reason = str(args.get("reason") or "").strip()
            if not eid or not reason:
                return make_error(MCPError.INVALID_ARGS, "entry_id and reason required")
            ok = store.contradict(eid, reason)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "resolve":
            eid = str(args.get("entry_id") or "").strip()
            if not eid:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            ok = store.mark_resolved(eid)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "next_target":
            targets = store.next_target(limit=int(args.get("limit") or 5))
            return {"ok": True, "targets": targets, "count": len(targets),
                    "summary": _target_collection_summary(targets),
                    "note": "Highest-priority unexplored addresses. Use code(action='decompile') on the top target."}
        if action == "frontier":
            try:
                from .frontier import FrontierEngine
                emb_db = os.path.join(self.cache_dir, "embeddings.sqlite3")
                fe = FrontierEngine(emb_db, getattr(store, "db_path", None))
                results = fe.frontier(limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200))
                return {"ok": True, "frontier": results, "count": len(results), "summary": _frontier_collection_summary(results)}
            except Exception as e:
                return make_error(MCPError.IO_ERROR, f"frontier unavailable: {e}")
        if action == "propagate_labels":
            try:
                from .frontier import FrontierEngine
                emb_db = os.path.join(self.cache_dir, "embeddings.sqlite3")
                fe = FrontierEngine(emb_db, getattr(store, "db_path", None))
                n = fe.refresh()
                if n < 3:
                    return {"ok": True, "propagated": 0, "entries": [], "count": 0,
                            "summary": {"count": 0, "briefs": []},
                            "note": "Not enough embeddings to propagate labels yet."}
                propagated = fe.propagate_labels()
                return {
                    "ok": True,
                    "propagated": len(propagated),
                    "entries": propagated[:20],
                    "count": len(propagated),
                    "summary": _proposal_collection_summary(propagated),
                    "note": (
                        f"Propagated {len(propagated)} labels to embedding neighbors. "
                        "Review the generated entries, then keep or contradict the false positives."
                    ),
                }
            except Exception as e:
                return make_error(MCPError.IO_ERROR, f"propagate_labels unavailable: {e}")
        if action == "add_evidence":
            entry_id = str(args.get("entry_id") or "").strip()
            evidence_type = str(args.get("evidence_type") or args.get("type") or "").strip()
            value = str(args.get("value") or "").strip()
            if not entry_id or not evidence_type or not value:
                return make_error(MCPError.INVALID_ARGS, "entry_id, evidence_type/type, and value required")
            ok = store.add_evidence(entry_id, evidence_type=evidence_type, value=value, weight=float(args.get("weight", 1.0)))
            return {"ok": ok, "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
        if action == "calibrate":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            new_conf = store.calibrate_confidence(entry_id)
            if new_conf is None:
                return make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
            return {"ok": True, "entry_id": entry_id, "confidence": new_conf}
        if action == "campaign_summary":
            return {"ok": True, "summary": store.campaign_summary()}
        if action == "auto_tag_propagate":
            updated = store.auto_tag_propagate()
            return {"ok": True, "updated": int(updated)}
        if action in ("start_crawler", "stop_crawler", "crawler_status", "accept", "reject"):
            # Delegate to the tool module which owns the crawler singleton
            mod = type(self)._blackboard_module
            if mod is None:
                return make_error(MCPError.IO_ERROR, "BlackboardStore unavailable")
            crawler = mod._BackgroundCrawler.instance()
            if action == "start_crawler":
                crawler.start(notify_fn=self._send_notification)
                return {"ok": True, "running": crawler.is_running(),
                        "note": "Crawler uses frontier targets and runs agent(action='quick') every 0.5s."}
            elif action == "stop_crawler":
                crawler.stop()
                return {"ok": True, "running": False}
            elif action == "crawler_status":
                proposals = crawler.pending_proposals()
                return {"ok": True, "running": crawler.is_running(),
                        "pending_proposals": len(proposals), "proposals_pending": len(proposals),
                        "addresses_visited": crawler.visited_count(), "proposals": proposals[:10],
                        "summary": _proposal_collection_summary(proposals)}
            elif action == "accept":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                eid = crawler.accept(pid)
                return {"ok": bool(eid), "entry_id": eid} if eid else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
            elif action == "reject":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                ok = crawler.reject(pid)
                return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
        if action == "attention_status":
            return {"ok": True, "note": "attention_kernel replaced by intelligence.py"}
        if action == "attention_policy_upsert":
            return {"ok": True, "action": "attention_policy_upsert",
                    "note": "attention_kernel replaced by intelligence.py"}
        if action in ("accept_proposal", "reject_proposal"):
            sid = self.current_session.session_id if self.current_session else ""
            engine = self._analysis_engines.get(sid)
            if not engine:
                return make_error(MCPError.NOT_FOUND, "No analysis engine running for current session")
            pid = str(args.get("proposal_id") or "").strip()
            if not pid:
                return make_error(MCPError.INVALID_PARAMS, "proposal_id required")
            if action == "accept_proposal":
                scope = str(args.get("scope") or "all").strip()
                selected_ids = args.get("selected_ids") or []
                result = engine.proposals.accept(pid, scope=scope, selected_ids=selected_ids)
                if result is None:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                # Apply accepted items based on proposal type
                applied = self._apply_proposal(result, engine)
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://state"},
                })
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid, "accepted_items": len(result.get("accepted_items", [])), "applied": applied}
            else:
                bb_path = os.path.join(self.cache_dir, f"{sid}.blackboard.db")
                ok = engine.proposals.reject(pid, bb_path=bb_path)
                if not ok:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid}
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported blackboard action: '{action}'",
            hint="Valid actions: policy_set, policy_status, policy_check, phase_status, phase_set, phase_tick, quest_board, quest_complete, memory_compile, phase_finalize, trace_ingest, trace_run, trace_status, proposal_create, proposal_list, proposal_accept, proposal_reject, decision_card, working_set, state_health, notes_export, notes_import, write, read, list, search, update, delete, clear, stats, merge, prune, contradict, resolve, next_target, frontier, propagate_labels, start_crawler, stop_crawler, crawler_status, accept, reject, accept_proposal, reject_proposal, add_evidence, calibrate, campaign_summary, auto_tag_propagate",
        )
