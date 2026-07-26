"""Phase management and policy enforcement for the blackboard mixin.

Extracted from server_blackboard.py to keep the main handler focused.
This mixin provides:
  - Phase lifecycle (scout → prove → commit → finalize)
  - Phase contracts and escape routes
  - Policy enforcement (staleness, working-set gates)
  - Pre-flight and follow-up gates for tool calls
"""
from __future__ import annotations

import json
from typing import Any

from ..errors import MCPError, make_error


class ServerBlackboardPhaseMixin:
    """Phase management and policy enforcement methods."""

    _EVIDENCE_TOOL_HINTS = frozenset({
        "code", "search", "graph", "firmware_view", "types", "data",
        "funcs", "memory", "calc", "blackboard",
    })

    # ── Phase lifecycle ──────────────────────────────────────────────────────

    def _phase_state(self) -> dict[str, Any]:
        state = getattr(self, "_blackboard_phase_state", None)
        if not isinstance(state, dict):
            state = {
                "phase": "scout",
                "auto_transition": True,
                "recent_actions": [],
                "seen_addrs": [],
                "last_transition_reason": "init",
            }
            self._blackboard_phase_state = state
        return state

    def _phase_snapshot(self, state: dict[str, Any], store) -> dict[str, Any]:
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

    def _phase_transition(self, state: dict[str, Any], phase: str, reason: str) -> None:
        phase = str(phase or "").strip().lower()
        if phase not in {"scout", "prove", "commit", "finalize"}:
            return
        state["phase"] = phase
        state["last_transition_reason"] = reason[:160]

    def _phase_log_action(self, state: dict[str, Any], action: str, addr: str = "") -> None:
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

    def _phase_find_loop(self, state: dict[str, Any]) -> bool:
        recent = state.get("recent_actions") or []
        if len(recent) < 6:
            return False
        tail = recent[-6:]
        uniq = set(tail)
        return len(uniq) <= 2 and tail.count(tail[-1]) >= 3

    def _phase_contracts(self, phase: str) -> dict[str, Any]:
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

    def _phase_escape_route(self, store, limit: int = 3) -> list[dict[str, Any]]:
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

    def _phase_tick(self, state: dict[str, Any], store, limit: int = 3) -> dict[str, Any]:
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

    def _evidence_has_tool_citation(self, evidence_for: list[Any]) -> bool:
        for item in evidence_for or []:
            txt = str(item or "").strip().lower()
            if not txt:
                continue
            if ":" in txt:
                head = txt.split(":", 1)[0].strip()
                if head in self._EVIDENCE_TOOL_HINTS:
                    return True
            for tool_name in self._EVIDENCE_TOOL_HINTS:
                if f"{tool_name}(" in txt or f"{tool_name} " in txt:
                    return True
        return False

    def _phase_auto_transition(self, state: dict[str, Any], action: str, args: dict[str, Any], store) -> None:
        if not bool(state.get("auto_transition", True)):
            return
        phase = str(state.get("phase") or "scout")
        if phase == "scout":
            seen_count = len(state.get("seen_addrs") or [])
            if seen_count >= 3:
                self._phase_transition(state, "prove", "auto: >=3 unique addresses discovered")
        proposal_type = str(args.get("proposal_type") or args.get("type") or "").strip().lower()
        if action in {"proposal_create", "proposal_accept"} and phase in {"scout", "commit"}:
            if proposal_type in {"rename", "patch"} or action in {"proposal_accept"}:
                self._phase_transition(state, "commit", f"auto: {action} requested")
        if action in {"memory_compile", "phase_finalize"}:
            self._phase_transition(state, "finalize", f"auto: {action} requested")

    def _phase_contract_check(self, state: dict[str, Any], action: str, args: dict[str, Any], store) -> dict[str, Any] | None:
        phase = str(state.get("phase") or "scout")
        if phase == "scout":
            return None
        if phase == "prove":
            if action in {"proposal_create", "proposal_accept"} and not self._phase_has_prove_receipts(store):
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
            if action in {"proposal_create", "proposal_accept"}:
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

    # ── Pre-flight / follow-up gates ─────────────────────────────────────────

    def _phase_preflight_for_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any] | None:
        try:
            if str(tool_name or "").strip().lower() == "blackboard":
                return None
            if not getattr(self, "_phase_gates_enabled", False):
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

    def _phase_followup_for_response(self, tool_name: str) -> dict[str, Any] | None:
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

    # ── Policy ───────────────────────────────────────────────────────────────

    def _bb_policy_state(self) -> dict[str, Any]:
        state = getattr(self, "_blackboard_policy_state", None)
        if not isinstance(state, dict):
            state = {
                "strict_mode": False,
                "max_staleness_calls": 6,
                "require_working_set": True,
                "require_decision_or_write": True,
                "enforce_phases": ["commit", "finalize"],
                "last_call_count_at_update": 0,
                "policy_markers": [],
            }
            self._blackboard_policy_state = state
        return state

    def _bb_policy_bump(self) -> dict[str, Any]:
        state = self._bb_policy_state()
        state["last_call_count_at_update"] = int(state.get("last_call_count_at_update", 0)) + 1
        return state

    def _bb_policy_mark(self, state: dict[str, Any], marker: str) -> None:
        markers = state.get("policy_markers")
        if not isinstance(markers, list):
            markers = []
        markers.append(str(marker or ""))
        state["policy_markers"] = markers[-50:]

    def _bb_policy_snapshot(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "strict_mode": bool(state.get("strict_mode", False)),
            "max_staleness_calls": int(state.get("max_staleness_calls", 6)),
            "require_working_set": bool(state.get("require_working_set", True)),
            "require_decision_or_write": bool(state.get("require_decision_or_write", True)),
            "enforce_phases": list(state.get("enforce_phases") or []),
            "last_call_count_at_update": int(state.get("last_call_count_at_update", 0)),
            "markers": list(state.get("policy_markers") or [])[-10:],
        }

    def _bb_policy_enforced_for_phase(self, state: dict[str, Any], phase: str) -> bool:
        if not bool(state.get("strict_mode", False)):
            return False
        return str(phase or "").strip().lower() in set(state.get("enforce_phases") or [])

    def _bb_policy_check(self, state: dict[str, Any]) -> dict[str, Any]:
        reasons = []
        if bool(state.get("require_working_set", True)):
            reasons.append("require_working_set=True")
        if bool(state.get("require_decision_or_write", True)):
            reasons.append("require_decision_or_write=True")
        staleness = int(state.get("max_staleness_calls", 6))
        if staleness < 3:
            reasons.append(f"max_staleness_calls={staleness} (minimum 3 recommended)")
        strict = bool(state.get("strict_mode", False))
        if strict:
            reasons.append("strict_mode enabled — phase gates are enforced")
        return {
            "ok": True,
            "strict_mode": strict,
            "enforce_phases": list(state.get("enforce_phases") or []),
            "reasons": reasons[:10],
            "recommendation": "Set strict_mode=false or expand enforce_phases if gates are too aggressive.",
        }
