"""Phase management and policy enforcement for the blackboard mixin.

Extracted from server_blackboard.py to keep the main handler focused.
This mixin provides:
  - Phase lifecycle (scout → prove → commit → finalize)
  - Phase contracts and escape routes
  - Policy enforcement (staleness, working-set gates)
  - Pre-flight and follow-up gates for tool calls
  - A durable per-session phase/policy core persisted in ``bb_machinery``

The per-session phase and policy state live in the workspace's
``bb_machinery`` table (written through the orchestration layer) so they
survive a host restart, while still being strictly scoped per session: one
session's machine never leaks into another sharing the same host. A legacy
directly-assigned singleton (``_blackboard_phase_state`` /
``_blackboard_policy_state``) is honored verbatim for back-compatibility and
for tests that seed state by hand.
"""
from __future__ import annotations

import contextlib
import json
from typing import Any

from ..errors import MCPError, make_error

#: funcs tool actions that mutate the IDB; the tool exposes read-only actions
#: (info/metrics/find_similar) alongside these, so phase gates must not treat
#: every funcs call as a write. Kept local because funcs.py imports the IDA
#: SDK and cannot be imported here.
_FUNCS_WRITE_ACTIONS = frozenset({"create", "change", "delete", "set_flags"})

#: Namespace under which the per-session phase core is persisted.
_PHASE_NS = "phase"
#: Namespace under which the per-session policy core is persisted.
_POLICY_NS = "policy"

#: Internal keys attached to a durable-backed state dict so mutation helpers
#: know where to persist. Filtered out of every snapshot.
_DURABLE_KEY = "_durable_key"
_DURABLE_NS = "_durable_ns"


def _strip_durable(state: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in state.items() if not k.startswith("_durable")}


class ServerBlackboardPhaseMixin:
    """Phase management and policy enforcement methods."""

    _EVIDENCE_TOOL_HINTS = frozenset({
        "code", "search", "graph", "types", "data",
        "funcs", "memory", "calc", "blackboard",
    })

    # ── Phase lifecycle ──────────────────────────────────────────────────────

    def _bb_state_key(self, sid: str | None = None) -> str:
        """Session key used to scope phase/policy state.

        State is per-session so one session's phase machine or policy markers
        never leak into another session sharing the same host (and the same
        binary-scoped workspace DB). An empty key is used when no session is
        active (defensive; callers that require a session fail earlier).
        """
        if sid:
            return str(sid).strip().upper()
        session = getattr(self, "current_session", None)
        if session is None:
            return ""
        return str(getattr(session, "session_id", "") or "").strip().upper()

    def _phase_persist(self, state: dict[str, Any]) -> None:
        """Persist a durable-backed phase state back to ``bb_machinery``."""
        ns = state.get(_DURABLE_NS)
        key = state.get(_DURABLE_KEY)
        if not ns or not key:
            return
        try:
            store = self._get_blackboard_store()
        except Exception:
            store = None
        if store is None:
            return
        with contextlib.suppress(Exception):
            self._orchestration().machinery_set(
                store, ns, key, _strip_durable(state)
            )

    def _policy_persist(self, state: dict[str, Any]) -> None:
        ns = state.get(_DURABLE_NS)
        key = state.get(_DURABLE_KEY)
        if not ns or not key:
            return
        try:
            store = self._get_blackboard_store()
        except Exception:
            store = None
        if store is None:
            return
        with contextlib.suppress(Exception):
            self._orchestration().machinery_set(
                store, ns, key, _strip_durable(state)
            )

    def _phase_state(self, sid: str | None = None) -> dict[str, Any]:
        # Back-compat: a directly-assigned legacy singleton (some callers and
        # tests set ``_blackboard_phase_state``) is honored verbatim. Production
        # code no longer writes it; state lives in per-session durable state.
        legacy = getattr(self, "_blackboard_phase_state", None)
        if isinstance(legacy, dict):
            return legacy
        key = self._bb_state_key(sid)
        states = getattr(self, "_blackboard_phase_states", None)
        if not isinstance(states, dict):
            states = {}
            self._blackboard_phase_states = states
        cached = states.get(key)
        if isinstance(cached, dict):
            return cached
        # Durable load: a prior host session persisted this session's machine.
        durable = None
        try:
            store = self._get_blackboard_store()
            if store is not None:
                durable = self._orchestration().machinery_get(
                    store, _PHASE_NS, key, default=None
                )
        except Exception:
            durable = None
        if isinstance(durable, dict):
            state = dict(durable)
        else:
            state = {
                "phase": "scout",
                "auto_transition": True,
                "recent_actions": [],
                "seen_addrs": [],
                "last_transition_reason": "init",
            }
        state[_DURABLE_NS] = _PHASE_NS
        state[_DURABLE_KEY] = key
        states[key] = state
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
        self._phase_persist(state)

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
        self._phase_persist(state)

    def _phase_find_loop(self, state: dict[str, Any]) -> bool:
        recent = state.get("recent_actions") or []
        if len(recent) < 6:
            return False
        tail = recent[-6:]
        uniq = set(tail)
        if len(uniq) == 1:
            return True
        if len(uniq) > 2:
            return False
        # Two distinct actions: a genuine loop repeats the latest action in
        # immediate succession; a clean A/B alternation is a scan, not a loop.
        return tail.count(tail[-1]) >= 3 and tail[-1] == tail[-2]

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
        # Scan every decision card regardless of lane: the working_set hint
        # recommends `lane_now`, which stores cards under category wm_now, not
        # hypothesis. Filtering on the decision_card tag catches all lanes.
        cards = store.list(tag="decision_card", include_resolved=True, include_contradicted=False, limit=80)
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
            try:
                payload = json.loads(str(t.get("content") or "{}"))
            except Exception:
                payload = {}
            if str(payload.get("status") or "").strip().lower() == "done":
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
                if phase == "scout" and not self._phase_has_prove_receipts(store):
                    # Route through the prove gate instead of jumping straight
                    # to commit: proposal ops need evidence receipts first.
                    self._phase_transition(state, "prove", f"auto: {action} requested without evidence")
                else:
                    self._phase_transition(state, "commit", f"auto: {action} requested")
        if action in {"memory_compile", "phase_finalize"}:
            self._phase_transition(state, "finalize", f"auto: {action} requested")

    def _phase_contract_check(self, state: dict[str, Any], action: str, args: dict[str, Any], store) -> dict[str, Any] | None:
        phase = str(state.get("phase") or "scout")
        if phase == "scout":
            return None
        if phase == "prove":
            if action in {"proposal_create", "proposal_accept"} and not self._phase_has_prove_receipts(store):
                return self._governance_denied(
                    state,
                    None,
                    "prove phase requires evidence cards and completed trace tasks before proposal operations",
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
                        return self._governance_denied(
                            state,
                            None,
                            f"commit phase requires strict spec: {err}",
                        )
            return None
        if phase == "finalize":
            if action in {"proposal_create", "proposal_accept"}:
                stats = store.stats() or {}
                contradicted = int(stats.get("contradicted") or 0)
                if contradicted > 0:
                    return self._governance_denied(
                        state,
                        None,
                        f"finalize phase blocked: unresolved contradictions remain (contradicted={contradicted})",
                    )
            return None
        return None

    # ── Governance error envelope ───────────────────────────────────────────

    def _governance_denied(
        self, phase_state: dict[str, Any], policy_state: dict[str, Any] | None, message: str
    ) -> dict[str, Any]:
        """Build the POLICY_DENIED governance envelope.

        Body is ``{ok:false, gate, phase, policy, message}`` on top of the
        standard error fields, so a caller can branch on ``error``/``code``
        while the model sees the structured governance reason.
        """
        env = make_error(MCPError.POLICY_DENIED, message)
        env["ok"] = False
        env["gate"] = "phase"
        env["phase"] = str((phase_state or {}).get("phase") or "scout")
        env["policy"] = (
            self._bb_policy_snapshot(policy_state) if policy_state else {}
        )
        env["message"] = message
        return env

    def _policy_denied(
        self, phase_state: dict[str, Any], policy_state: dict[str, Any], message: str
    ) -> dict[str, Any]:
        env = self._governance_denied(phase_state, policy_state, message)
        env["gate"] = "policy"
        return env

    # ── Pre-flight / follow-up gates ─────────────────────────────────────────

    @staticmethod
    def _phase_write_call(tool_name: str, action: str) -> bool:
        """True when a tool call mutates the IDB (a write-surface call).

        funcs exposes read-only actions (info/metrics/find_similar) next to
        its writes, so only the write actions are gated; ``modify``,
        ``segments``, and ``annotation`` are treated as write tools. This one
        classification is shared by the prove and commit branches so both
        gate the same calls.
        """
        tool = str(tool_name or "").strip().lower()
        if tool in {"modify", "segments", "annotation"}:
            return True
        if tool == "funcs":
            return str(action or "").strip().lower() in _FUNCS_WRITE_ACTIONS
        return False

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
            policy_state = self._bb_policy_state()
            action = str((args or {}).get("action") or "").strip().lower()
            addr = str((args or {}).get("addr") or (args or {}).get("address") or "").strip()
            logical = f"{tool_name}:{action or 'call'}"
            self._phase_log_action(phase_state, logical, addr=addr)
            self._phase_auto_transition(phase_state, logical, args or {}, store)
            phase = str(phase_state.get("phase") or "scout")
            if phase == "scout":
                return None
            if phase == "prove":
                if self._phase_write_call(tool_name, action) and not self._phase_has_prove_receipts(store):
                    return self._governance_denied(
                        phase_state,
                        policy_state,
                        "prove phase requires evidence cards and completed trace tasks before write-surface tools",
                    )
                return None
            if phase == "commit":
                if self._phase_write_call(tool_name, action):
                    ack = bool((args or {}).get("_phase_commit_ack", False))
                    if not ack:
                        return self._governance_denied(
                            phase_state,
                            policy_state,
                            "commit phase requires explicit acknowledgement for write-surface tools",
                        )
                return None
            if phase == "finalize":
                if str(tool_name or "") in {"modify", "segments", "funcs", "annotation"}:
                    stats = store.stats() or {}
                    contradicted = int(stats.get("contradicted") or 0)
                    if contradicted > 0:
                        return self._governance_denied(
                            phase_state,
                            policy_state,
                            f"finalize phase blocked: unresolved contradictions remain (contradicted={contradicted})",
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

    def _bb_policy_state(self, sid: str | None = None) -> dict[str, Any]:
        # Back-compat: honor a directly-assigned legacy singleton, mirroring
        # ``_phase_state``. Per-session durable state is the default thereafter.
        legacy = getattr(self, "_blackboard_policy_state", None)
        if isinstance(legacy, dict):
            return legacy
        key = self._bb_state_key(sid)
        states = getattr(self, "_blackboard_policy_states", None)
        if not isinstance(states, dict):
            states = {}
            self._blackboard_policy_states = states
        cached = states.get(key)
        if isinstance(cached, dict):
            return cached
        durable = None
        try:
            store = self._get_blackboard_store()
            if store is not None:
                durable = self._orchestration().machinery_get(
                    store, _POLICY_NS, key, default=None
                )
        except Exception:
            durable = None
        if isinstance(durable, dict):
            state = dict(durable)
        else:
            state = {
                "strict_mode": False,
                "max_staleness_calls": 6,
                "require_working_set": True,
                "require_decision_or_write": True,
                "enforce_phases": ["commit", "finalize"],
                "last_call_count_at_update": 0,
                "policy_markers": [],
            }
        state[_DURABLE_NS] = _POLICY_NS
        state[_DURABLE_KEY] = key
        states[key] = state
        return state

    def _bb_policy_bump(self) -> dict[str, Any]:
        state = self._bb_policy_state()
        state["last_call_count_at_update"] = int(state.get("last_call_count_at_update", 0)) + 1
        self._policy_persist(state)
        return state

    def _bb_policy_mark(self, state: dict[str, Any], marker: str) -> None:
        markers = state.get("policy_markers")
        if not isinstance(markers, list):
            markers = []
        call_count = int(state.get("last_call_count_at_update", 0))
        markers.append(f"{marker}@{call_count}")
        state["policy_markers"] = markers[-50:]
        self._policy_persist(state)

    @staticmethod
    def _marker_call(markers: list[Any], name: str) -> int:
        """Latest call count at which a named marker was recorded (0 if never)."""
        best = 0
        prefix = f"{name}@"
        for m in markers or []:
            s = str(m)
            if s.startswith(prefix) and len(s) > len(prefix):
                with contextlib.suppress(ValueError):
                    best = max(best, int(s.split("@", 1)[1]))
        return best

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
        markers = state.get("policy_markers") or []
        current_call = int(state.get("last_call_count_at_update", 0))
        max_stale = max(1, int(state.get("max_staleness_calls", 6)))
        ok = True
        if bool(state.get("require_working_set", True)):
            last_ws = self._marker_call(markers, "working_set")
            if current_call - last_ws > max_stale:
                ok = False
                reasons.append("require_working_set: no working_set call within max_staleness_calls")
        if bool(state.get("require_decision_or_write", True)):
            last_dw = max(self._marker_call(markers, "decision"), self._marker_call(markers, "write"))
            if current_call - last_dw > max_stale:
                ok = False
                reasons.append("require_decision_or_write: no decision/write within max_staleness_calls")
        staleness = max_stale
        if staleness < 3:
            reasons.append(f"max_staleness_calls={staleness} (minimum 3 recommended)")
        strict = bool(state.get("strict_mode", False))
        if strict:
            reasons.append("strict_mode enabled — phase gates are enforced")
        if not ok:
            reasons.append("Call working_set, then write a decision card or finding, before retrying the gated action.")
        return {
            "ok": ok,
            "strict_mode": strict,
            "enforce_phases": list(state.get("enforce_phases") or []),
            "reasons": reasons[:10],
            "recommendation": (
                "Set strict_mode=false or expand enforce_phases if gates are too aggressive."
                if ok
                else "Call working_set and write a decision card or finding before retrying."
            ),
        }
