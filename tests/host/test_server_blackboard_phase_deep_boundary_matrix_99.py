"""Deep offline coverage for blackboard phase and policy governance modes."""

from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.server.server_blackboard_phase import ServerBlackboardPhaseMixin


class _Store:
    def __init__(self, *, stats=None, cards=(), tasks=(), targets=()):
        self._stats = stats or {}
        self.cards = list(cards)
        self.tasks = list(tasks)
        self.targets = list(targets)
        self.persisted = []
        self.raise_stats = False

    def stats(self):
        if self.raise_stats:
            raise RuntimeError("stats unavailable")
        return dict(self._stats)

    def list(self, **kwargs):
        if kwargs.get("category") == "trace_task":
            return list(self.tasks)
        if kwargs.get("tag") == "decision_card":
            return list(self.cards)
        return []

    def next_target(self, limit=3):
        return self.targets[:limit]


class _Orchestration:
    def __init__(self, durable=None, *, fail_get=False, fail_set=False):
        self.durable = durable
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.writes = []

    def machinery_get(self, _store, _namespace, _key, default=None):
        if self.fail_get:
            raise RuntimeError("durable read failed")
        return self.durable if self.durable is not None else default

    def machinery_set(self, _store, namespace, key, value):
        if self.fail_set:
            raise RuntimeError("durable write failed")
        self.writes.append((namespace, key, value))


class _Host(ServerBlackboardPhaseMixin):
    def __init__(self, store=None, orchestration=None):
        self.store = store or _Store()
        self.orchestration = orchestration or _Orchestration()
        self.current_session = SimpleNamespace(session_id="session-a")

    def _get_blackboard_store(self):
        return self.store

    def _orchestration(self):
        return self.orchestration

    @staticmethod
    def _validate_proposal_spec(_proposal_type, spec):
        return None if isinstance(spec, dict) and spec else "proposal spec missing"


def test_phase_state_persistence_cache_legacy_and_snapshot_modes():
    host = _Host()
    assert host._bb_state_key() == "SESSION-A"
    assert host._bb_state_key(" explicit ") == "EXPLICIT"
    host.current_session = None
    assert host._bb_state_key() == ""
    host.current_session = SimpleNamespace(session_id="session-a")

    fresh = host._phase_state()
    assert fresh["phase"] == "scout"
    assert host._phase_state() is fresh
    host._blackboard_phase_state = {"phase": "legacy"}
    assert host._phase_state() == {"phase": "legacy"}
    del host._blackboard_phase_state

    durable_host = _Host(orchestration=_Orchestration({"phase": "prove", "seen_addrs": ["1"]}))
    durable = durable_host._phase_state()
    assert durable["phase"] == "prove"
    assert durable["_durable_ns"] == "phase"
    failing = _Host(orchestration=_Orchestration(fail_get=True))
    assert failing._phase_state()["phase"] == "scout"

    state = {"phase": "scout", "_durable_ns": "phase", "_durable_key": "S"}
    host._phase_persist(state)
    assert host.orchestration.writes[0][2].get("_durable_ns") is None
    host._policy_persist({"strict_mode": True, "_durable_ns": "policy", "_durable_key": "S"})
    assert host.orchestration.writes[-1][0] == "policy"
    host._phase_persist({"phase": "scout"})
    host._policy_persist({"strict_mode": True})
    no_store = _Host(store=None)
    no_store._get_blackboard_store = lambda: None
    no_store._phase_persist({"_durable_ns": "phase", "_durable_key": "S"})
    no_store._policy_persist({"_durable_ns": "policy", "_durable_key": "S"})
    bad_store = _Host(orchestration=_Orchestration(fail_set=True))
    bad_store._phase_persist({"_durable_ns": "phase", "_durable_key": "S"})
    bad_store._policy_persist({"_durable_ns": "policy", "_durable_key": "S"})
    getter_failure = _Host()
    getter_failure._get_blackboard_store = lambda: (_ for _ in ()).throw(RuntimeError("store read failed"))
    getter_failure._phase_persist({"_durable_ns": "phase", "_durable_key": "S"})
    getter_failure._policy_persist({"_durable_ns": "policy", "_durable_key": "S"})

    host._phase_transition(fresh, "invalid", "ignored")
    host._phase_transition(fresh, "prove", "reason" * 100)
    assert fresh["phase"] == "prove" and len(fresh["last_transition_reason"]) == 160
    host._phase_log_action(fresh, "a", addr="0x1")
    host._phase_log_action(fresh, "a", addr="0x1")
    fresh["recent_actions"] = "bad"
    fresh["seen_addrs"] = "bad"
    host._phase_log_action(fresh, "b", addr="0x2")
    assert fresh["recent_actions"] == ["b"]
    for index in range(30):
        host._phase_log_action(fresh, str(index))
    assert len(fresh["recent_actions"]) == 24


def test_phase_loop_contract_escape_and_tick_recommendations():
    host = _Host(_Store(stats={"contradicted": 2}, targets=[{}, {"addr": " 0x10 "}, {"addr": "0x20"}]))
    assert host._phase_find_loop({"recent_actions": ["a"] * 5}) is False
    assert host._phase_find_loop({"recent_actions": ["a", "b", "c", "d", "e", "f"]}) is False
    assert host._phase_find_loop({"recent_actions": ["a", "b", "a", "b", "a", "a"]}) is True
    assert len(host._phase_escape_route(host.store, limit=3)) == 2
    assert host._phase_contracts("unknown")["write_policy"] == "optional"
    assert host._phase_contracts("prove")["must_have"] == ["evidence_for", "trace_done"]
    assert host._phase_contracts("commit")["must_have"] == ["proposal_spec_valid"]
    assert host._phase_contracts("finalize")["must_have"] == ["contradictions_reconciled"]

    state = {"phase": "prove", "recent_actions": [], "seen_addrs": []}
    tick = host._phase_tick(state, host.store)
    assert tick["loop_detected"] is False
    assert "evidence" in tick["recommendations"][0]
    state["phase"] = "commit"
    assert "proposal" in host._phase_tick(state, host.store)["recommendations"][0]
    state["phase"] = "finalize"
    assert "contradictions" in host._phase_tick(state, host.store)["recommendations"][0]

    loop_state = {"phase": "scout", "recent_actions": ["same"] * 6, "seen_addrs": []}
    loop_tick = host._phase_tick(loop_state, host.store, limit=2)
    assert loop_tick["phase"]["phase"] == "prove"
    assert loop_tick["escape_route_targets"]
    host.store.raise_stats = True
    snapshot = host._phase_snapshot({"phase": "scout", "seen_addrs": [], "recent_actions": []}, host.store)
    assert snapshot["contradicted_entries"] == 0


def test_prove_receipts_and_evidence_citation_variants():
    cards = [
        {"tags": ["other"], "content": "{}"},
        {"tags": ["decision_card"], "content": "not json"},
        {"tags": ["decision_card"], "content": json.dumps({"evidence_for": ["plain note"]})},
    ]
    host = _Host(_Store(cards=cards, tasks=[{"content": "not json"}]))
    assert host._phase_has_prove_receipts(host.store) is False
    assert host._evidence_has_tool_citation(["", "plain", "code: decompile"]) is True
    assert host._evidence_has_tool_citation(["other: search(needle)"]) is True
    assert host._evidence_has_tool_citation(["search(needle)"]) is True
    assert host._evidence_has_tool_citation(["unknown"] * 2) is False
    host.store.cards.append(
        {"tags": ["decision_card"], "content": json.dumps({"evidence_for": ["code: decompile"]})}
    )
    assert host._phase_has_prove_receipts(host.store) is False
    host.store.tasks.append({"content": json.dumps({"status": "done"})})
    assert host._phase_has_prove_receipts(host.store) is True


def test_phase_auto_transition_and_contract_checks():
    host = _Host()
    state = {"phase": "scout", "auto_transition": False, "seen_addrs": ["1", "2", "3"]}
    host._phase_auto_transition(state, "modify:rename", {}, host.store)
    assert state["phase"] == "scout"
    state["auto_transition"] = True
    host._phase_auto_transition(state, "search:call", {}, host.store)
    assert state["phase"] == "prove"
    proposal = {"phase": "scout", "auto_transition": True, "seen_addrs": []}
    host._phase_auto_transition(proposal, "proposal_create", {"proposal_type": "rename"}, host.store)
    assert proposal["phase"] == "prove"

    state["phase"] = "commit"
    host._phase_auto_transition(state, "proposal_create", {"type": "patch"}, host.store)
    assert state["phase"] == "commit"
    host._phase_auto_transition(state, "proposal_create", {"type": "other"}, host.store)
    host._phase_auto_transition(state, "memory_compile", {}, host.store)
    assert state["phase"] == "finalize"

    prove = {"phase": "prove"}
    blocked = host._phase_contract_check(prove, "proposal_create", {}, host.store)
    assert blocked and blocked["code"] == "POLICY_DENIED"
    assert host._phase_contract_check(prove, "search", {}, host.store) is None
    commit = {"phase": "commit"}
    assert host._phase_contract_check(commit, "proposal_create", {"type": "rename", "spec": "bad"}, host.store)
    assert host._phase_contract_check(commit, "proposal_create", {"type": "other"}, host.store) is None
    assert host._phase_contract_check(commit, "search", {}, host.store) is None
    finalize = {"phase": "finalize"}
    host.store._stats = {"contradicted": 1}
    assert host._phase_contract_check(finalize, "proposal_accept", {}, host.store)
    host.store._stats = {"contradicted": 0}
    assert host._phase_contract_check(finalize, "proposal_accept", {}, host.store) is None
    assert host._phase_contract_check(finalize, "search", {}, host.store) is None
    assert host._phase_contract_check({"phase": "other"}, "search", {}, host.store) is None


def test_governance_envelopes_preflight_and_followup_modes():
    host = _Host(_Store(stats={"contradicted": 1}))
    policy = {"strict_mode": True, "policy_markers": []}
    denied = host._governance_denied({"phase": "prove"}, policy, "blocked")
    assert denied["gate"] == "phase" and denied["policy"]["strict_mode"] is True
    assert host._policy_denied({"phase": "prove"}, policy, "blocked")["gate"] == "policy"

    host._phase_gates_enabled = False
    assert host._phase_preflight_for_tool("modify", {}) is None
    host._phase_gates_enabled = True
    host._get_blackboard_store = lambda: None
    assert host._phase_preflight_for_tool("modify", {}) is None
    host._get_blackboard_store = lambda: host.store
    host._blackboard_phase_state = {"phase": "scout", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("blackboard", {}) is None
    assert host._phase_preflight_for_tool("code", {"action": "decompile", "addr": "0x1"}) is None
    host._blackboard_phase_state = {"phase": "prove", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("modify", {"action": "rename"})
    host._blackboard_phase_state = {"phase": "commit", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("modify", {"action": "rename"})
    assert host._phase_preflight_for_tool("modify", {"action": "rename", "_phase_commit_ack": True}) is None
    host._blackboard_phase_state = {"phase": "finalize", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("modify", {"action": "rename"})
    assert host._phase_preflight_for_tool("search", {}) is None
    host._blackboard_phase_state = {"phase": "prove", "recent_actions": [], "seen_addrs": []}
    host.store.cards = [{"tags": ["decision_card"], "content": json.dumps({"evidence_for": ["code: info"]})}]
    host.store.tasks = [{"content": json.dumps({"status": "done"})}]
    assert host._phase_preflight_for_tool("modify", {"action": "rename"}) is None
    host._blackboard_phase_state = {"phase": "commit", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("search", {}) is None
    host._get_blackboard_store = lambda: (_ for _ in ()).throw(RuntimeError("store gone"))
    assert host._phase_preflight_for_tool("code", {}) is None

    host = _Host(_Store(stats={"contradicted": 0}))
    host._phase_gates_enabled = True
    host._blackboard_phase_state = {"phase": "finalize", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("modify", {"action": "rename"}) is None
    host._blackboard_phase_state = {"phase": "unknown", "recent_actions": [], "seen_addrs": []}
    assert host._phase_preflight_for_tool("search", {}) is None

    host = _Host(_Store(stats={"contradicted": 2}))
    host._blackboard_phase_state = {"phase": "prove"}
    assert host._phase_followup_for_response("code")["phase_gate"]["phase"] == "prove"
    host._blackboard_phase_state = {"phase": "commit"}
    assert host._phase_followup_for_response("code")["phase_gate"]["phase"] == "commit"
    host._blackboard_phase_state = {"phase": "finalize"}
    assert host._phase_followup_for_response("code")["phase_gate"]["phase"] == "finalize"
    host.store._stats = {"contradicted": 0}
    assert host._phase_followup_for_response("code") is None
    host._blackboard_phase_state = {"phase": "unknown"}
    assert host._phase_followup_for_response("code") is None
    assert host._phase_followup_for_response("blackboard") is None
    host._get_blackboard_store = lambda: (_ for _ in ()).throw(RuntimeError("gone"))
    assert host._phase_followup_for_response("code") is None


def test_policy_state_markers_check_and_phase_write_classification():
    host = _Host()
    state = host._bb_policy_state()
    assert state["strict_mode"] is False
    assert host._bb_policy_state() is state
    host._blackboard_policy_state = {"strict_mode": True}
    assert host._bb_policy_state()["strict_mode"] is True
    del host._blackboard_policy_state
    durable = _Host(orchestration=_Orchestration({"strict_mode": True, "policy_markers": ["write@2"]}))
    assert durable._bb_policy_state()["strict_mode"] is True
    failing = _Host(orchestration=_Orchestration(fail_get=True))
    assert failing._bb_policy_state()["strict_mode"] is False

    bumped = host._bb_policy_bump()
    host._bb_policy_mark(bumped, "working_set")
    host._bb_policy_mark(bumped, "decision")
    assert host._marker_call(["working_set@bad", "working_set@4"], "working_set") == 4
    assert host._marker_call([], "none") == 0
    snap = host._bb_policy_snapshot(bumped)
    assert snap["markers"]
    malformed_markers = dict(bumped, policy_markers="bad")
    host._bb_policy_mark(malformed_markers, "write")
    assert host._bb_policy_enforced_for_phase({"strict_mode": True, "enforce_phases": ["commit"]}, "commit")
    assert not host._bb_policy_enforced_for_phase({"strict_mode": False, "enforce_phases": ["commit"]}, "commit")

    stale = {
        "strict_mode": False,
        "max_staleness_calls": 2,
        "require_working_set": True,
        "require_decision_or_write": True,
        "last_call_count_at_update": 6,
        "policy_markers": [],
    }
    checked = host._bb_policy_check(stale)
    assert checked["ok"] is False and checked["reasons"]
    fresh = dict(stale, policy_markers=["working_set@6", "decision@6"], max_staleness_calls=2)
    assert host._bb_policy_check(fresh)["ok"] is True
    fresh["max_staleness_calls"] = 1
    fresh["strict_mode"] = True
    fresh["require_working_set"] = False
    fresh["require_decision_or_write"] = False
    assert host._bb_policy_check(fresh)["ok"] is True

    assert ServerBlackboardPhaseMixin._phase_write_call("modify", "anything")
    assert ServerBlackboardPhaseMixin._phase_write_call("segments", "read")
    assert ServerBlackboardPhaseMixin._phase_write_call("funcs", "set_flags")
    assert not ServerBlackboardPhaseMixin._phase_write_call("funcs", "info")
    assert not ServerBlackboardPhaseMixin._phase_write_call("code", "decompile")
