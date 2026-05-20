import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ida_pro_mcp.host.server_blackboard import ServerBlackboardMixin


class _FakeStore:
    def __init__(self):
        self.items = []
        self._id = 0

    def write(self, title, content="", category="general", addr="", tags=None, confidence=0.5, source="", source_type="", **kwargs):
        self._id += 1
        eid = f"e{self._id}"
        self.items.append(
            {
                "id": eid,
                "title": title,
                "content": content,
                "category": category,
                "addr": addr,
                "tags": tags or [],
                "confidence": confidence,
                "source_type": source_type or source or "manual",
                "resolved": 0,
                "contradicted": 0,
            }
        )
        return eid

    def list(self, category=None, limit=100, include_resolved=True, include_contradicted=False, **kwargs):
        rows = [r for r in self.items if (not category or r.get("category") == category)]
        if not include_contradicted:
            rows = [r for r in rows if not r.get("contradicted")]
        return rows[:limit]

    def read(self, entry_id):
        for r in self.items:
            if r.get("id") == entry_id:
                return r
        return None

    def semantic_search(self, **kwargs):
        return self.list(limit=kwargs.get("top_k", 20))

    def next_target(self, limit=5):
        return [
            {
                "entry_id": "q1",
                "addr": "0x401000",
                "title": "decrypt_config",
                "confidence": 0.8,
                "priority_score": 0.55,
                "xref_count": 4,
                "entropy": 3.2,
            },
            {
                "entry_id": "q2",
                "addr": "0x402000",
                "title": "packet_handler",
                "confidence": 0.75,
                "priority_score": 0.60,
                "xref_count": 3,
                "entropy": 2.7,
            },
        ][:limit]

    def stats(self):
        by_category = {}
        contradicted = 0
        for row in self.items:
            by_category[row["category"]] = by_category.get(row["category"], 0) + 1
            if row.get("contradicted"):
                contradicted += 1
        avg = 0.0
        if self.items:
            avg = sum(float(r.get("confidence") or 0.0) for r in self.items) / len(self.items)
        return {
            "total_entries": len(self.items),
            "by_category": by_category,
            "avg_confidence": avg,
            "unresolved": len(self.items),
            "contradicted": contradicted,
        }

    def exists_similar(self, addr, category, title):
        return any(r.get("category") == category and r.get("title") == title for r in self.items)

    def update(self, entry_id, **kwargs):
        row = self.read(entry_id)
        if not row:
            return False
        row.update(kwargs)
        return True

    def delete(self, entry_id):
        before = len(self.items)
        self.items = [r for r in self.items if r.get("id") != entry_id]
        return len(self.items) != before

    def clear(self, category=None):
        if not category:
            n = len(self.items)
            self.items = []
            return n
        before = len(self.items)
        self.items = [r for r in self.items if r.get("category") != category]
        return before - len(self.items)

    def contradict(self, entry_id, reason):
        row = self.read(entry_id)
        if not row:
            return False
        row["contradicted"] = 1
        row["contradiction_reason"] = reason
        return True

    def mark_resolved(self, entry_id):
        row = self.read(entry_id)
        if not row:
            return False
        row["resolved"] = 1
        return True


class _DummyServer(ServerBlackboardMixin):
    def __init__(self):
        self.cache_dir = "/tmp"
        self.current_session = None
        self._blackboard_module = None
        self._blackboard_store = None
        self._analysis_engines = {}
        self._send_notification = lambda _msg: None
        self._store = _FakeStore()
        self._tool_calls = []

    def _get_blackboard_store(self):
        return self._store

    def _execute_tool(self, tool_name, args):
        self._tool_calls.append((tool_name, dict(args)))
        if tool_name == "xref_analysis":
            return {"ok": True, "action": "influence", "items": [{"addr": args.get("addr"), "name": "decrypt_config"}]}
        if tool_name == "search":
            return {"ok": True, "matches": [f"{args.get('query')} at 0x401000"]}
        return {"ok": True}


def test_decision_card_and_working_set():
    srv = _DummyServer()
    card = srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_now",
            "claim": "Config decryptor found at 0x401000",
            "evidence_for": ["xrefs from parser", "AES constants"],
            "evidence_against": ["no key schedule confirmed"],
            "next_step": "decompile callers",
            "confidence": 0.81,
            "addr": "0x401000",
        }
    )
    assert card.get("ok") is True
    assert card.get("trace_task_id")
    ws = srv._handle_blackboard({"action": "working_set"})
    assert ws.get("ok") is True
    assert ws["lanes"]["lane_now"]["count"] >= 1
    assert ws["state_health"]["state_health"] >= 0


def test_notes_export_import_roundtrip(tmp_path):
    srv = _DummyServer()
    srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_hypotheses",
            "claim": "Potential watchdog routine",
            "confidence": 0.66,
        }
    )
    out = tmp_path / "re_notes.md"
    ex = srv._handle_blackboard({"action": "notes_export", "notes_path": str(out)})
    assert ex.get("ok") is True
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "lane_hypotheses" in text

    # Append one manual line and import into facts lane
    with out.open("a", encoding="utf-8") as fh:
        fh.write("- confirmed: watchdog reset branch at 0x402100\n")
    imp = srv._handle_blackboard(
        {
            "action": "notes_import",
            "notes_path": str(out),
            "lane": "lane_facts",
            "confidence": 0.9,
            "auto_trace": True,
        }
    )
    assert imp.get("ok") is True
    assert imp.get("trace_tasks_created", 0) >= 1
    facts = srv._handle_blackboard({"action": "list", "category": "fact"})
    assert facts.get("count", 0) >= 1


def test_state_health_shape():
    srv = _DummyServer()
    res = srv._handle_blackboard({"action": "state_health"})
    assert res.get("ok") is True
    assert "state_health" in res
    assert "recommended_action" in res
    assert isinstance(res.get("signals"), dict)


def test_proposal_create_validation_and_list():
    srv = _DummyServer()
    bad = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "bad proposal",
            "spec": {"renames": [{"addr": "0x401000"}]},
        }
    )
    assert bad.get("error") is True

    good = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename funcs",
            "spec": {"renames": [{"addr": "0x401000", "name": "decrypt_config"}]},
            "confidence": 0.88,
        }
    )
    assert good.get("ok") is True
    listing = srv._handle_blackboard({"action": "proposal_list"})
    assert listing.get("ok") is True
    assert listing.get("count", 0) >= 1
    assert listing["proposals"][0]["proposal_type"] == "rename"


def test_proposal_accept_and_reject_lifecycle():
    srv = _DummyServer()
    created = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename one",
            "spec": {"renames": [{"addr": "0x401000", "name": "handler_main"}]},
        }
    )
    pid = created.get("proposal_id")
    accepted = srv._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert accepted.get("ok") is True
    assert accepted.get("status") == "verified"
    assert accepted["verification"]["ok"] is True
    assert accepted["verification"]["passed"] >= 1
    assert any(c[0] == "modify" for c in srv._tool_calls)

    created2 = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "patch",
            "title": "patch branch",
            "spec": {"patches": [{"addr": "0x402000", "asm": "nop"}]},
        }
    )
    pid2 = created2.get("proposal_id")
    rejected = srv._handle_blackboard({"action": "proposal_reject", "proposal_id": pid2, "reason": "unsafe patch"})
    assert rejected.get("ok") is True
    assert rejected.get("status") == "rejected"
    deads = srv._handle_blackboard({"action": "list", "category": "dead_end"})
    assert deads.get("count", 0) >= 1


def test_proposal_accept_fails_if_verification_fails():
    srv = _DummyServer()

    def _bad_execute(tool_name, args):
        srv._tool_calls.append((tool_name, dict(args)))
        if tool_name == "search":
            return {"ok": True, "matches": ["wrong_symbol at 0x999999"]}
        return {"ok": True}

    srv._execute_tool = _bad_execute
    created = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename one",
            "spec": {"renames": [{"addr": "0x401000", "name": "handler_main"}]},
        }
    )
    pid = created.get("proposal_id")
    accepted = srv._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert accepted.get("ok") is False
    assert accepted.get("status") == "failed"
    assert accepted["verification"]["ok"] is False


def test_verified_proposal_boosts_queue_priority():
    srv = _DummyServer()
    created = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename one",
            "spec": {"renames": [{"addr": "0x401000", "name": "handler_main"}]},
        }
    )
    pid = created.get("proposal_id")
    accepted = srv._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert accepted.get("status") == "verified"
    ws = srv._handle_blackboard({"action": "working_set"})
    queue = ws["lanes"]["lane_queue"]["items"]
    assert queue[0]["addr"] == "0x401000"
    assert "proposal_verified_boost" in queue[0]["tags"]


def test_trace_ingest_run_status_and_auto_proposal():
    srv = _DummyServer()
    ingest = srv._handle_blackboard(
        {
            "action": "trace_ingest",
            "text": "Investigate 0x401000 decrypt_config path and callers",
            "depth": 2,
            "limit": 4,
        }
    )
    assert ingest.get("ok") is True
    task_id = ingest.get("trace_task_id")
    assert task_id

    pending = srv._handle_blackboard({"action": "trace_status", "status": "pending"})
    assert pending.get("ok") is True
    assert any(t.get("trace_task_id") == task_id for t in pending.get("tasks", []))

    run = srv._handle_blackboard({"action": "trace_run", "limit": 2})
    assert run.get("ok") is True
    assert run.get("ran", 0) >= 1

    done = srv._handle_blackboard({"action": "trace_status", "status": "done"})
    assert done.get("ok") is True
    assert any(t.get("trace_task_id") == task_id for t in done.get("tasks", []))

    proposals = srv._handle_blackboard({"action": "proposal_list"})
    assert proposals.get("ok") is True
    assert proposals.get("count", 0) >= 1


def test_decision_card_can_disable_auto_trace():
    srv = _DummyServer()
    card = srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_now",
            "claim": "Analyze 0x401111 now",
            "auto_trace": False,
        }
    )
    assert card.get("ok") is True
    assert card.get("trace_task_id") is None


def test_policy_strict_gate_blocks_trace_run_until_fresh_context():
    srv = _DummyServer()
    set_policy = srv._handle_blackboard(
        {
            "action": "policy_set",
            "strict_mode": True,
            "max_staleness_calls": 2,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["scout", "prove", "commit", "finalize"],
        }
    )
    assert set_policy.get("ok") is True

    blocked = srv._handle_blackboard({"action": "trace_run", "limit": 1})
    assert blocked.get("error") is True
    assert "Strict policy gate failed" in str(blocked.get("message") or "")

    srv._handle_blackboard({"action": "working_set"})
    srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_now",
            "claim": "follow 0x401000",
            "addr": "0x401000",
        }
    )
    # Add one trace task so trace_run has work when gate is satisfied.
    srv._handle_blackboard({"action": "trace_ingest", "text": "inspect 0x401000 decrypt_config"})
    srv._handle_blackboard({"action": "working_set"})
    srv._handle_blackboard({"action": "write", "title": "fresh execution intent", "category": "wm_now"})
    allowed = srv._handle_blackboard({"action": "trace_run", "limit": 1})
    assert allowed.get("ok") is True
    assert allowed.get("ran", 0) >= 1


def test_policy_check_reports_staleness_reasons():
    srv = _DummyServer()
    srv._handle_blackboard(
        {
            "action": "policy_set",
            "strict_mode": True,
            "max_staleness_calls": 1,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["scout", "prove", "commit", "finalize"],
        }
    )
    srv._handle_blackboard({"action": "working_set"})
    srv._handle_blackboard({"action": "decision_card", "claim": "A at 0x401000", "addr": "0x401000"})
    # Advance call sequence without refreshing working_set / decision-write.
    srv._handle_blackboard({"action": "state_health"})
    status = srv._handle_blackboard({"action": "policy_check"})
    assert status.get("ok") is False
    reasons = status.get("reasons", [])
    assert "stale_working_set" in reasons or "stale_decision_or_write" in reasons


def test_phase_auto_transitions_to_prove_after_three_addresses():
    srv = _DummyServer()
    for addr in ("0x401000", "0x401100", "0x401200"):
        srv._handle_blackboard({"action": "write", "title": f"seen {addr}", "addr": addr, "category": "hypothesis"})
    phase = srv._handle_blackboard({"action": "phase_status"})
    assert phase.get("ok") is True
    assert phase["phase"]["phase"] == "prove"


def test_evidence_gravity_attached_to_write_and_decision_card():
    srv = _DummyServer()
    wr = srv._handle_blackboard(
        {"action": "write", "title": "cfg decrypt", "addr": "0x401000", "content": "seed finding", "category": "hypothesis"}
    )
    assert wr.get("ok") is True
    assert isinstance(wr.get("gravity"), dict)
    assert wr["gravity"].get("ok") is True
    assert "embedding_neighbor_count" in wr["gravity"]

    dc = srv._handle_blackboard(
        {"action": "decision_card", "claim": "analyze 0x401000", "addr": "0x401000", "evidence_for": ["xrefs"]}
    )
    assert dc.get("ok") is True
    assert dc.get("gravity", {}).get("ok") is True


def test_commit_contract_requires_strict_spec():
    srv = _DummyServer()
    srv._handle_blackboard({"action": "phase_set", "phase": "commit"})
    bad = srv._handle_blackboard(
        {"action": "proposal_create", "proposal_type": "rename", "title": "bad", "spec": {"renames": [{"addr": "0x401000"}]}}
    )
    assert bad.get("error") is True
    assert "strict spec" in str(bad.get("message") or "").lower()


def test_finalize_contract_blocks_commit_actions_with_contradictions():
    srv = _DummyServer()
    eid = srv._handle_blackboard({"action": "write", "title": "hyp", "category": "hypothesis"}).get("entry_id")
    srv._handle_blackboard({"action": "contradict", "entry_id": eid, "reason": "wrong"})
    srv._handle_blackboard({"action": "phase_set", "phase": "finalize"})
    blocked = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename",
            "spec": {"renames": [{"addr": "0x401000", "name": "x"}]},
        }
    )
    assert blocked.get("error") is True
    assert "unresolved contradictions" in str(blocked.get("message") or "").lower()


def test_quest_board_and_memory_compile_actions():
    srv = _DummyServer()
    srv._handle_blackboard({"action": "write", "title": "candidate", "addr": "0x401000", "category": "hypothesis", "confidence": 0.8})
    qb = srv._handle_blackboard({"action": "quest_board", "limit": 8})
    assert qb.get("ok") is True
    assert qb.get("count", 0) >= 1
    assert any(q.get("quest_type") == "trace_caller" for q in qb.get("quests", []))

    qc = srv._handle_blackboard(
        {
            "action": "quest_complete",
            "quest_id": "q-1",
            "quest_type": "verify_this",
            "status": "completed",
            "result": "verified via xrefs and strings",
            "evidence": ["xref_analysis influence", "code callers"],
            "entry_id": "",
            "addr": "0x401000",
        }
    )
    assert qc.get("ok") is True
    assert qc.get("quest", {}).get("status") == "completed"

    mc = srv._handle_blackboard({"action": "memory_compile", "limit": 10})
    assert mc.get("ok") is True
    assert "facts" in mc
    assert "open_hypotheses" in mc
    assert "next_frontier" in mc
    assert "quest_metrics" in mc
    assert mc["quest_metrics"]["completed"] >= 1
    assert "phase_quality" in mc
    assert mc["phase_quality"]["score"] >= 0


def test_phase_tick_reports_contracts_and_escape_route_on_loop():
    srv = _DummyServer()
    srv._handle_blackboard({"action": "phase_set", "phase": "scout", "auto_transition": True})
    # Force repetitive action pattern to trigger loop detection
    for _ in range(4):
        srv._handle_blackboard({"action": "search", "query": "cfg"})
    tick = srv._handle_blackboard({"action": "phase_tick", "limit": 3})
    assert tick.get("ok") is True
    assert "contracts" in tick
    assert isinstance(tick.get("recommendations"), list)
    if tick.get("loop_detected"):
        assert isinstance(tick.get("escape_route_targets"), list)


def test_phase_tick_in_prove_requires_receipts_signal():
    srv = _DummyServer()
    srv._handle_blackboard({"action": "phase_set", "phase": "prove"})
    tick = srv._handle_blackboard({"action": "phase_tick"})
    assert tick.get("ok") is True
    assert tick.get("phase", {}).get("phase") == "prove"
    assert tick.get("prove_receipts_ready") is False
    assert any("decision_card" in r.lower() for r in tick.get("recommendations", []))


def test_prove_receipts_require_tool_cited_evidence():
    srv = _DummyServer()
    srv._handle_blackboard({"action": "phase_set", "phase": "prove"})
    srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_hypotheses",
            "claim": "weak evidence",
            "evidence_for": ["found constants", "looks right"],
        }
    )
    blocked = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename blocked",
            "spec": {"renames": [{"addr": "0x401000", "name": "f1"}]},
        }
    )
    assert blocked.get("error") is True

    srv._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_hypotheses",
            "claim": "strong evidence",
            "evidence_for": ["code: caller fanout from reset", "xref_analysis: influence depth=2"],
            "addr": "0x401000",
        }
    )
    srv._handle_blackboard({"action": "trace_ingest", "text": "trace 0x401000 cfg"})
    srv._handle_blackboard({"action": "trace_run", "limit": 1})
    ok = srv._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename allowed",
            "spec": {"renames": [{"addr": "0x401000", "name": "f2"}]},
        }
    )
    assert ok.get("ok") is True


def test_memory_compile_can_emit_markdown_snapshot(tmp_path):
    srv = _DummyServer()
    srv._handle_blackboard({"action": "write", "title": "fact1", "category": "fact", "addr": "0x401000", "confidence": 0.9})
    out = tmp_path / "compiled_notes.md"
    res = srv._handle_blackboard({"action": "memory_compile", "limit": 8, "notes_path": str(out)})
    assert res.get("ok") is True
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "Memory Compiler Snapshot" in text
    assert "Next Frontier" in text
