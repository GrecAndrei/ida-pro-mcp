"""Regression tests for p06_blackboard fixes.

Covers the audit-confirmed defects in the blackboard host mixin and the
blackboard tool surface:
  - proposal_accept used an undefined ``_proposal_verify`` (AttributeError)
  - proposal_accept dry_run mutated the proposal to 'accepted'
  - proposal status tags accumulated (store unions tags) and trace_run
    re-executed completed tasks forever
  - ``frontier``/``next_target`` summaries ignored the store's ``address`` key
  - ``update`` with status forwarded arbitrary fields into ``transition``
  - ``read`` returned INVALID_ARGS instead of NOT_FOUND
  - the prove-receipt gate only saw hypothesis-category cards (lane_now cards
    were invisible), and scout could jump straight to commit past the gate
  - ``_phase_find_loop`` flagged clean A/B alternations as stuck loops
  - ``_bb_policy_check`` was decorative (always ok=True)
  - ``blackboard(action='coverage')`` hardcoded coverage_pct to 0.0
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def _server_with_workspace(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"p06-fixes")
    server = object.__new__(ServerBlackboardMixin)
    if not hasattr(ServerBlackboardMixin, "_blackboard_module"):
        ServerBlackboardMixin._blackboard_module = None
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "a.i64"),
        session_id="sess-p06",
    )
    server.current_session = session
    store = BlackboardStore(server._session_blackboard_path(session_obj=session))
    return server, store


def _in_commit_phase(server):
    """Move the phase state to commit so proposal ops pass the evidence gate.

    `_handle_blackboard` runs the phase contract unconditionally: proposal
    ops in scout auto-transition to prove, which then blocks until evidence
    receipts exist. These tests exercise the proposal machinery itself, so
    they seed the phase at commit (where proposal_accept is allowed).
    """
    server._blackboard_phase_state = {
        "phase": "commit",
        "auto_transition": True,
        "recent_actions": [],
        "seen_addrs": ["0x401000", "0x402000", "0x403000"],
        "last_transition_reason": "test setup",
    }


def _write_proposal(store, status="proposed"):
    return store.write(
        title="Rename handle_recv",
        content=json.dumps({
            "proposal_type": "rename",
            "spec": {"renames": [{"addr": "0x401000", "name": "handle_recv"}]},
            "verification_spec": {"kind": "symbol_name_match"},
            "status": status,
        }),
        category="proposal",
        addr="0x401000",
        tags=["proposal_lifecycle", f"status:{status}", "proposal_type:rename"],
        confidence=0.7,
        source="test",
        source_type="proposal",
    )


# ---------------------------------------------------------------------------
# proposal_accept / proposal lifecycle
# ---------------------------------------------------------------------------

def test_proposal_accept_no_longer_raises_and_records_status(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    _in_commit_phase(server)
    pid = _write_proposal(store)

    result = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})

    assert result["ok"] is True
    assert result["status"] in ("verified", "failed")
    entry = store.read(pid)
    payload = json.loads(entry["content"])
    assert payload["status"] == result["status"]
    # An accepted proposal is no longer listed as proposed.
    assert server._proposal_entries(store, status="proposed") == []
    assert server._proposal_entries(store, status=result["status"]) == [entry]


def test_proposal_accept_dry_run_does_not_mutate(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    _in_commit_phase(server)
    pid = _write_proposal(store)

    result = server._handle_blackboard(
        {"action": "proposal_accept", "proposal_id": pid, "dry_run": True}
    )

    assert result["ok"] is True
    assert result["dry_run"] is True
    entry = store.read(pid)
    payload = json.loads(entry["content"])
    assert payload["status"] == "proposed"
    tags = entry["tags"]
    assert "status:accepted" not in tags
    assert server._proposal_entries(store, status="proposed") == [entry]


def test_proposal_reject_records_content_status(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    _in_commit_phase(server)
    pid = _write_proposal(store)

    result = server._handle_blackboard({"action": "proposal_reject", "proposal_id": pid})

    assert result["ok"] is True
    entry = store.read(pid)
    assert json.loads(entry["content"])["status"] == "rejected"
    assert server._proposal_entries(store, status="proposed") == []
    assert server._proposal_entries(store, status="rejected") == [entry]


# ---------------------------------------------------------------------------
# trace task lifecycle (payload status is authoritative; tags accumulate)
# ---------------------------------------------------------------------------

def test_trace_run_does_not_rerun_completed_tasks(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    first = server._handle_blackboard({"action": "trace_ingest", "text": "inspect 0x401000 and 0x401020"})
    assert first["ok"] is True

    run_one = server._handle_blackboard({"action": "trace_run", "limit": 10})
    assert run_one["ok"] is True
    assert run_one["enqueued"] == 1
    server._orchestration().drain(timeout=10)

    run_two = server._handle_blackboard({"action": "trace_run", "limit": 10})
    assert run_two["enqueued"] == 0


def test_trace_status_reads_payload_status_not_accumulated_tags(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    server._handle_blackboard({"action": "trace_ingest", "text": "inspect 0x401000"})
    server._handle_blackboard({"action": "trace_run", "limit": 10})
    # trace_run is non-blocking (enqueue + worker pool); drain so the status
    # assertions below are deterministic.
    server._orchestration().drain(timeout=10)

    pending = server._handle_blackboard({"action": "trace_status", "status": "pending"})
    assert pending["count"] == 0
    all_tasks = server._handle_blackboard({"action": "trace_status"})
    assert all_tasks["count"] == 1
    assert all_tasks["tasks"][0]["status"] == "done"


# ---------------------------------------------------------------------------
# frontier / next_target summaries
# ---------------------------------------------------------------------------

def test_frontier_action_returns_without_type_error(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    # No live IDA session, so no neighbours — but the call must not raise
    # TypeError from passing strategy= to next_target.
    result = server._handle_blackboard({"action": "frontier", "limit": 5})
    assert result["ok"] is True
    assert isinstance(result.get("frontier"), list)
    assert "count" in result


def test_next_target_strategy_summary_uses_address_key(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    store.upsert_finding(
        "Open question about frame length", addr="0x401000", kind="question", status="open"
    )
    result = server._handle_blackboard({"action": "next_target", "strategy": "unresolved"})
    assert result["ok"] is True
    summary = result["summary"]
    assert summary["count"] >= 1
    assert summary["best_addr"] == "0x401000"
    assert summary["briefs"][0]["addr"] == "0x401000"


# ---------------------------------------------------------------------------
# update action with status + extra fields
# ---------------------------------------------------------------------------

def test_update_with_status_and_category_no_type_error(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    eid = store.upsert_finding("Parser length", addr="0x401000", category="parsing")["entry_id"]

    result = server._handle_blackboard(
        {"action": "update", "entry_id": eid, "status": "confirmed", "category": "fact"}
    )

    assert result["ok"] is True
    entry = store.read(eid)
    assert entry["status"] == "confirmed"
    assert entry["category"] == "fact"


def test_read_missing_entry_returns_not_found(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "read", "entry_id": "does-not-exist"})
    assert result.get("error") is True
    assert result.get("code") == MCPError.NOT_FOUND


# ---------------------------------------------------------------------------
# prove receipts: lane_now decision cards count, scout cannot skip the gate
# ---------------------------------------------------------------------------

def test_phase_prove_receipts_see_lane_now_decision_cards(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    store.write(
        title="trace task done",
        content=json.dumps({"status": "done", "entities": {}}),
        category="trace_task",
        tags=["trace_task", "status:done"],
    )
    # A done trace task alone is not enough.
    assert server._phase_has_prove_receipts(store) is False

    # A lane_now decision card (category wm_now, not hypothesis) must count.
    card = server._handle_blackboard(
        {
            "action": "decision_card",
            "lane": "lane_now",
            "claim": "handle_recv parses a length prefix",
            "evidence_for": ["code:smart_decompile"],
        }
    )
    assert card["ok"] is True
    assert server._phase_has_prove_receipts(store) is True


def test_scout_proposal_ops_route_through_prove_when_no_receipts(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    state = server._phase_state()
    state["phase"] = "scout"
    state["auto_transition"] = True

    server._phase_auto_transition(
        state, "proposal_create", {"proposal_type": "rename", "spec": {}}, store
    )

    assert state["phase"] == "prove", "scout must not skip the prove gate"


# ---------------------------------------------------------------------------
# loop detection
# ---------------------------------------------------------------------------

def test_phase_find_loop_does_not_flag_alternation(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    assert server._phase_find_loop({"recent_actions": ["a", "b", "a", "b", "a", "b"]}) is False
    assert server._phase_find_loop({"recent_actions": ["a", "a", "a", "a", "a", "a"]}) is True


# ---------------------------------------------------------------------------
# strict policy check is no longer decorative
# ---------------------------------------------------------------------------

def test_bb_policy_check_enforces_recent_working_set_and_decision(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    base = {
        "strict_mode": True,
        "max_staleness_calls": 6,
        "require_working_set": True,
        "require_decision_or_write": True,
        "enforce_phases": ["commit", "finalize"],
        "policy_markers": [],
    }

    stale = dict(base, last_call_count_at_update=10)
    assert server._bb_policy_check(stale)["ok"] is False

    fresh = dict(base, last_call_count_at_update=10, policy_markers=["working_set@9", "decision@9"])
    assert server._bb_policy_check(fresh)["ok"] is True

    aged = dict(base, last_call_count_at_update=20, policy_markers=["working_set@9", "decision@9"])
    assert server._bb_policy_check(aged)["ok"] is False


# ---------------------------------------------------------------------------
# blackboard(action='coverage') computes a real percentage
# ---------------------------------------------------------------------------

def test_coverage_action_computes_real_percentage(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    assert server._get_blackboard_store() is not None

    store.record_examination("0x401000", verdict="interesting", note="handler")
    store.upsert_finding("Handle recv", addr="0x402000", category="parsing")

    # The IDA-side tool module is a thin bridge after the redesign; coverage
    # is computed by the host dispatcher over the store.
    result = server._handle_blackboard({"action": "coverage"})

    assert result["ok"] is True
    assert result["analyzed"] == 1
    assert result["total_entries"] == 2
    assert result["unvisited"] == 1
    assert result["coverage_pct"] == 50.0
