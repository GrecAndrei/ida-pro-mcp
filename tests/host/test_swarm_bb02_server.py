"""Regression tests for bb02: dict-driven host blackboard surface.

The host blackboard handler (``server_blackboard.py``) was rewritten to be
dict-driven over the new store: every action routes to a ``_bb_action_*``
method, the governance gate runs once per dispatch, evidence gravity is a
bounded snapshot fired only on create, ``trace_run`` is non-blocking
(enqueue + drain), and the crawler writes real proposed entries into the
workspace. These tests exercise the host mixin in isolation with fake
sessions — no live IDA, no IDB.

Covers:
  - dict-driven dispatch: every table action reaches a real handler method
  - removed actions return ACTION_NOT_FOUND (quest_board, quest_complete,
    propagate_labels, semantic_index, semantic_rebuild)
  - POLICY_DENIED envelopes from the strict policy gate
  - bounded evidence gravity (<= EVIDENCE_GRAVITY_MAX_ITEMS) fired on create
  - async trace lifecycle: ingest -> run (non-blocking) -> drain -> status
  - crawler writes a real proposed entry; the notification carries its real id
  - unified proposal lifecycle over real entries (create / accept / reject)
  - crawler_status canonical shape (no ``proposals_pending`` alias)
  - opaque raw-blob / RISC-V scenario (no IDB, sha256-scoped workspace)
  - lifecycle scenario: open -> confirmed -> contradicted (rejected) -> resolved
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.blackboard_orchestration import (
    EVIDENCE_GRAVITY_MAX_ITEMS,
    NS_GRAVITY,
)
from ida_pro_mcp.host.server.server_blackboard import (
    _BLACKBOARD_ACTIONS,
    ServerBlackboardMixin,
)


def _make_server(tmp_path) -> ServerBlackboardMixin:
    server = object.__new__(ServerBlackboardMixin)
    if not hasattr(ServerBlackboardMixin, "_blackboard_module"):
        ServerBlackboardMixin._blackboard_module = None
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    return server


def _make_session(tmp_path, tag: str, sid: str) -> SimpleNamespace:
    binary = tmp_path / f"{tag}.bin"
    binary.write_bytes(tag.encode() * 8)
    return SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / f"{tag}.i64"),
        session_id=sid,
    )


def _set_phase(server, phase: str, auto_transition: bool = True) -> None:
    server._blackboard_phase_state = {
        "phase": phase,
        "auto_transition": auto_transition,
        "recent_actions": [],
        "seen_addrs": ["0x401000", "0x402000", "0x403000"],
        "last_transition_reason": "test setup",
    }


# ---------------------------------------------------------------------------
# dict-driven dispatch
# ---------------------------------------------------------------------------


def test_dict_dispatch_routes_every_table_action_to_a_handler(tmp_path):
    for action, handler_name in _BLACKBOARD_ACTIONS.items():
        handler = getattr(ServerBlackboardMixin, handler_name, None)
        assert callable(handler), f"{action} -> {handler_name} is not a callable method"

    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "dispatch", "SESS-D")

    res = server._handle_blackboard({"action": "list", "limit": 5})
    assert res["ok"] is True

    res = server._handle_blackboard({"action": "stats"})
    assert res["ok"] is True

    res = server._handle_blackboard(
        {"action": "write", "name": "obs", "addr": "0x401000", "notes": "x"}
    )
    assert res["ok"] is True
    assert res["created"] is True


def test_removed_actions_return_action_not_found(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "dead", "SESS-DEAD")
    for action in (
        "quest_board",
        "quest_complete",
        "propagate_labels",
        "semantic_index",
        "semantic_rebuild",
    ):
        res = server._handle_blackboard({"action": action})
        assert res.get("error") is True, f"{action} should not be handled: {res}"
        assert res.get("code") == MCPError.ACTION_NOT_FOUND, f"{action}: {res}"


def test_unknown_action_returns_action_not_found(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "unk", "SESS-U")
    res = server._handle_blackboard({"action": "definitely_not_an_action"})
    assert res.get("code") == MCPError.ACTION_NOT_FOUND
    assert res.get("error") is True


# ---------------------------------------------------------------------------
# governance: POLICY_DENIED envelopes
# ---------------------------------------------------------------------------


def test_strict_policy_gate_returns_policy_denied_envelope(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "pol", "SESS-POL")
    _set_phase(server, "commit")
    server._blackboard_policy_state = {
        "strict_mode": True,
        "max_staleness_calls": 6,
        "require_working_set": True,
        "require_decision_or_write": True,
        "enforce_phases": ["commit"],
        "last_call_count_at_update": 50,
        "policy_markers": [],
    }
    store = server._get_blackboard_store()
    pid = store.write(
        title="rename candidate",
        content=json.dumps(
            {
                "proposal_type": "rename",
                "spec": {"renames": [{"addr": "0x401000", "name": "parse_pkt"}]},
                "status": "proposed",
            }
        ),
        category="proposal",
        addr="0x401000",
        tags=["proposal_type:rename", "status:proposed"],
        status="proposed",
    )

    denied = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert denied["ok"] is False
    assert denied["code"] == MCPError.POLICY_DENIED
    assert denied["gate"] == "policy"
    assert denied["phase"] == "commit"

    # After a working_set + write the markers are fresh and the gate clears.
    server._handle_blackboard({"action": "working_set", "limit": 3})
    server._handle_blackboard(
        {"action": "write", "name": "observation", "addr": "0x401000", "notes": "seen"}
    )
    accepted = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert accepted["ok"] is True
    assert accepted["status"] == "verified"


def test_policy_only_actions_need_no_store(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = None
    res = server._handle_blackboard({"action": "policy_status"})
    assert res["ok"] is True
    assert "policy" in res


# ---------------------------------------------------------------------------
# evidence gravity (bounded, fired only on create)
# ---------------------------------------------------------------------------


def test_evidence_gravity_is_bounded_and_persisted(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "grav", "SESS-G")
    store = server._get_blackboard_store()

    # A fake runtime that would otherwise return unbounded probe results.
    server._execute_tool = lambda tool, payload: {"ok": True, "nodes": list(range(50))}

    snap = server._evidence_gravity(
        store, source_entry_id="new-entry", addr="0x401000", source_text="check 0x401000"
    )
    assert snap["ok"] is True
    assert len(snap["items"]) <= EVIDENCE_GRAVITY_MAX_ITEMS

    # The raw bounded snapshot is persisted in bb_machinery under the gravity
    # namespace so it survives without polluting the findings table.
    raw = server._orchestration().machinery_get(store, NS_GRAVITY, "new-entry")
    assert raw is not None
    assert raw["source_entry_id"] == "new-entry"
    assert len(raw["items"]) <= EVIDENCE_GRAVITY_MAX_ITEMS
    tools_used = [item.get("tool") for item in snap["items"] if item.get("tool") != "semantic"]
    assert "search" not in tools_used


def test_write_fires_gravity_only_on_create(tmp_path, monkeypatch):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "wgrav", "SESS-WG")

    calls: list[dict] = []

    def fake_gravity(self, store, source_entry_id: str, addr: str, source_text: str = ""):
        calls.append({"entry_id": source_entry_id, "addr": addr})
        return {"ok": True, "entry_id": "gravity-row"}

    monkeypatch.setattr(type(server), "_evidence_gravity", fake_gravity)

    first = server._handle_blackboard(
        {"action": "write", "name": "Parser length unchecked", "addr": "0x401000", "notes": "Initial"}
    )
    second = server._handle_blackboard(
        {"action": "write", "name": "Parser length unchecked", "addr": "0x401000", "notes": "Merged"}
    )

    assert first["created"] is True
    assert first["gravity"] == {"ok": True, "entry_id": "gravity-row"}
    assert second["created"] is False
    assert second["gravity"] is None
    assert len(calls) == 1
    assert calls[0]["addr"] == "0x401000"


# ---------------------------------------------------------------------------
# trace tasks: non-blocking trace_run
# ---------------------------------------------------------------------------


def test_trace_lifecycle_ingest_run_drain_status(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "trace", "SESS-T")

    ing = server._handle_blackboard(
        {"action": "trace_ingest", "text": "check who calls 0x80000000 and sub_1234"}
    )
    assert ing["ok"] is True
    task_id = ing["trace_task_id"]
    assert ing["status"] == "pending"

    # trace_run enqueues and returns immediately (non-blocking).
    run = server._handle_blackboard({"action": "trace_run", "limit": 5})
    assert run["ok"] is True
    assert run["status"] == "running"
    assert run["enqueued"] == 1
    assert run["task_ids"] == [task_id]
    assert "ran" not in run and "results" not in run

    # Drain waits for the background worker, then status reflects completion.
    server._orchestration().drain(timeout=10)
    st = server._handle_blackboard({"action": "trace_status", "status": "done"})
    assert st["ok"] is True
    assert any(t["trace_task_id"] == task_id for t in st["tasks"])


# ---------------------------------------------------------------------------
# crawler: real proposed entries + corrected notification
# ---------------------------------------------------------------------------


def test_crawler_writes_real_proposed_entry_and_notifies_with_real_id(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "crawl", "SESS-C")
    store = server._get_blackboard_store()
    store.write(
        title="suspicious function",
        category="hypothesis",
        addr="0x1c000100",
        kind="hypothesis",
        status="open",
    )

    notifications: list[dict] = []

    def capture(notification: dict) -> None:
        notifications.append(notification)

    server._send_notification = capture

    orch = server._orchestration()

    def probe(addr: str) -> dict:
        return {
            "title": f"candidate {addr}",
            "findings": ["Raw indirect branch target; check pointer validation"],
            "labels": ["indirect_jump", "rv64"],
        }

    orch._crawler._probe = probe
    orch._crawler._notify_fn = capture

    entry_id = orch.crawl_step(store)
    assert entry_id, "crawler produced no proposal"

    entry = store.read(entry_id)
    assert entry is not None
    assert entry.get("category") == "proposal"
    payload = json.loads(entry["content"])
    assert payload["status"] == "proposed"
    assert payload["proposal_type"] == "rename"
    assert payload["spec"]["renames"][0]["addr"] == "0x1c000100"

    # The notification carries the REAL proposal entry id, not a placeholder.
    assert notifications, "crawler emitted no notification"
    data = notifications[0]["params"]["data"]
    assert data["proposals"][0]["proposal_id"] == entry_id

    # crawler_status uses the canonical shape (no proposals_pending alias).
    status = server._handle_blackboard({"action": "crawler_status"})
    assert status["ok"] is True
    assert "proposals_pending" not in status
    assert status["pending_proposals"] >= 1
    assert any(p.get("proposal_id") == entry_id for p in status["proposals"])


def test_crawler_start_stop_roundtrip(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "cstart", "SESS-CS")
    started = server._handle_blackboard({"action": "start_crawler"})
    assert started["ok"] is True
    assert started["running"] is True
    stopped = server._handle_blackboard({"action": "stop_crawler"})
    assert stopped["ok"] is True
    assert stopped["running"] is False


# ---------------------------------------------------------------------------
# proposal lifecycle over real entries
# ---------------------------------------------------------------------------


def test_proposal_lifecycle_create_accept_reject(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "prop", "SESS-P")
    # Pin phase to scout with auto_transition off so the lifecycle test is
    # deterministic and not routed through the prove-evidence gate.
    _set_phase(server, "scout", auto_transition=False)

    created = server._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename sub_401000",
            "addr": "0x401000",
            "spec": {"renames": [{"addr": "0x401000", "name": "parse_pkt"}]},
        }
    )
    assert created["ok"] is True
    pid = created["proposal_id"]
    assert created["status"] == "proposed"

    lst = server._handle_blackboard({"action": "proposal_list", "status": "proposed"})
    assert any(p["proposal_id"] == pid for p in lst["proposals"])

    # dry_run previews acceptance without mutating.
    dry = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid, "dry_run": True})
    assert dry["ok"] is True
    assert dry["dry_run"] is True
    lst2 = server._handle_blackboard({"action": "proposal_list", "status": "proposed"})
    assert any(p["proposal_id"] == pid for p in lst2["proposals"])

    # Real accept: no runtime hook -> verification passes, apply is a no-op.
    acc = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert acc["ok"] is True
    assert acc["status"] == "verified"

    # Reject a second proposal.
    pid2 = server._handle_blackboard(
        {
            "action": "proposal_create",
            "proposal_type": "rename",
            "title": "rename sub_402000",
            "addr": "0x402000",
            "spec": {"renames": [{"addr": "0x402000", "name": "other_fn"}]},
        }
    )["proposal_id"]
    rej = server._handle_blackboard(
        {"action": "proposal_reject", "proposal_id": pid2, "reason": "wrong guess"}
    )
    assert rej["ok"] is True
    assert rej["status"] == "rejected"

    all_list = server._handle_blackboard({"action": "proposal_list"})
    by_id = {p["proposal_id"]: p["status"] for p in all_list["proposals"]}
    assert by_id[pid] == "verified"
    assert by_id[pid2] == "rejected"


def test_crawler_proposal_can_be_accepted_via_lifecycle(tmp_path):
    """The accept/reject short actions delegate to the unified lifecycle."""
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "acc", "SESS-A")
    _set_phase(server, "scout", auto_transition=False)
    store = server._get_blackboard_store()
    store.write(
        title="suspicious function",
        category="hypothesis",
        addr="0x1c000200",
        kind="hypothesis",
        status="open",
    )
    orch = server._orchestration()

    def probe(addr: str) -> dict:
        return {
            "title": f"candidate {addr}",
            "findings": ["indirect branch"],
            "labels": ["rv64"],
        }

    orch._crawler._probe = probe
    entry_id = orch.crawl_step(store)
    assert entry_id
    res = server._handle_blackboard({"action": "accept", "proposal_id": entry_id})
    assert res["ok"] is True
    assert res["status"] == "verified"
    assert store.read(entry_id)["status"] == "verified"


# ---------------------------------------------------------------------------
# opaque raw-blob / RISC-V scenario (no IDB)
# ---------------------------------------------------------------------------


def test_raw_riscv_blob_workspace_without_idb(tmp_path):
    # A bare RISC-V firmware blob: opaque bytes, no ELF/PE structure, no IDB.
    blob = tmp_path / "rv_fw_blob.bin"
    blob.write_bytes(bytes(range(256)) * 16)
    server = _make_server(tmp_path)
    server.current_session = SimpleNamespace(
        binary_path=str(blob),
        idb_path="",
        session_id="SESS-RV",
    )

    res = server._handle_blackboard(
        {
            "action": "write",
            "name": "raw reset vector",
            "addr": "0x8000",
            "notes": "RV32 reset vector is a jump to 0x80000000",
            "category": "hypothesis",
            "confidence": 0.7,
        }
    )
    assert res["ok"] is True
    assert res["created"] is True
    eid = res["entry_id"]

    rd = server._handle_blackboard({"action": "read", "entry_id": eid})
    assert rd["ok"] is True
    assert rd["entry"]["addr"] == "0x8000"

    sr = server._handle_blackboard({"action": "search", "query": "vector", "limit": 5})
    assert sr["ok"] is True
    assert sr["count"] >= 1

    nt = server._handle_blackboard({"action": "next_target", "limit": 3})
    assert nt["ok"] is True
    assert "targets" in nt
    assert "strategies" in nt


# ---------------------------------------------------------------------------
# lifecycle scenario: open -> confirmed -> contradicted -> resolved
# ---------------------------------------------------------------------------


def test_entry_lifecycle_open_confirmed_contradicted_resolved(tmp_path):
    server = _make_server(tmp_path)
    server.current_session = _make_session(tmp_path, "life", "SESS-L")
    _set_phase(server, "scout", auto_transition=False)

    w = server._handle_blackboard(
        {
            "action": "write",
            "name": "length field unchecked",
            "addr": "0x401000",
            "notes": "candidate claim",
            "kind": "hypothesis",
            "status": "proposed",
        }
    )
    assert w["ok"] is True
    eid = w["entry_id"]
    assert server._get_blackboard_store().read(eid)["status"] == "proposed"

    # proposed -> confirmed via the update/transition action.
    up = server._handle_blackboard(
        {"action": "update", "entry_id": eid, "status": "confirmed", "reason": "verified against IDA"}
    )
    assert up["ok"] is True
    assert server._get_blackboard_store().read(eid)["status"] == "confirmed"

    # confirmed -> contradicted (contradict rejects the entry).
    c = server._handle_blackboard(
        {"action": "contradict", "entry_id": eid, "reason": "counter-evidence found"}
    )
    assert c["ok"] is True
    assert server._get_blackboard_store().read(eid)["status"] == "rejected"

    # contradicted -> resolved.
    r = server._handle_blackboard({"action": "resolve", "entry_id": eid})
    assert r["ok"] is True
    assert server._get_blackboard_store().read(eid)["status"] == "resolved"
