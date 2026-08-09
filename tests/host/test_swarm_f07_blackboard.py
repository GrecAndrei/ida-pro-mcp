"""Regression tests for f07_blackboard audit findings.

Covers:
  - [high] phase/policy state is per-session, not a host-global singleton
  - [medium] bool-string coercion (bool("false") is True) via _coerce_bool
  - [medium] patch proposals are never marked 'verified' when not applied
  - [medium] a trace that gathered no evidence is 'failed', not a prove receipt
  - [medium] export/notes_import/memory_compile paths are confined to a root
  - [medium] clear/delete/prune warn that scope is the binary-wide workspace
  - [medium] malformed numeric args return an INVALID_ARGS envelope
  - [low] a store-open failure surfaces the cause instead of opaque unavailable
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin


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
    binary.write_bytes(tag.encode())
    return SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / f"{tag}.i64"),
        session_id=sid,
    )


def _set_phase(server, phase: str) -> None:
    server._blackboard_phase_state = {
        "phase": phase,
        "auto_transition": True,
        "recent_actions": [],
        "seen_addrs": ["0x401000", "0x402000", "0x403000"],
        "last_transition_reason": "test setup",
    }


# ---------------------------------------------------------------------------
# [high] per-session phase/policy state
# ---------------------------------------------------------------------------

def test_phase_state_is_per_session(tmp_path):
    server = _make_server(tmp_path)
    sess_a = _make_session(tmp_path, "bin-a", "SESS-A")
    sess_b = _make_session(tmp_path, "bin-b", "SESS-B")

    server.current_session = sess_a
    # memory_compile auto-transitions the session to 'finalize'.
    server._handle_blackboard({"action": "memory_compile"})
    store_a = server._get_blackboard_store()
    eid = store_a.upsert_finding("claim", addr="0x401000")["entry_id"]
    store_a.contradict(eid, "counter-evidence")
    assert server._phase_state()["phase"] == "finalize"

    # Session B on the same host starts fresh — no leaked phase machine.
    server.current_session = sess_b
    assert server._phase_state()["phase"] == "scout"
    assert server._phase_state()["recent_actions"] == []

    # A is untouched by B's reads.
    server.current_session = sess_a
    assert server._phase_state()["phase"] == "finalize"


def test_policy_state_is_per_session(tmp_path):
    server = _make_server(tmp_path)
    sess_a = _make_session(tmp_path, "bin-a", "SESS-A")
    sess_b = _make_session(tmp_path, "bin-b", "SESS-B")

    server.current_session = sess_a
    server._handle_blackboard({"action": "write", "name": "obs", "addr": "0x401000", "notes": "x"})
    state_a = server._bb_policy_state()
    assert state_a.get("policy_markers"), "session A should have a write marker"
    assert state_a.get("last_call_count_at_update", 0) >= 1

    server.current_session = sess_b
    state_b = server._bb_policy_state()
    assert state_b.get("policy_markers") == []
    assert state_b.get("last_call_count_at_update") == 0

    # A's marker does not satisfy B's staleness gate: B has no markers, so a
    # call 10 steps after the (never-recorded) working_set/decision is stale.
    state_b["strict_mode"] = True
    state_b["last_call_count_at_update"] = 10
    assert server._bb_policy_check(state_b)["ok"] is False


def test_finalize_in_one_session_does_not_block_another(tmp_path):
    server = _make_server(tmp_path)
    server._phase_gates_enabled = True
    sess_a = _make_session(tmp_path, "bin-a", "SESS-A")
    sess_b = _make_session(tmp_path, "bin-b", "SESS-B")

    server.current_session = sess_a
    server._handle_blackboard({"action": "memory_compile"})
    store_a = server._get_blackboard_store()
    eid = store_a.upsert_finding("claim", addr="0x401000")["entry_id"]
    store_a.contradict(eid, "counter-evidence")
    assert server._phase_state()["phase"] == "finalize"
    assert server._phase_preflight_for_tool("modify", {"action": "rename", "addr": "0x402000"}) is not None

    server.current_session = sess_b
    assert server._phase_preflight_for_tool("modify", {"action": "rename", "addr": "0x402000"}) is None


# ---------------------------------------------------------------------------
# [medium] bool-string coercion
# ---------------------------------------------------------------------------

def test_policy_set_strict_mode_false_string_is_coerced(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-pol", "SESS-POL")
    server.current_session = sess

    res = server._handle_blackboard({"action": "policy_set", "strict_mode": "false"})
    assert res["ok"] is True
    status = server._handle_blackboard({"action": "policy_status"})
    assert status["policy"]["strict_mode"] is False


def test_export_include_resolved_false_string_excludes_resolved(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-exp", "SESS-EXP")
    server.current_session = sess
    store = server._get_blackboard_store()
    store.upsert_finding("Resolved thing", addr="0x401000", category="parsing", kind="finding", status="resolved")
    store.upsert_finding("Open thing", addr="0x402000", category="parsing", kind="finding", status="open")

    res = server._handle_blackboard({"action": "export", "format": "json", "include_resolved": "false"})
    assert res["ok"] is True
    snapshot = json.loads(res["content"])
    titles = [e["title"] for e in snapshot["entries"]]
    assert "Open thing" in titles
    assert "Resolved thing" not in titles


def test_dry_run_false_string_runs_live_accept(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-dr", "SESS-DR")
    server.current_session = sess
    _set_phase(server, "commit")
    server._execute_tool = lambda tool, args: {"ok": True}
    store = server._get_blackboard_store()
    pid = store.write(
        title="Rename handle_recv",
        content=json.dumps({
            "proposal_type": "rename",
            "spec": {"renames": [{"addr": "0x401000", "name": "handle_recv"}]},
            "verification_spec": {"kind": "symbol_name_match"},
            "status": "proposed",
        }),
        category="proposal",
        addr="0x401000",
        tags=["proposal_lifecycle", "status:proposed", "proposal_type:rename"],
        confidence=0.7,
        source="test",
        source_type="proposal",
    )

    res = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid, "dry_run": "false"})
    assert res["ok"] is True
    entry = store.read(pid)
    assert json.loads(entry["content"])["status"] != "proposed", "dry_run='false' must execute, not preview"


# ---------------------------------------------------------------------------
# [medium] patch proposals must not report 'verified' when unapplied
# ---------------------------------------------------------------------------

def test_patch_proposal_accept_is_not_marked_verified(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-patch", "SESS-PATCH")
    server.current_session = sess
    _set_phase(server, "commit")
    # A runtime hook exists, so _proposal_execute reaches the (non-functional)
    # patch branch instead of the "hook unavailable" early return.
    server._execute_tool = lambda tool, args: {"ok": True}
    store = server._get_blackboard_store()
    pid = store.write(
        title="Patch nop sled",
        content=json.dumps({
            "proposal_type": "patch",
            "spec": {"patches": [{"addr": "0x401000", "bytes": "9090"}]},
            "verification_spec": {},
            "status": "proposed",
        }),
        category="proposal",
        addr="0x401000",
        tags=["proposal_lifecycle", "status:proposed", "proposal_type:patch"],
        confidence=0.7,
        source="test",
        source_type="proposal",
    )

    res = server._handle_blackboard({"action": "proposal_accept", "proposal_id": pid})
    assert res["status"] == "failed"
    assert res["ok"] is False
    entry = store.read(pid)
    assert json.loads(entry["content"])["status"] == "failed"
    # A failed patch must not be boosted as verified work.
    assert "0x401000" not in server._verified_proposal_addrs(store)


# ---------------------------------------------------------------------------
# [medium] trace_run can mark a task 'failed' when nothing was gathered
# ---------------------------------------------------------------------------

def test_trace_run_marks_failed_when_no_evidence(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-trace", "SESS-TRACE")
    server.current_session = sess
    server._execute_tool = lambda tool, args: {
        "error": True,
        "code": "RPC_CONNECTION_ERROR",
        "message": "no runtime",
    }

    server._handle_blackboard({"action": "trace_ingest", "text": "inspect 0x401000"})
    res = server._handle_blackboard({"action": "trace_run", "limit": 10})
    assert res["ok"] is True
    assert res["enqueued"] == 1
    assert res["status"] == "running"
    # trace_run is non-blocking; drain waits for the background worker.
    server._orchestration().drain(timeout=10)

    status = server._handle_blackboard({"action": "trace_status"})
    task = status["tasks"][0]
    assert task["status"] == "failed"
    # The task's stored result records the failed evidence-gathering run.
    assert task["result"].get("ok") is False
    assert task["result"].get("evidence_count") == 0
    # A failed trace must not satisfy the prove-phase evidence gate.
    assert server._phase_has_prove_receipts(server._get_blackboard_store()) is False


# ---------------------------------------------------------------------------
# [medium] export / notes_import / memory_compile path confinement
# ---------------------------------------------------------------------------

def test_export_path_outside_root_rejected(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-sec", "SESS-SEC")
    server.current_session = sess
    outside = str(tmp_path.parent / "escaped-export.json")

    res = server._handle_blackboard({"action": "export", "format": "json", "path": outside})
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS
    assert not os.path.exists(outside)


def test_export_relative_path_writes_under_root(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-sec2", "SESS-SEC2")
    server.current_session = sess

    res = server._handle_blackboard({"action": "export", "format": "json", "path": "reports/findings.json"})
    assert res["ok"] is True
    assert os.path.isfile(os.path.join(str(tmp_path), "reports", "findings.json"))


def test_notes_import_outside_root_rejected(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-sec3", "SESS-SEC3")
    server.current_session = sess
    outside = tmp_path.parent / "notes.md"
    outside.write_text("- foreign notes line\n")

    res = server._handle_blackboard({"action": "notes_import", "notes_path": str(outside)})
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


def test_memory_compile_notes_path_outside_root_skipped(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-sec4", "SESS-SEC4")
    server.current_session = sess
    outside = tmp_path.parent / "compile.md"

    res = server._handle_blackboard({"action": "memory_compile", "notes_path": str(outside)})
    assert res["ok"] is True
    assert res.get("notes_path") is None
    assert not os.path.exists(outside)


# ---------------------------------------------------------------------------
# [medium] clear/delete/prune warn that scope is the binary-wide workspace
# ---------------------------------------------------------------------------

def test_clear_warns_binary_wide_scope(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-clr", "SESS-CLR")
    server.current_session = sess
    server._get_blackboard_store().upsert_finding("thing", addr="0x401000")

    res = server._handle_blackboard({"action": "clear"})
    assert res["ok"] is True
    assert res.get("scope") == "entire_binary_workspace"
    assert "shared" in res.get("note", "")


def test_delete_and_prune_warn_binary_wide_scope(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-del", "SESS-DEL")
    server.current_session = sess
    store = server._get_blackboard_store()
    eid = store.upsert_finding("thing", addr="0x401000")["entry_id"]

    del_res = server._handle_blackboard({"action": "delete", "entry_id": eid})
    assert del_res["ok"] is True
    assert del_res.get("scope") == "entire_binary_workspace"

    prune_res = server._handle_blackboard({"action": "prune", "max_entries": 1})
    assert prune_res["ok"] is True
    assert prune_res.get("scope") == "entire_binary_workspace"


# ---------------------------------------------------------------------------
# [medium] malformed numeric args surface as INVALID_ARGS, not a raise
# ---------------------------------------------------------------------------

def test_malformed_confidence_returns_invalid_args_envelope(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-num", "SESS-NUM")
    server.current_session = sess

    res = server._handle_blackboard({"action": "decision_card", "claim": "x", "confidence": "abc"})
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS

    res2 = server._handle_blackboard({"action": "decision_card", "claim": "x", "expires_hours": "not-an-int"})
    assert res2.get("error") is True
    assert res2.get("code") == MCPError.INVALID_ARGS


def test_malformed_min_confidence_returns_invalid_args_envelope(tmp_path):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-num2", "SESS-NUM2")
    server.current_session = sess

    res = server._handle_blackboard({"action": "export", "format": "json", "min_confidence": "high"})
    assert res.get("error") is True
    assert res.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# [low] store-open failure surfaces the cause
# ---------------------------------------------------------------------------

def test_store_unavailable_surfaces_cause(tmp_path, monkeypatch):
    server = _make_server(tmp_path)
    sess = _make_session(tmp_path, "bin-err", "SESS-ERR")
    server.current_session = sess

    def _fail(self):
        self._blackboard_store_error = "database is locked"

    monkeypatch.setattr(ServerBlackboardMixin, "_get_blackboard_store", _fail)
    res = server._handle_blackboard({"action": "stats"})
    assert res.get("error") is True
    assert res.get("code") == MCPError.DB_ERROR
    assert "locked" in res.get("message", "")
