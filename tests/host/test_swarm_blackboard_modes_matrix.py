"""End-to-end offline matrix for the shared blackboard action surface."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin


def _server(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"blackboard fixture")
    server = object.__new__(ServerBlackboardMixin)
    # The loader caches the IDA-side module on the class; reset it so this
    # matrix always exercises the real workspace store with its local path.
    ServerBlackboardMixin._blackboard_module = None
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = SimpleNamespace(
        session_id="SID-BB01",
        binary_path=str(binary),
        idb_path=str(tmp_path / "sample.i64"),
    )
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: server.current_session)
    server._blackboard_path_cache = {}
    server._blackboard_store_error = ""
    server._execute_tool = lambda *_args, **_kwargs: {"ok": True}
    server.call_tool = lambda *_args, **_kwargs: {"ok": True}
    return server


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_blackboard_crud_retrieval_and_lifecycle_modes(tmp_path):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()

    policy_set = _ok(server._bb_action_policy_set({"strict_mode": "false", "enforce_phases": "commit,finalize"}, None, phase, policy))
    assert policy_set["strict_mode"] is False
    assert _ok(server._bb_action_policy_status({}, None, phase, policy))["policy"]["enforce_phases"] == ["commit", "finalize"]
    assert _ok(server._bb_action_policy_check({}, None, phase, policy))["ok"] is True
    assert _ok(server._bb_action_phase_status({}, store, phase, policy))["phase"]["phase"] == "scout"
    assert _ok(server._bb_action_phase_set({"phase": "prove", "auto_transition": "false"}, store, phase, policy))["phase"]["phase"] == "prove"
    assert _ok(server._bb_action_phase_tick({"limit": "2"}, store, phase, policy))["ok"] is True

    written = _ok(server._bb_action_write({
        "name": "Network parser", "notes": "reads packet length", "addr": "0x140001000",
        "category": "analysis", "tags": "network|parser", "confidence": "0.8",
        "evidence": [{"kind": "xref", "value": "0x140001008"}],
    }, store, phase, policy))
    eid = written["entry_id"]
    assert store.read(eid)["title"] == "Network parser"
    assert _ok(server._bb_action_list({"category": "analysis", "limit": 10}, store, phase, policy))["count"] >= 1
    assert _ok(server._bb_action_search({"query": "packet", "limit": 5}, store, phase, policy))["count"] >= 1
    assert _ok(server._bb_action_read({"entry_id": eid}, store, phase, policy))["entry"]["id"] == eid
    assert _ok(server._bb_action_update({"entry_id": eid, "confidence": 0.9, "priority": 0.7}, store, phase, policy))["entry"]["confidence"] == 0.9
    assert _ok(server._bb_action_add_evidence({"entry_id": eid, "type": "runtime", "value": "confirmed", "weight": "1.5"}, store, phase, policy))["entry_id"] == eid
    assert _ok(server._bb_action_calibrate({"entry_id": eid}, store, phase, policy))["entry_id"] == eid
    assert _ok(server._bb_action_mark_examined({"addr": "0x140001020", "verdict": "interesting", "note": "follow call", "name": "handler"}, store, phase, policy))["action"] == "mark_examined"
    assert _ok(server._bb_action_recall({"addrs": "0x140001000|0x140001020", "limit": 5}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_next_target({"strategy": "coverage", "limit": 5}, store, phase, policy))["strategy"] == "coverage"
    assert _ok(server._bb_action_frontier({"limit": 5}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_conflicts({"limit": 5}, store, phase, policy))["count"] >= 0
    assert _ok(server._bb_action_stale({"limit": 5}, store, phase, policy))["count"] >= 0
    assert _ok(server._bb_action_stats({}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_coverage({}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_campaign_summary({}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_workspace_brief({"limit": 5}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_working_set({"limit": 3}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_state_health({}, store, phase, policy))["ok"] is True

    assert _ok(server._bb_action_contradict({"entry_id": eid, "reason": "counterexample"}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_resolve({"entry_id": eid}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_decay({"half_life_days": "7", "min_confidence": "0.2"}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_prune({"max_entries": 100}, store, phase, policy))["ok"] is True
    assert _ok(server._bb_action_clear({}, store, phase, policy))["scope"] == "entire_binary_workspace"


def test_blackboard_decision_proposal_export_notes_and_dispatch_modes(tmp_path):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()
    card = _ok(server._bb_action_decision_card({
        "claim": "entry parses network frames", "addr": "0x140001000",
        "evidence_for": "call:x|string:y", "next_step": "inspect length check",
        "confidence": 0.7, "auto_trace": False,
    }, store, phase, policy))
    assert card["card"]["evidence_for"] == ["call:x", "string:y"]

    spec = {"renames": [{"addr": "0x140001000", "name": "parse_frame"}]}
    proposal = _ok(server._bb_action_proposal_create({
        "proposal_type": "rename", "title": "Name frame parser", "spec": spec,
        "addr": "0x140001000", "confidence": 0.8,
    }, store, phase, policy))
    pid = proposal["proposal_id"]
    listed = _ok(server._bb_action_proposal_list({"status": "proposed", "limit": 10}, store, phase, policy))
    assert listed["count"] >= 1
    preview = _ok(server._bb_action_proposal_accept({"proposal_id": pid, "dry_run": "true"}, store, phase, policy))
    assert preview["dry_run"] is True
    rejected = _ok(server._bb_action_proposal_reject({"proposal_id": pid, "reason": "needs review"}, store, phase, policy))
    assert rejected["status"] == "rejected"

    notes = tmp_path / "cache" / "notes.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("# Review\n\n- inspect 0x140001000\n- confirm parser\n", encoding="utf-8")
    imported = _ok(server._bb_action_notes_import({"notes_path": str(notes), "auto_trace": False}, store, phase, policy))
    assert imported["imported"] >= 1
    compiled = _ok(server._bb_action_memory_compile({"limit": 10, "notes_path": str(notes)}, store, phase, policy))
    assert "phase" in compiled

    exported = _ok(server._bb_action_export({"format": "json", "include_resolved": "true"}, store, phase, policy))
    assert json.loads(exported["content"])["entries"]
    markdown = _ok(server._bb_action_export({"format": "markdown"}, store, phase, policy))
    assert "#" in markdown["content"]
    assert server._bb_action_export({"format": "xml"}, store, phase, policy)["error"] is True

    # The outer handler must translate the public `address` field, inject the
    # phase snapshot, and preserve a clean unsupported-action envelope.
    outer = _ok(server._handle_blackboard({"action": "list", "address": "0x140001000", "limit": 3}))
    assert "phase" not in outer or isinstance(outer["phase"], dict)
    bad = server._handle_blackboard({"action": "not-real"})
    assert bad["error"] is True


def test_blackboard_trace_crawler_and_invalid_inputs_are_safe(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()
    assert server._bb_action_write({}, store, phase, policy)["error"] is True
    assert server._bb_action_search({}, store, phase, policy)["error"] is True
    assert server._bb_action_read({"entry_id": "missing"}, store, phase, policy)["error"] is True
    assert server._bb_action_contradict({}, store, phase, policy)["error"] is True
    assert server._bb_action_add_evidence({}, store, phase, policy)["error"] is True
    assert server._bb_action_proposal_create({"proposal_type": "bad", "spec": {}}, store, phase, policy)["error"] is True
    assert server._bb_action_phase_set({"phase": "bad"}, store, phase, policy)["error"] is True
    assert server._bb_action_recall({"addr": "0x140001000"}, store, phase, policy)["ok"] is True

    orch = SimpleNamespace(
        start_crawler=lambda *args, **kwargs: True,
        stop_crawler=lambda: None,
        crawler_is_running=lambda: False,
        crawler_visited_count=lambda: 2,
        pending_proposal_rows=lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(server, "_orchestration", lambda: orch)
    assert _ok(server._bb_action_start_crawler({}, store, phase, policy))["running"] is True
    assert _ok(server._bb_action_stop_crawler({}, store, phase, policy))["running"] is False
    status = _ok(server._bb_action_crawler_status({}, store, phase, policy))
    assert status["addresses_visited"] == 2


def test_blackboard_memory_compile_composes_lanes_proposals_and_quests(tmp_path):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()

    store.write(
        "Verified parser fact",
        "checks the packet length",
        category="fact",
        addr="0x140001000",
        confidence=0.92,
    )
    store.write(
        "Open parser hypothesis",
        "length is attacker controlled",
        category="hypothesis",
        addr="0x140001010",
        confidence=0.55,
    )
    store.write(
        "Dead parser lead",
        "the branch is unreachable",
        category="dead_end",
        addr="0x140001020",
        confidence=0.8,
    )
    contradicted = store.write(
        "Contradicted lead",
        "an old interpretation",
        category="fact",
        addr="0x140001030",
        confidence=0.9,
    )
    assert store.contradict(contradicted, "runtime disproved it") is True
    store.write(
        "Completed quest",
        "parser review",
        category="quest_log",
        tags=["status:completed"],
    )
    store.write(
        "Failed quest",
        "dead branch review",
        category="quest_log",
        tags=["status:failed"],
    )
    proposal = _ok(server._bb_action_proposal_create({
        "proposal_type": "rename",
        "title": "Name parser",
        "spec": {"renames": [{"addr": "0x140001000", "name": "parse_packet"}]},
    }, store, phase, policy))
    store.write(
        "Ignored non-rename proposal",
        "{}",
        category="proposal",
        status="proposed",
    )

    notes = tmp_path / "cache" / "compiled.md"
    compiled = _ok(server._bb_action_memory_compile({
        "limit": 10,
        "notes_path": str(notes),
    }, store, phase, policy))

    assert len(compiled["facts"]) == 1
    assert "Verified parser fact" in compiled["facts"][0]["summary"]
    assert len(compiled["open_hypotheses"]) == 1
    assert "Open parser hypothesis" in compiled["open_hypotheses"][0]["summary"]
    assert len(compiled["dead_ends"]) == 2
    dead_summaries = " ".join(row["summary"] for row in compiled["dead_ends"])
    assert "Dead parser lead" in dead_summaries
    assert "Contradicted lead" in dead_summaries
    assert compiled["rename_batch"] == [{
        "proposal_id": proposal["proposal_id"],
        "title": "Name parser",
        "spec": [{"addr": "0x140001000", "name": "parse_packet"}],
    }]
    assert compiled["quest_metrics"] == {
        "total": 2,
        "completed": 1,
        "failed": 1,
        "completion_rate": 0.5,
    }
    assert compiled["phase_quality"]["contradictions"] == 1
    assert compiled["notes_path"] == str(notes)
    assert "Verified parser fact" in notes.read_text(encoding="utf-8")


def test_blackboard_file_actions_reject_traversal_and_symlink_components(tmp_path, monkeypatch):
    server = _server(tmp_path)
    allowed = tmp_path / "sandbox"
    allowed.mkdir()
    monkeypatch.setenv("IDA_MCP_BLACKBOARD_ROOT", str(allowed))
    assert server._bb_path_root() == str(allowed.resolve())
    resolved, error = server._bb_confine_path("report.md")
    assert resolved == str(allowed / "report.md")
    assert error is None

    inside = allowed / "real"
    inside.mkdir()
    link = allowed / "link"
    link.symlink_to(inside, target_is_directory=True)
    escaped, symlink_error = server._bb_confine_path("link/report.md")
    assert escaped == ""
    assert symlink_error["error"] is True
    assert "symbolic links" in symlink_error["message"]

    traversed, traversal_error = server._bb_confine_path("../outside/report.md")
    assert traversed == ""
    assert traversal_error["error"] is True
    assert "escapes allowed root" in traversal_error["message"]
