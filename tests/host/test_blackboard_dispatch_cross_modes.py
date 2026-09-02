"""Cross-mode behavior tests for the host blackboard dispatcher.

These tests deliberately combine the dispatcher, phase state, the durable
store, and the file/runtime adapters.  The blackboard is a state machine, so
testing each action in isolation misses the failures that matter most to an
analyst moving from an observation to evidence, a proposal, and a report.
"""

from __future__ import annotations

import json

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_blackboard as module
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin, _coerce_str_list
from tests.host.test_swarm_blackboard_modes_matrix import _server


def _parts(result: dict) -> dict:
    assert result.get("ok") is True, result
    return result


def test_dispatch_governance_and_failure_envelopes_cross_modes(tmp_path, monkeypatch):
    server = _server(tmp_path)

    assert _coerce_str_list([" a ", "", 3]) == ["a", "3"]
    assert _coerce_str_list(" a | | b ") == ["a", "b"]
    assert _coerce_str_list(None) == []

    # Policy actions do not need a store.  A store failure is still exposed
    # with its diagnostic when a normal action does need one.
    assert _parts(server._handle_blackboard({"action": "phase_status"}))["phase"]
    monkeypatch.setattr(server, "_get_blackboard_store", lambda: None)
    server._blackboard_store_error = "database is locked"
    failed = server._handle_blackboard({"action": "list"})
    assert failed["error"] is True
    assert failed["code"] == MCPError.DB_ERROR
    assert "database is locked" in failed["message"]

    # Bad input is normalized at the outer boundary rather than escaping as
    # an internal exception.
    malformed = server._handle_blackboard(None)
    assert malformed["error"] is True
    assert malformed["code"] == MCPError.INVALID_ARGS

    second = tmp_path / "second"
    second.mkdir()
    server = _server(second)
    unknown = server._handle_blackboard({"action": "not-a-blackboard-action"})
    assert unknown["error"] is True
    assert unknown["code"] == MCPError.ACTION_NOT_FOUND

    # The dispatch wrapper preserves scalar handler results for extension
    # actions, and adds the phase snapshot only to the documented actions.
    module._BLACKBOARD_ACTIONS["test_scalar"] = "_test_scalar_handler"
    try:
        server._test_scalar_handler = lambda *_args: "scalar-result"
        scalar = server._handle_blackboard({"action": "test_scalar"})
        assert scalar == {"ok": True, "result": "scalar-result"}
    finally:
        module._BLACKBOARD_ACTIONS.pop("test_scalar", None)


def test_evidence_gravity_runtime_embedding_and_no_runtime_modes(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = server._get_blackboard_store()

    assert server._evidence_gravity(store, "entry", "") == {
        "ok": False,
        "reason": "no_addr_or_runtime",
    }
    del server._execute_tool
    assert server._evidence_gravity(store, "entry", "0x1000")["reason"] == "no_addr_or_runtime"

    calls = []
    server._execute_tool = lambda tool, args: calls.append((tool, args)) or (
        {"error": True, "message": "probe unavailable"} if tool == "code" else {"items": [tool]}
    )
    store.semantic_search = lambda **_kwargs: [
        {"id": "near", "addr": "0x1010", "title": "nearby", "category": "fact", "confidence": 0.8},
        {"id": "extra", "addr": "0x1020", "title": "extra", "category": "fact", "confidence": 0.7},
    ]
    snapshot = server._evidence_gravity(store, "entry", "0x1000", "length check")
    assert snapshot["ok"] is True
    assert len(snapshot["items"]) == 5
    assert any(item["tool"] == "semantic" for item in snapshot["items"])
    assert len(calls) == 3

    monkeypatch.setenv("IDA_MCP_EMBED_DISABLED", "1")
    no_embed = server._evidence_gravity(store, "entry-2", "0x2000")
    assert all(item["tool"] != "semantic" for item in no_embed["items"])
    assert server._orchestration().machinery_get(store, module.NS_GRAVITY, "entry")
    server._orchestration().shutdown()


def test_proposal_lifecycle_success_failure_and_validation_modes(tmp_path):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()

    assert server._bb_action_proposal_create({"proposal_type": "rename", "spec": "{bad"}, store, phase, policy)["error"]
    assert server._bb_action_proposal_create({"proposal_type": "rename", "spec": {"renames": []}}, store, phase, policy)["error"]

    proposal = _parts(server._bb_action_proposal_create({
        "type": "rename",
        "spec": {"renames": [{"addr": "0x1000", "name": "parse_packet"}]},
    }, store, phase, policy))
    server._symbol_at = lambda _addr: "sub_1000"
    server._execute_tool = lambda _tool, _args: {"ok": True}
    accepted = _parts(server._bb_action_proposal_accept({"proposal_id": proposal["proposal_id"]}, store, phase, policy))
    assert accepted["status"] == "verified"
    assert store.read(proposal["proposal_id"])["status"] == "verified"

    patch = _parts(server._bb_action_proposal_create({
        "proposal_type": "patch",
        "spec": {"patches": [{"addr": "0x1000", "bytes": "90"}]},
    }, store, phase, policy))
    failed = server._bb_action_proposal_accept({"proposal_id": patch["proposal_id"]}, store, phase, policy)
    assert failed["ok"] is False
    assert failed["status"] == "failed"

    malformed = store.write(
        title="broken proposal", content="not-json", category="proposal", status="proposed"
    )
    assert server._bb_action_proposal_accept({"proposal_id": malformed}, store, phase, policy)["error"]
    assert server._bb_action_proposal_accept({"proposal_id": "missing"}, store, phase, policy)["error"]
    assert server._bb_action_proposal_reject({}, store, phase, policy)["error"]


def test_notes_import_compile_and_phase_transitions_share_workspace(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()
    notes = tmp_path / "cache" / "analyst.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text(
        "# Notes\n- inspect 0x1000\nnot a bullet\n- (none)\n- inspect 0x1000\n- confirm parser\n",
        encoding="utf-8",
    )
    tasks = []
    monkeypatch.setattr(
        server,
        "_maybe_auto_trace_from_text",
        lambda *_args, **_kwargs: tasks.append("trace-1") or "trace-1",
    )
    imported = _parts(server._bb_action_notes_import({
        "notes_path": str(notes), "lane": "lane_facts", "auto_trace": True,
    }, store, phase, policy))
    assert imported["imported"] == 2
    assert imported["trace_tasks_created"] == 2
    assert imported["lane"] == "lane_facts"

    compiled_path = tmp_path / "cache" / "compiled.md"
    compiled = _parts(server._bb_action_memory_compile({
        "limit": 5, "path": str(compiled_path),
    }, store, phase, policy))
    assert compiled["notes_path"] == str(compiled_path)
    assert "Memory Compiler Snapshot" in compiled_path.read_text(encoding="utf-8")

    # The full action path translates the public address alias and persists
    # phase state in the same workspace that contains the imported notes.
    _parts(server._handle_blackboard({"action": "write", "name": "address observation", "address": "0x1000"}))
    listed = _parts(server._handle_blackboard({"action": "list", "address": "0x1000"}))
    assert listed["count"] >= 1
    assert _parts(server._handle_blackboard({"action": "phase_set", "phase": "commit"}))["phase"]["phase"] == "commit"
    read = server._handle_blackboard({"action": "read", "entry_id": listed["entries"][0]["id"]})
    assert read["entry"]["id"] == listed["entries"][0]["id"]


def test_shutdown_and_store_loader_failures_are_defensive(tmp_path, monkeypatch):
    server = _server(tmp_path)
    class Orchestrator:
        def shutdown(self):
            raise RuntimeError("worker already gone")

    server._bb_orchestrator = Orchestrator()
    ServerBlackboardMixin.shutdown(server)

    # A loader failure is retained for the outer handler's actionable DB
    # error, while a subsequent successful load clears it.
    class BrokenModule:
        class BlackboardStore:
            def __init__(self, **_kwargs):
                raise OSError("cannot open workspace")

    monkeypatch.setattr(ServerBlackboardMixin, "_blackboard_module", BrokenModule, raising=False)
    assert server._get_blackboard_store() is None
    assert "cannot open workspace" in server._blackboard_store_error

    class GoodModule:
        BlackboardStore = type("Store", (), {"__init__": lambda self, **_kwargs: None})

    monkeypatch.setattr(ServerBlackboardMixin, "_blackboard_module", GoodModule, raising=False)
    assert server._get_blackboard_store() is not None
    assert server._blackboard_store_error is None
