"""Exercise remaining blackboard host boundaries without an IDA runtime."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_blackboard as module
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin


class _Store:
    def __init__(self, entries=None, *, stats=None, targets=None):
        self.entries = list(entries or [])
        self._stats = dict(stats or {})
        self.targets_rows = list(targets or [])
        self.writes = []
        self.updates = []

    def list(self, **kwargs):
        rows = list(self.entries)
        if kwargs.get("category"):
            rows = [row for row in rows if row.get("category") == kwargs["category"]]
        return rows[: kwargs.get("limit", len(rows))]

    def read(self, entry_id):
        return next((row for row in self.entries if row.get("id") == entry_id), None)

    def write(self, **kwargs):
        entry_id = f"new-{len(self.writes) + 1}"
        row = {"id": entry_id, **kwargs}
        self.writes.append(row)
        self.entries.append(row)
        return entry_id

    def update(self, entry_id, **kwargs):
        row = self.read(entry_id)
        if row is None:
            return False
        row.update(kwargs)
        self.updates.append((entry_id, kwargs))
        return True

    def transition(self, entry_id, **kwargs):
        row = self.read(entry_id)
        if row is None:
            return None
        row.update(kwargs)
        return row

    def next_target(self, **_kwargs):
        return list(self.targets_rows)

    def stats(self):
        return dict(self._stats)

    def semantic_search(self, **_kwargs):
        return []


def _server(tmp_path: Path) -> ServerBlackboardMixin:
    server = object.__new__(ServerBlackboardMixin)
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    server._blackboard_policy_state = {}
    server._blackboard_phase_state = {
        "phase": "scout",
        "auto_transition": True,
        "recent_actions": [],
        "seen_addrs": [],
    }
    return server


def _phase():
    return {"phase": "scout", "recent_actions": [], "seen_addrs": []}


def test_session_path_resolution_and_filesystem_root_fallbacks(tmp_path, monkeypatch):
    server = _server(tmp_path)
    server.current_session = SimpleNamespace(session_id="CURRENT", idb_path="", binary_path="")
    server.session_mgr.get_session = lambda _sid: (_ for _ in ()).throw(RuntimeError("gone"))
    assert server._session_blackboard_path(sid="OTHER").endswith("OTHER.blackboard.db")
    assert server._session_blackboard_path(sid="current").endswith("current.blackboard.db")

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"binary")
    session = SimpleNamespace(binary_path=str(binary), idb_path=str(tmp_path / "sample.i64"), session_id="S")
    server.current_session = session
    monkeypatch.setattr(module.os, "stat", lambda _path: (_ for _ in ()).throw(OSError("raced")))
    monkeypatch.setattr(server, "_binary_sha256", lambda _path: "")
    assert server._session_blackboard_path(session_obj=session).endswith("sample.i64.blackboard.db")

    server.current_session = None
    server.cache_dir = ""
    assert server._bb_path_root() is None
    assert server._bb_confine_path("file.md")[1]["code"] == MCPError.INVALID_ARGS

    server._bb_path_root = lambda: str(tmp_path)
    monkeypatch.setattr(module.os.path, "commonpath", lambda _paths: (_ for _ in ()).throw(ValueError("drives")))
    assert server._bb_confine_path("file.md")[1]["error"] is True

    monkeypatch.setattr(module.os.path, "relpath", lambda *_args: (_ for _ in ()).throw(ValueError("drives")))
    assert ServerBlackboardMixin._bb_path_has_symlink(str(tmp_path / "a"), str(tmp_path)) is True


def test_dispatch_gate_workspace_seed_and_evidence_failure_modes(tmp_path, monkeypatch):
    server = _server(tmp_path)
    phase = {"phase": "commit", "recent_actions": [], "seen_addrs": []}
    policy = {"strict_mode": True, "enforce_phases": ["commit"], "policy_markers": []}
    block = {"error": True, "code": MCPError.POLICY_DENIED}
    monkeypatch.setattr(server, "_phase_log_action", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_phase_auto_transition", lambda *_args: None)
    monkeypatch.setattr(server, "_phase_contract_check", lambda *_args: block)
    assert server._bb_dispatch_gate("write", {}, object(), phase, policy) is block

    transitions = []
    monkeypatch.setattr(server, "_phase_contract_check", lambda *_args: None)
    monkeypatch.setattr(server, "_phase_find_loop", lambda _state: True)
    monkeypatch.setattr(server, "_phase_transition", lambda *_args: transitions.append(_args))
    monkeypatch.setattr(server, "_bb_policy_enforced_for_phase", lambda *_args: True)
    monkeypatch.setattr(server, "_bb_policy_check", lambda _state: {"ok": False})
    denied = server._bb_dispatch_gate("proposal_accept", {}, object(), phase, policy)
    assert denied["error"] is True and transitions

    workspace = tmp_path / "workspace.db"
    workspace.write_bytes(b"not sqlite")
    server._seed_shared_workspace(str(workspace), "digest", "")
    monkeypatch.setattr(module.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("missing")))
    server._seed_shared_workspace(str(tmp_path / "new.db"), "digest", "")

    store = _Store()
    server._execute_tool = lambda *_args: (_ for _ in ()).throw(RuntimeError("probe"))
    monkeypatch.setattr(module.time, "monotonic", iter([0.0, 0.0, 3.0]).__next__)
    monkeypatch.setenv("IDA_MCP_EMBED_DISABLED", "1")
    snapshot = server._evidence_gravity(store, "entry", "0x1000")
    assert snapshot["ok"] is True
    assert snapshot["items"][0]["ok"] is False

    store.semantic_search = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("embedding"))
    monkeypatch.setattr(module.time, "monotonic", lambda: 0.0)
    monkeypatch.delenv("IDA_MCP_EMBED_DISABLED")
    assert server._evidence_gravity(store, "entry-2", "0x2000")["ok"] is True


def test_memory_compile_lanes_and_proposal_status_boundaries(tmp_path):
    server = _server(tmp_path)
    entries = [
        {"id": "fact", "title": "fact", "content": "yes", "category": "fact", "confidence": 0.8},
        {"id": "open", "title": "open", "content": "maybe", "category": "hypothesis", "confidence": 0.3, "resolved": False},
        {"id": "dead", "title": "dead", "content": "no", "category": "dead_end", "confidence": 0.2},
    ]
    entries.extend([
        {"id": "bad-proposal", "title": "bad", "category": "proposal", "content": "not-json"},
        {"id": "rename", "title": "rename", "category": "proposal", "content": json.dumps({"proposal_type": "rename", "spec": {"renames": []}})},
        {"id": "q1", "title": "done", "category": "quest_log", "tags": ["status:completed"]},
        {"id": "q2", "title": "failed", "category": "quest_log", "tags": ["status:failed"]},
    ])
    store = _Store(entries, stats={"contradicted": 2}, targets=[{"addr": "0x1", "title": "frontier"}])
    server._proposal_entries = lambda _store, **_kwargs: [entries[3], entries[4]]
    server._bb_path_root = lambda: str(tmp_path)
    compiled = server._memory_compile(store, limit=5)
    assert compiled["quest_metrics"] == {"total": 2, "completed": 1, "failed": 1, "completion_rate": 0.5}
    assert compiled["facts"] and compiled["open_hypotheses"] and compiled["dead_ends"]

    notes_dir = tmp_path / "notes-dir"
    notes_dir.mkdir()
    failed = server._memory_compile(store, limit=5, notes_path="notes-dir")
    assert failed["notes_path"] is None

    assert server._lane_fetch(store, "lane_queue", 5)[0]["category"] == "frontier"
    server._verified_proposal_addrs = lambda _store: {"0x1"}
    queue = server._lane_fetch(store, "lane_queue", 5)
    assert queue[0]["priority_score"] == 0.2

    health = server._state_health(_Store(stats={
        "total_entries": 3,
        "unresolved": 2,
        "contradicted": 5,
        "avg_confidence": 0.2,
        "by_category": {"hypothesis": 1},
    }))
    assert health["state_health"] < 60

    assert server._validate_rename_spec(None)
    assert server._validate_patch_spec(None)
    assert server._validate_proposal_spec("type", {})
    assert server._proposal_status({"content": "not-json", "tags": []}) == "proposed"


def test_proposal_and_crud_handlers_return_actionable_errors(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = _Store([
        {"id": "bad", "category": "proposal", "content": "not-json", "tags": "bad"},
        {"id": "p", "category": "proposal", "content": json.dumps({"proposal_type": "rename", "spec": {"renames": [{"addr": "0x1", "name": "fn"}]}}), "tags": []},
    ])
    phase = _phase()
    policy = {}
    for args in ({}, {"proposal_id": "missing"}, {"proposal_id": "bad"}):
        assert server._bb_action_proposal_accept(args, store, phase, policy)["error"] is True
    assert server._bb_action_proposal_reject({}, store, phase, policy)["error"] is True
    assert server._bb_action_proposal_reject({"proposal_id": "missing"}, store, phase, policy)["error"] is True

    class TransitionStore(_Store):
        def transition(self, *_args, **_kwargs):
            raise ValueError("bad status")

    transition = TransitionStore([{"id": "e"}])
    assert server._bb_action_update({"entry_id": "e", "status": "bad"}, transition, phase, policy)["error"] is True
    assert server._bb_action_update({"entry_id": "missing", "status": "resolved"}, transition, phase, policy)["error"] is True
    assert server._bb_action_update({"entry_id": "e", "status": "resolved"}, _Store(), phase, policy)["error"] is True

    assert server._bb_action_proposal_create({"proposal_type": "rename", "spec": []}, store, phase, policy)["error"] is True
    assert server._bb_action_proposal_create({"proposal_type": "rename", "spec": {"renames": [{"addr": "0x1", "name": "fn"}]}}, store, phase, policy)["ok"] is True

    monkeypatch.setattr(server, "_proposal_verify", lambda *_args: {"ok": False, "problems": ["blocked"], "checks": []})
    result = server._bb_action_proposal_accept({"proposal_id": "p"}, store, phase, policy)
    assert result["status"] == "failed"


def test_export_notes_and_runtime_action_edge_envelopes(tmp_path, monkeypatch):
    server = _server(tmp_path)
    server._bb_path_root = lambda: str(tmp_path)
    store = _Store()
    assert server._bb_action_export({"format": "xml"}, store, _phase(), {})["error"] is True
    assert server._bb_action_notes_import({"path": "missing.md"}, store, _phase(), {})["error"] is True
    assert server._bb_action_read({"entry_id": "missing"}, store, _phase(), {})["error"] is True
    assert server._bb_action_list({"min_confidence": 0.2}, store, _phase(), {})["ok"] is True

    store.targets = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("strategy"))
    assert server._bb_action_frontier({}, store, _phase(), {})["error"] is True
    assert server._bb_action_next_target({"strategy": "coverage"}, store, _phase(), {})["error"] is True

    assert server._bb_action_contradict({}, store, _phase(), {})["error"] is True
    assert server._bb_action_resolve({}, store, _phase(), {})["error"] is True
    assert server._bb_action_add_evidence({}, store, _phase(), {})["error"] is True
    assert server._bb_action_calibrate({}, store, _phase(), {})["error"] is True
