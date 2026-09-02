"""Boundary coverage for blackboard persistence, proposals, and file safety."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_blackboard as blackboard_mod
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from tests.host.test_swarm_blackboard_modes_matrix import _server


class Store:
    def __init__(self, entries=None, stats=None):
        self.entries = entries or []
        self._stats = stats or {}
        self.updates = []

    def read(self, entry_id):
        return next((entry for entry in self.entries if entry.get("id") == entry_id), None)

    def update(self, entry_id, **updates):
        entry = self.read(entry_id)
        if entry is None:
            return False
        entry.update(updates)
        self.updates.append((entry_id, updates))
        return True

    def list(self, **_kwargs):
        return list(self.entries)

    def stats(self):
        return dict(self._stats)

    def next_target(self, **_kwargs):
        return [
            {
                "entry_id": "q1",
                "addr": "0x1000",
                "title": "queue target",
                "summary": "inspect",
                "priority_score": 0.5,
                "confidence": 0.4,
            }
        ]


def test_blackboard_path_security_and_workspace_migration_edges(tmp_path, monkeypatch):
    server = _server(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"same binary")
    server.current_session.binary_path = str(binary)
    server.current_session.idb_path = str(tmp_path / "sample.i64")
    path = server._session_blackboard_path()
    assert path.endswith(".db") and "sha256-" in path
    assert server._session_blackboard_path(sid="SID-BB01") == path

    server.current_session.binary_path = str(tmp_path / "missing.bin")
    assert server._session_blackboard_path().endswith("sample.i64.blackboard.db")
    server.current_session.idb_path = ""
    assert server._session_blackboard_path(sid="SID-OTHER").endswith("SID-OTHER.blackboard.db")
    server.current_session = None
    assert server._session_blackboard_path() == ""

    assert server._binary_sha256(str(binary))
    assert server._binary_sha256(str(tmp_path / "nope")) == ""
    monkeypatch.setattr(blackboard_mod.hashlib, "sha256", lambda: (_ for _ in ()).throw(OSError("hash")))
    assert server._binary_sha256(str(binary)) == ""

    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    with sqlite3.connect(source) as conn:
        conn.execute("create table findings (id text primary key, title text)")
        conn.execute("insert into findings values ('one', 'first')")
        conn.commit()
    with sqlite3.connect(target) as conn:
        conn.execute("create table findings (id text primary key, title text)")
        conn.commit()
    ServerBlackboardMixin._merge_workspace_rows(str(source), str(target))
    with sqlite3.connect(target) as conn:
        assert conn.execute("select title from findings").fetchone() == ("first",)
    ServerBlackboardMixin._merge_workspace_rows(str(tmp_path / "missing"), str(target))
    server._seed_shared_workspace(str(tmp_path / "new.db"), "missing-digest", str(server.current_session or ""))

    monkeypatch.setenv("IDA_MCP_BLACKBOARD_ROOT", str(tmp_path))
    assert server._bb_path_root() == str(tmp_path.resolve())
    assert server._bb_confine_path("notes.md")[0] == str((tmp_path / "notes.md").resolve())
    assert server._bb_confine_path("")[1]["error"] is True
    assert server._bb_confine_path("../outside")[1]["error"] is True
    link = tmp_path / "link"
    (tmp_path / "real").mkdir()
    link.symlink_to(tmp_path / "real", target_is_directory=True)
    assert server._bb_confine_path("link/file")[1]["error"] is True
    assert ServerBlackboardMixin._bb_path_has_symlink("", str(tmp_path)) is True


def test_proposal_verification_execution_and_health_modes(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = Store([
        {"id": "p1", "addr": "0x1000", "tags": ["status:verified"], "content": json.dumps({
            "spec": {"renames": [{"addr": "0x1000", "name": "entry"}], "patches": [{"addr": "0x2000"}], "types": [{"addr": "0x3000"}]},
        })},
        {"id": "p2", "addr": "0x2000", "tags": "bad", "content": "{bad"},
    ])
    assert server._verified_proposal_addrs(store) == {"0x1000", "0x2000", "0x3000"}
    assert server._proposal_name_candidate("123 parser / main") == "_123_parser___main"
    assert server._proposal_name_candidate("!!!") == "sub_candidate"
    assert server._validate_rename_spec({"renames": [{"addr": "", "name": "x"}]})
    assert server._validate_rename_spec({"renames": [None]})
    assert server._validate_patch_spec({"patches": [{"addr": "0x1", "asm": ""}]})
    assert server._validate_patch_spec({"patches": [None]})
    assert server._validate_proposal_spec("type", {"types": []})
    assert server._validate_proposal_spec("other", {}) is None

    server._symbol_at = lambda addr: "user_name" if addr == "0x1" else "sub_2"
    blocked = server._proposal_verify("rename", {"renames": [{"addr": "0x1", "name": "new"}, {"addr": "0x2", "name": "new2"}]})
    assert blocked["ok"] is False
    assert server._proposal_verify("patch", {"patches": []})["ok"] is True
    server._execute_tool = lambda _tool, args: {"ok": args.get("name") == "good"}
    assert server._proposal_execute("rename", {"renames": [{"addr": "0x1", "name": "good"}, {}, {"addr": "0x2", "name": "bad"}]})["applied"] == 1
    assert server._proposal_execute("patch", {"patches": []})["ok"] is False
    del server._execute_tool
    assert server._proposal_execute("rename", {"renames": []})["note"]

    entry = {"id": "p3", "tags": ["status:proposed", "keep"], "content": "{bad"}
    store.entries.append(entry)
    assert server._apply_lifecycle_status(store, "p3", "verified", "checked")["status"] == "verified"
    assert server._apply_lifecycle_status(store, "missing", "failed") is None
    assert server._proposal_status({"content": "{bad", "tags": ["status:rejected"]}) == "rejected"
    assert server._proposal_status({"content": "{}", "tags": ["status:custom"]}) == "custom"
    assert server._proposal_status_replace(["status:old", "x"], "new") == ["x", "status:new"]

    for stats, expected in (
        ({}, "Write a `lane_now`"),
        ({"total_entries": 2, "unresolved": 1, "by_category": {"wm_now": 1}, "avg_confidence": 0.8}, "Promote one"),
        ({"total_entries": 4, "unresolved": 1, "by_category": {"wm_now": 1, "fact": 1}, "avg_confidence": 0.2}, "Calibrate"),
        ({"total_entries": 5, "unresolved": 1, "by_category": {"wm_now": 1, "fact": 1, "dead_end": 1}, "avg_confidence": 0.8}, "Run `working_set`"),
    ):
        health = server._state_health(Store(stats=stats))
        assert health["recommended_action"].startswith(expected)


def test_blackboard_action_boundaries_and_cross_session_roundtrip(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    phase = server._phase_state()
    policy = server._bb_policy_state()
    entry = server._bb_action_write({"name": "state", "category": "hypothesis", "addr": "0x1000"}, store, phase, policy)
    eid = entry["entry_id"]
    updated = server._bb_action_update({"entry_id": eid, "status": "resolved", "reason": "confirmed", "priority": 0.9}, store, phase, policy)
    assert updated["ok"] is True
    assert server._bb_action_update({"entry_id": eid}, store, phase, policy)["error"] is True
    assert server._bb_action_add_evidence({"entry_id": "missing", "type": "x", "value": "y"}, store, phase, policy)["error"] is True
    assert server._bb_action_calibrate({"entry_id": "missing"}, store, phase, policy)["error"] is True
    assert server._bb_action_contradict({"entry_id": "missing", "reason": "x"}, store, phase, policy)["error"] is True
    assert server._bb_action_resolve({"entry_id": "missing"}, store, phase, policy)["error"] is True
    assert server._bb_action_next_target({"strategy": "not-a-strategy"}, store, phase, policy)["error"] is True
    assert server._bb_action_delete({"entry_id": "missing"}, store, phase, policy)["ok"] is False

    class SymbolStore:
        def __init__(self, **_kwargs):
            self.rows = []

        def upsert_hypothesis(self, **kwargs):
            self.rows.append(kwargs)
            return "row-1"

        def query_hypotheses(self, **_kwargs):
            return [
                {"hypothesis_text": "at 0x1004", "addr_offset": 4, "confidence": 0.9, "source_session": "old"},
                {"hypothesis_text": "", "addr_offset": 8},
            ]

    monkeypatch.setattr(blackboard_mod, "SymbolDB", SymbolStore)
    server.session_mgr.get_high_confidence_hypotheses = lambda *_args, **_kwargs: [
        {"statement": "parser at 0x80000010", "confidence": 0.9},
        {"statement": "no address", "confidence": 0.9},
    ]
    sess = SimpleNamespace(binary_path=str(tmp_path / "sample.bin"), idb_path=str(tmp_path / "sample.i64"), analysis_options={"baseaddr": "0x80000000", "chip_family": "arm"})
    assert server._export_session_hypotheses_to_symbol_db("SID-BB01", sess) == 1
    blackboard_mod.ServerBlackboardMixin._blackboard_module = None
    assert server._import_cross_session_hypotheses(sess) == 1
