from __future__ import annotations

import threading
from types import SimpleNamespace

from ida_pro_mcp.host.intelligence import advisory
from ida_pro_mcp.host.intelligence.core import _extract_signature
from ida_pro_mcp.host.server.blackboard_orchestration import (
    NS_GRAVITY,
    BlackboardOrchestrator,
)
from tests.host.test_swarm_blackboard_modes_matrix import _server


def test_blackboard_writes_refresh_advisory_in_background(tmp_path, monkeypatch):
    server = _server(tmp_path)
    started = threading.Event()
    release = threading.Event()
    seen = []

    def fake_organize(_state, findings, xrefs, relations, **_kwargs):
        seen.append((findings, xrefs, relations))
        if len(seen) == 1:
            started.set()
            assert release.wait(5)
        return {
            "ok": True,
            "source": "provider_advisory",
            "organization": [],
            "xrefs": [],
            "relations": [],
            "evidence": {
                "signatures_seen": [],
                "budget_burn": {},
                "confidence": None,
                "fail_closed_order": [],
                "applied": False,
                "disagreement": False,
            },
        }

    monkeypatch.setattr(advisory, "organize_blackboard", fake_organize)
    first = server._handle_blackboard(
        {
            "action": "write",
            "name": "Network parser",
            "notes": "RAW_DECOMP secret_token",
            "category": "general",
            "addr": "0x1000",
            "tags": "network|parser",
            "evidence": [{"type": "xref", "value": "0x1010"}],
        }
    )
    assert first["ok"] is True
    assert started.wait(2)

    second = server._handle_blackboard(
        {
            "action": "write",
            "name": "Network parser checksum",
            "notes": "second private body",
            "category": "hypothesis",
            "addr": "0x1020",
            "tags": "network|checksum",
        }
    )
    assert second["ok"] is True
    release.set()

    orchestrator = server._orchestration()
    orchestrator.drain(timeout=5)
    store = server._get_blackboard_store()
    result = server._bb_action_workspace_brief({}, store, server._phase_state(), server._bb_policy_state())

    snapshot = result["blackboard_advisory"]
    assert snapshot["status"] == "ready"
    assert snapshot["candidate_counts"]["findings"] == 2
    assert snapshot["candidate_counts"]["xrefs"] >= 1
    assert snapshot["candidate_counts"]["relations"] >= 1
    assert snapshot["evidence"]["applied"] is False
    assert len(seen) >= 2
    assert all(
        "RAW_DECOMP" not in str(group)
        and "secret_token" not in str(group)
        and "second private body" not in str(group)
        for batch in seen
        for group in batch
    )

    assert store.read(first["entry_id"])["content"] == "RAW_DECOMP secret_token"
    server.shutdown()


def test_advisory_uses_only_observed_graph_edges_and_candidate_relations(tmp_path):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    entry_id = store.write(
        title="Network parser",
        content="raw body is not considered by the advisor",
        category="general",
        addr="0x1000",
        evidence=[{"type": "xref", "value": "edge to 0x1010"}],
    )
    entry = store.read(entry_id)
    orchestrator = server._orchestration()
    orchestrator.machinery_set(
        store,
        NS_GRAVITY,
        entry_id,
        {
            "items": [
                None,
                {"tool": "graph", "result": "not a graph"},
                {
                    "tool": "graph",
                    "result": {
                        "nodes": [
                            None,
                            {"addr": "bad", "name": "invalid"},
                            {"addr": "0x1000", "name": "parse_packet"},
                            {"addr": "0x1010", "name": "decode_token"},
                        ],
                        "edges": [
                            None,
                            {"from": "bad", "to": "0x1000"},
                            {"from": "0x1000", "to": "0x1010"},
                        ],
                    },
                },
            ]
        },
    )
    xrefs = orchestrator._blackboard_xref_candidates(
        store,
        [None, entry, {"id": "no-address", "addr": "not-an-address"}],
        {entry_id: {"signature": "network parser"}},
        _extract_signature,
    )
    assert xrefs == [
        {
            "entry_id": entry_id,
            "from_address": "0x1000",
            "to_address": "0x1010",
            "direction": "callee",
            "from_signature": "parse packet",
            "to_signature": "decode token",
        }
    ]

    candidates = [
        {"entry_id": "duplicate", "signature": "network parser"},
        {"entry_id": "duplicate", "signature": "network parser"},
        *[
            {"entry_id": f"finding-{index}", "signature": "network parser"}
            for index in range(7)
        ],
    ]
    relations = orchestrator._blackboard_relation_candidates(
        candidates, {item["entry_id"]: set() for item in candidates}
    )
    assert len(relations) == 16
    assert all(item["relation"] == "shared_signature" for item in relations)
    assert orchestrator._blackboard_relation_candidates(
        [
            {"entry_id": "one", "address": "0x2000", "signature": "alpha"},
            {"entry_id": "two", "address": "0x2000", "signature": "beta"},
            {"entry_id": "three", "signature": "other"},
        ],
        {"one": set(), "two": set(), "three": set()},
    )[0]["relation"] == "same_address"
    server.shutdown()


def test_advisory_scheduler_and_worker_failures_are_reported_without_failing_writes(tmp_path, monkeypatch):
    server = _server(tmp_path)
    store = server._get_blackboard_store()
    orchestrator = BlackboardOrchestrator(server, max_workers=1)
    assert orchestrator.enqueue_blackboard_advisory(SimpleNamespace(db_path="")) is False

    monkeypatch.setattr(orchestrator._pool, "submit", lambda *_args: False)
    assert orchestrator.enqueue_blackboard_advisory(store) is False
    assert orchestrator.blackboard_advisory(store)["status"] == "unavailable"

    path = store.db_path
    monkeypatch.setattr(orchestrator, "_open_store", lambda _path: None)
    orchestrator._run_blackboard_advisory(path, "sid")
    assert orchestrator.blackboard_advisory(store)["reason"] == "blackboard store is unavailable"

    monkeypatch.setattr(orchestrator, "_open_store", lambda _path: store)
    build_blackboard_advisory = orchestrator._build_blackboard_advisory
    monkeypatch.setattr(
        orchestrator,
        "_build_blackboard_advisory",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("private failure")),
    )
    orchestrator._run_blackboard_advisory(path, "sid")
    assert orchestrator.blackboard_advisory(store)["reason"] == "blackboard advisory could not be computed"
    monkeypatch.setattr(orchestrator, "_build_blackboard_advisory", build_blackboard_advisory)

    class BrokenList:
        db_path = store.db_path

        @staticmethod
        def list(**_kwargs):
            raise RuntimeError("private store failure")

    unreadable = orchestrator._build_blackboard_advisory(BrokenList(), "sid")
    assert unreadable["status"] == "unavailable"
    orchestrator.shutdown()


def test_blackboard_write_succeeds_when_advisory_scheduling_raises(tmp_path, monkeypatch):
    server = _server(tmp_path)

    def fail_schedule():
        raise RuntimeError("advisory pool unavailable")

    monkeypatch.setattr(server, "_orchestration", fail_schedule)
    result = server._handle_blackboard(
        {"action": "write", "name": "Stored finding", "notes": "persistent content"}
    )
    assert result["ok"] is True
    assert server._get_blackboard_store().read(result["entry_id"])["content"] == "persistent content"
