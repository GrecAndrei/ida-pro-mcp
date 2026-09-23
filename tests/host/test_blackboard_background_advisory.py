from __future__ import annotations

import threading

from ida_pro_mcp.host.intelligence import advisory
from ida_pro_mcp.host.server.blackboard_orchestration import NS_GRAVITY
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
