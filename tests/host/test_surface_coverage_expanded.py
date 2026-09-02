"""Additional stable-interface coverage for the host investigation surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.session import SessionManager
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore, marker_for


def test_blackboard_store_anchor_examination_and_recall_lifecycle(tmp_path: Path):
    store = BlackboardStore(str(tmp_path / "blackboard.db"))
    try:
        invalid = store.observe_code("", "decompile", text="return 0")
        assert invalid["ok"] is False
        invalid_kind = store.observe_code("0x401000", "unknown", text="return 0")
        assert invalid_kind["ok"] is False

        first_anchor = store.observe_code("0x401000", "decompile", text="return 1")
        assert first_anchor["changed"] is False
        entry_id = store.write(
            "Parser checks length",
            content="reads the packet header",
            category="analysis",
            addr="0x401000",
            confidence=0.9,
            tags=["parser"],
            evidence=[{"type": "xref", "value": "caller"}],
        )
        examined = store.record_examination(
            "0x401000", verdict="boring", note="temporary review", name="parser"
        )
        assert examined["created"] is True
        assert store.examination("0x401000")["verdict"] == "boring"
        updated_examined = store.record_examination(
            "0x401000", verdict="interesting", note="revisit needed"
        )
        assert updated_examined["created"] is False
        assert store.examination("0x401000")["verdict"] == "interesting"

        changed = store.observe_code("0x401000", "decompile", text="return 2")
        assert changed["changed"] is True
        assert changed["stale_marked"] >= 1
        assert store.stale_entries()
        assert store.clear_stale(entry_id) is True
        assert store.clear_stale("missing") is False

        assert store.adopt_annotation("0x401010", name="sub_401010") is None
        assert store.adopt_annotation("0x401010", comment=marker_for(entry_id)) is None
        adopted = store.adopt_annotation(
            "0x401010", name="parse_header", comment="known packet parser"
        )
        assert adopted and adopted["created"] is True

        recalled = store.recall(
            ["0x401000", "0x401000", "0x401010", "bad"], limit=10
        )
        assert recalled["addresses"] == ["0x401000", "0x401010", "bad"]
        assert recalled["counts"]["findings"] >= 1
        assert store.recall([], limit=2)["addresses"] == []
        assert store.recall_lines(["0x401000"], limit=4)
        assert store.comment_for(store.read(entry_id), max_len=80).startswith(
            "Parser checks length"
        )
    finally:
        store.close()


def test_blackboard_store_targets_transitions_and_maintenance(tmp_path: Path):
    store = BlackboardStore(str(tmp_path / "blackboard.db"))
    try:
        open_id = store.write(
            "Investigate parser",
            category="analysis",
            addr="0x401000",
            kind="question",
            depends_on="0x402000",
            confidence=0.4,
            priority=0.8,
        )
        confirmed_id = store.write(
            "Known entry",
            category="analysis",
            addr="0x402000",
            status="confirmed",
            confidence=0.95,
        )
        assert store.transition(open_id, "confirmed", content="verified")
        assert store.add_evidence(open_id, "runtime", "observed", weight=0.75)
        assert store.calibrate_confidence(open_id) == 0.75
        assert store.mark_published(open_id, "parser") is True
        assert store.publishable(include_published=True)
        assert store.mark_resolved(open_id) is True
        assert store.contradict(confirmed_id, "counter-evidence") is True
        assert store.conflicts()

        def rpc(tool, args):
            if args["action"] == "functions":
                return {
                    "functions": [
                        {"start_ea": 0x403000, "name": "sub_403000", "xref_count": 4},
                        {"addr": "0x404000", "name": "named", "xref_count": 1},
                    ]
                }
            return {"items": [{"address": "0x405000"}]}

        coverage = store.targets("coverage", limit=5, rpc_fn=rpc, query="calls")
        assert coverage["strategy"] == "coverage"
        assert coverage["targets"]
        assert store.targets("frontier", limit=5, rpc_fn=rpc)["strategy"] == "frontier"
        assert store.targets("stale", limit=5)["strategy"] == "stale"
        assert store.targets("conflict", limit=5)["strategy"] == "conflict"
        assert store.targets("unresolved", limit=5)["strategy"] == "unresolved"
        assert store.next_target(limit=5, rpc_fn=rpc, query="parser")
        assert store.targets("coverage", limit=2)["note"]
        with pytest.raises(ValueError):
            store.targets("not-a-strategy")

        brief = store.workspace_brief(limit=3)
        assert brief["counts"]["total"] >= 1
        assert "Next:" in brief["brief"]
        assert store.campaign_summary()["total_entries"] >= 1
        assert store.update(open_id, resolved=True, contradiction_reason="") is True
        assert store.exists_similar("0x401000", "analysis", "Investigate parser") is True

        duplicate_a = store.write("Same observation", category="misc", addr="0x406000")
        duplicate_b = store.write("Same observation now", category="misc", addr="0x406000")
        assert store.auto_merge(addr="0x406000", category="misc", similarity_threshold=0.1)["merged"] == 1
        assert store.delete(duplicate_a) is False
        assert store.delete(duplicate_b) is True

        old_id = store.write("old low confidence", confidence=0.1, addr="0x407000")
        assert isinstance(store.prune(max_entries=1, min_q_value=0.2), dict)
        assert store.read(old_id) is None or store.read(old_id).get("confidence", 0) >= 0.2
        assert store.clear("does-not-exist") == 0
    finally:
        store.close()


def test_session_action_surface_handles_metadata_macros_and_idle_cleanup(tmp_path: Path, monkeypatch):
    server = IDAMCPServer()
    manager = SessionManager(str(tmp_path / "sessions"))
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    session = manager.create_session(str(binary), tags=["keep"], notes="initial")
    server.session_mgr = manager
    server.current_session = session
    server._ensure_client_owns_session = lambda _session: None
    server._client_owns_session = lambda _sid: True
    server._session_is_busy = lambda _sid: False
    server._runtime_record = lambda _sid: None
    server._safe_mode_active = lambda _sid: False
    server._analysis_is_complete = lambda _sid: True
    server._session_ownership_report = lambda _sid: {"locked": False}
    server._drop_sid_from_groups = lambda _sid: None
    server._forget_analysis_state = lambda _sid: None
    server._cleanup_runtime = lambda _sid: None
    server._export_session_hypotheses_to_symbol_db = lambda _sid: 0
    server._save_session_macros = lambda: None

    try:
        sid = session.session_id
        listed = server._handle_session({"action": "list", "limit": "2"})
        assert listed["ok"] is True and listed["count"] == 1
        assert server._handle_session({"action": "get", "session_id": sid})["ok"] is True
        assert server._handle_session({"action": "search_notes", "query": "initial"})["count"] == 1
        assert server._session_action_stats({})["ok"] is True
        assert server._session_action_narrative({"limit": 3})["ok"] is True
        assert server._session_action_validate({"session_id": sid})["ok"] is True

        assert server._handle_session({"action": "update", "session_id": sid, "tags": "a, b", "name": "renamed"})["ok"] is True
        assert server._handle_session({"action": "tag", "session_id": sid, "tag": "review"})["ok"] is True
        assert server._handle_session({"action": "add_note", "session_id": sid, "note": "checked"})["ok"] is True
        assert server._handle_session({"action": "untag", "session_id": sid, "tag": "review"})["ok"] is True
        assert server._handle_session({"action": "clear_notes", "session_id": sid})["ok"] is True
        assert server._handle_session({"action": "rename", "session_id": sid, "name": "final"})["ok"] is True

        macro = server._session_action_macro_set({
            "action": "macro_set", "name": "inspect", "data": {"action": "status"}
        })
        assert macro["ok"] is True
        assert server._session_action_macro_get({"name": "inspect"})["ok"] is True
        assert server._session_action_macro_list({})["count"] == 1
        server._execute_tool = lambda tool, args: {"ok": True, "tool": tool, "action": args["action"]}
        ran = server._session_action_macro_run({"name": "inspect"})
        assert ran["macro"] == "inspect"
        assert server._session_action_macro_delete({"name": "inspect"})["ok"] is True
        assert server._session_action_macro_get({"name": "inspect"})["error"] is True

        assert server._handle_session({"action": "snapshot", "session_id": sid})["ok"] is True
        assert server._handle_session({"action": "idle_purge"})["error"] is True
        assert server._handle_session({"action": "idle_purge", "idle_seconds": 60})["ok"] is True
        assert server._handle_session({"action": "not-real"})["error"] is True
    finally:
        server.shutdown()


def test_blackboard_dispatch_matrix_covers_crud_planning_and_file_paths(tmp_path: Path):
    """Run the host blackboard actions against a real temporary workspace."""
    server = IDAMCPServer()
    manager = SessionManager(str(tmp_path / "sessions"))
    binary = tmp_path / "blackboard.bin"
    binary.write_bytes(b"blackboard fixture")
    session = manager.create_session(str(binary))
    server.session_mgr = manager
    server.current_session = session
    server.cache_dir = str(tmp_path / "host-cache")
    server._blackboard_path_cache = {}
    server._phase_gates_enabled = False
    server._client_owns_session = lambda _sid: True
    server._session_is_busy = lambda _sid: False
    server._idb_rpc = lambda: (lambda _tool, _args: {
        "functions": [
            {"start_ea": 0x401000, "name": "sub_401000", "xref_count": 3},
            {"addr": "0x402000", "name": "named", "xref_count": 1},
        ]
    })
    server._execute_tool = lambda _tool, _args: {"ok": True}
    server._send_notification = lambda *_args, **_kwargs: None

    def call(**kwargs):
        result = server._handle_blackboard(kwargs)
        assert isinstance(result, dict), kwargs
        assert result.get("error") is not True, (kwargs, result)
        return result

    try:
        policy = call(action="policy_set", strict_mode=False, enforce_phases="commit|finalize")
        assert policy["ok"] is True
        assert call(action="policy_status")["ok"] is True
        assert call(action="policy_check")["ok"] is True
        assert call(action="phase_status")["ok"] is True
        assert call(action="phase_set", phase="prove")["ok"] is True
        assert call(action="phase_tick", limit=2)["ok"] is True

        written = call(
            action="write",
            title="Parser observation",
            content="length checked before copy",
            addr="0x401000",
            category="analysis",
            tags="parser|input",
            evidence=[{"type": "xref", "value": "caller"}],
        )
        entry_id = written["entry_id"]
        assert call(action="list", category="analysis")["count"] >= 1
        assert call(action="search", query="Parser")["ok"] is True
        assert call(action="read", entry_id=entry_id)["entry"]["id"] == entry_id
        assert call(action="update", entry_id=entry_id, content="length checked")["ok"] is True
        assert call(action="add_evidence", entry_id=entry_id, evidence_type="trace", value="seen")["ok"] is True
        assert call(action="calibrate", entry_id=entry_id)["ok"] is True
        assert call(action="mark_examined", addr="0x403000", verdict="boring")["ok"] is True
        assert call(action="recall", addrs="0x401000|0x403000")["ok"] is True

        for action in ("stats", "coverage", "workspace_brief", "campaign_summary", "state_health", "conflicts", "stale", "crawler_status"):
            assert call(action=action)["ok"] is True
        assert call(action="next_target", strategy="coverage", limit=3)["ok"] is True
        assert call(action="frontier", limit=3)["ok"] is True

        export_name = "blackboard.json"
        exported = call(action="export", format="json", path=export_name, include_resolved=True)
        assert exported["ok"] is True and Path(exported["path"]).exists()
        assert call(action="export", format="markdown", limit=10)["ok"] is True
        notes_path = Path(server._bb_path_root()) / "notes.md"
        notes_path.write_text("## Imported\n\nA useful observation at 0x404000.\n", encoding="utf-8")
        assert call(action="notes_import", path=notes_path.name)["ok"] is True

        assert call(action="decision_card", claim="Need to verify parser", addr="0x401000")["ok"] is True
        assert call(action="working_set", limit=3)["ok"] is True
        assert call(action="trace_ingest", text="inspect 0x401000", limit=1)["ok"] is True
        assert call(action="trace_status", limit=3)["ok"] is True
        assert call(action="trace_run", limit=1)["ok"] is True
        assert call(action="stop_crawler")["ok"] is True

        assert call(action="contradict", entry_id=entry_id, reason="counter evidence")["ok"] is True
        assert call(action="resolve", entry_id=entry_id)["ok"] is True
        assert call(action="delete", entry_id=entry_id)["ok"] is True
        assert call(action="clear", category="missing")["ok"] is True
        assert call(action="prune", max_entries=100)["ok"] is True
    finally:
        server.shutdown()
