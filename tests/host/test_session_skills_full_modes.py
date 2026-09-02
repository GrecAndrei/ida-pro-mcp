"""Integrated coverage for the session skills and activity surfaces."""

from __future__ import annotations

import json
import os
import sqlite3

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.session import Session, SessionManager
from ida_pro_mcp.host.server.session_skills import _activity_result_scalar


def _manager(tmp_path):
    manager = SessionManager(str(tmp_path))
    manager.sessions["SKILL001"] = Session(
        "SKILL001",
        idb_path=str(tmp_path / "demo.i64"),
        binary_path=str(tmp_path / "demo.bin"),
        phase="deep_analysis",
    )
    os.makedirs(os.path.dirname(manager._get_skills_path("SKILL001")), exist_ok=True)
    manager._save_skills(
        "SKILL001",
        {
            "skills": {
                "local-high": {
                    "q_value": 0.9,
                    "description": "inspect imports and callers",
                    "tags": ["imports", "analysis"],
                    "success_count": 2,
                    "failure_count": 0,
                },
                "local-low": {"q_value": 0.1, "description": "old", "tags": []},
            },
            "q_table": {"local-high": 0.9, "local-low": 0.1},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    return manager


def _add_global(manager):
    conn = sqlite3.connect(manager._global_skills_db)
    conn.execute(
        "INSERT INTO global_skills VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "global-imports",
            "Global imports",
            "inspect imports and xrefs",
            json.dumps(["read imports"]),
            json.dumps(["imports", "analysis"]),
            "OTHER001",
            0.7,
            3,
            1,
            "2026-01-01T00:00:00",
            "2026-01-02T00:00:00",
            None,
            4,
        ),
    )
    conn.commit()
    conn.close()


def test_skill_rating_listing_and_context_suggestions_share_persistence(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _add_global(manager)
    sid = "SKILL001"

    assert manager.rate_skill("missing", "local-high", 1)["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.rate_skill(sid, "missing", 1)["code"] == MCPError.NOT_FOUND
    promoted = manager.rate_skill(sid, "local-high", 1.0)
    assert promoted["ok"] is True
    assert promoted["promoted_to_L2"] is True
    failed = manager.rate_skill(sid, "local-low", 0.0)
    assert failed["ok"] is True
    assert failed["q_value"] < 0.1

    local_only = manager.list_skills(sid, min_q=0.5, global_skills=False)
    assert local_only["local_count"] == 1
    with_global = manager.list_skills(sid, min_q=0.0, global_skills=True)
    assert with_global["global_count"] == 1
    assert manager.list_skills("missing")["code"] == MCPError.SESSION_NOT_FOUND

    # Force the deterministic text fallback, then exercise the global and
    # local candidates in one suggestion result.
    class _UnavailableEmbedder:
        def __init__(self):
            raise RuntimeError("no local model")

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", _UnavailableEmbedder
    )
    suggested = manager.suggest_strategy(sid, "imports")
    assert suggested["ok"] is True
    assert {"local-high", "global-imports"}.issubset(
        {row["skill_id"] for row in suggested["suggestions"]}
    )
    assert suggested["suggestions"][0]["context_match"] is True
    assert manager.suggest_strategy(sid, "")["context"] == ""
    assert manager.suggest_strategy("missing")["code"] == MCPError.SESSION_NOT_FOUND


def test_activity_dead_end_shapes_dashboard_and_phase_modes(tmp_path):
    manager = _manager(tmp_path)
    sid = "SKILL001"

    assert _activity_result_scalar('{"target": "main"}') == "main"
    assert _activity_result_scalar('{"addresses": ["0x1000"]}') == "0x1000"
    assert _activity_result_scalar('{"topic": "loader"}') == "loader"
    assert _activity_result_scalar("not-json") == "not-json"

    repeated_decompile = [
        {"tool": "code", "action": "decompile", "result": '{"target":"main"}'}
        for _ in range(5)
    ]
    assert manager._detect_dead_end(repeated_decompile) is None
    repeated_decompile = [{"tool": "code", "action": "noop", "result": "x"}] * 5 + repeated_decompile
    warning = manager._detect_dead_end(repeated_decompile)
    assert warning["type"] == "repeated_decompile"

    repeated_search = [
        {"tool": "search", "action": "find", "result": '{"topic":"memcpy"}'}
        for _ in range(4)
    ]
    repeated_search = [{"tool": "data", "action": "x", "result": "x"}] * 6 + repeated_search
    assert manager._detect_dead_end(repeated_search)["type"] == "repeated_search"

    loop = []
    for i in range(5):
        loop.extend(
            [
                {"tool": "code", "action": "decompile", "result": f"a{i}"},
                {"tool": "data", "action": "strings", "result": f"b{i}"},
            ]
        )
    assert manager._detect_dead_end(loop)["type"] == "tool_loop"
    assert manager._detect_dead_end([]) is None

    manager.log_activity(sid, "code", "decompile", '{"target":"main"}')
    manager.log_activity(sid, "search", "find", '{"addresses":["0x1000"]}')
    manager.log_activity(sid, "data", "strings", "ok")
    manager.sessions[sid].phase = "reporting"
    manager.sessions[sid].update_access()
    dashboard = manager.dashboard(sid)
    assert dashboard["activity"]["functions_decompiled"] == 1
    assert dashboard["activity"]["searches_performed"] == 2
    assert dashboard["bootstrap"].get("initialized", False) is False
    assert dashboard["suggested_next"] == ["blackboard.export", "session.notebook"]
    assert manager.get_activity_log(sid, limit=2)["total"] == 3
    assert manager.get_phase(sid)["phase"] == "reporting"
    assert manager.get_phase("missing")["code"] == MCPError.SESSION_NOT_FOUND


def test_skill_file_recovery_and_triage_error_modes(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    path = manager._get_skills_path(sid)

    # A corrupt preferred file is handled as a fresh state; the legacy flat
    # file remains readable when the preferred path is absent.
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("not-json")
    assert manager._load_skills(sid)["skills"] == {}
    os.remove(path)
    legacy = os.path.join(manager.session_dir, "SID_SKILL001_skills.json")
    with open(legacy, "w", encoding="utf-8") as handle:
        json.dump({"skills": {"legacy": {}}, "q_table": {}, "activity_log": [], "hypotheses": []}, handle)
    assert "legacy" in manager._load_skills(sid)["skills"]

    manager.sessions[sid].idb_path = ""
    assert manager.suggest_triage(sid)["code"] == MCPError.INVALID_ARGS
    manager.sessions[sid].idb_path = str(tmp_path / "demo.i64")
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.context.get_assembler",
        lambda: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    triage = manager.suggest_triage(sid, limit="not-an-int")
    assert triage["ok"] is True
    assert triage["limit"] == 5
    assert triage["suggestions"] == []

    assert manager._bootstrap_prior_confidence(None) == 0.5
    assert manager._bootstrap_prior_confidence({"policies": {}}) == 0.5
