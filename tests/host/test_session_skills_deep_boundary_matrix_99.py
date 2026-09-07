"""Deep offline coverage for persisted skills and bootstrap guardrails."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import session_skills as skills_module
from ida_pro_mcp.host.server.session import Session, SessionManager


def _manager(tmp_path):
    manager = SessionManager(str(tmp_path))
    manager.sessions["SKILL001"] = Session(
        "SKILL001",
        idb_path=str(tmp_path / "sample.i64"),
        binary_path=str(tmp_path / "sample.bin"),
    )
    os.makedirs(os.path.dirname(manager._get_skills_path("SKILL001")), exist_ok=True)
    return manager


def test_scalar_and_state_normalization_covers_fallback_types():
    assert skills_module.SessionSkillsMixin._finite_score("not-a-number") == 0.5
    assert skills_module._activity_result_scalar("{not-json") == "{not-json"
    assert skills_module._activity_result_scalar(
        {"target": 7, "addresses": [7], "topic": 8}
    ) == "{'target': 7, 'addresses': [7], 'topic': 8}"[:200]

    normalized = skills_module.SessionSkillsMixin._normalize_skills_state(
        {
            "skills": ["not-a-map"],
            "q_table": [],
            "activity_log": "not-a-list",
            "hypotheses": {"not": "a-list"},
            "bootstrap": {},
        }
    )
    assert normalized == {
        "skills": {},
        "q_table": {},
        "activity_log": [],
        "hypotheses": [],
        "bootstrap": {},
    }

    normalized = skills_module.SessionSkillsMixin._normalize_skills_state(
        {"skills": {"x": {"tags": 42}}}
    )
    assert normalized["skills"]["x"]["tags"] == []


def test_save_skills_removes_partial_file_after_atomic_write_failure(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    messages = []
    monkeypatch.setattr(skills_module, "log_rpc", messages.append)
    monkeypatch.setattr(
        skills_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )

    manager._save_skills("SKILL001", {"skills": {}})

    assert messages and "replace failed" in messages[0]
    assert not list((tmp_path / "SID_SKILL001").glob("*.tmp"))


def test_bootstrap_error_propagation_and_readiness_trend_modes(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    missing = manager.bootstrap_plan_status("missing")
    assert missing["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.suggest_triage("missing")["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.bootstrap_readiness_gate("missing")["code"] == MCPError.SESSION_NOT_FOUND
    assert manager.bootstrap_finalize_report("missing")["code"] == MCPError.SESSION_NOT_FOUND

    failure = make_error(MCPError.INVALID_ARGS, "forced failure")
    monkeypatch.setattr(manager, "bootstrap_readiness_gate", lambda _sid: failure)
    assert manager.bootstrap_record_readiness(sid)["code"] == MCPError.INVALID_ARGS

    monkeypatch.setattr(manager, "bootstrap_readiness_trend", lambda *_a, **_k: failure)
    assert manager.bootstrap_readiness_regression_guard(sid)["code"] == MCPError.INVALID_ARGS

    trend_manager = _manager(tmp_path / "improving")
    monkeypatch.setattr(
        trend_manager,
        "_load_skills",
        lambda _sid: {
            "skills": {},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
            "bootstrap": {
                "readiness_history": [
                    {"readiness": False, "coverage": 10},
                    {"readiness": False, "coverage": 11},
                    {"readiness": True, "coverage": 20},
                    {"readiness": True, "coverage": 21},
                ]
            },
        },
    )
    improving = trend_manager.bootstrap_readiness_trend(sid, window=4)
    assert improving["status"] == "improving"
    assert trend_manager.bootstrap_readiness_trend("missing")["code"] == MCPError.SESSION_NOT_FOUND

    insufficient = trend_manager.bootstrap_readiness_regression_guard(sid)
    assert insufficient["triggered"] is False
    empty_manager = _manager(tmp_path / "empty")
    assert empty_manager.bootstrap_readiness_regression_guard(sid)["triggered"] is False

    regressing_manager = _manager(tmp_path / "regressing")
    regressing_manager._save_skills(
        sid,
        {
            "skills": {},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
            "bootstrap": {
                "readiness_history": [
                    {"readiness": True, "coverage": 90},
                    {"readiness": True, "coverage": 90},
                    {"readiness": False, "coverage": 80},
                    {"readiness": False, "coverage": 80},
                ]
            },
        },
    )
    guarded = regressing_manager.bootstrap_readiness_regression_guard(sid)
    assert guarded["triggered"] is True
    assert guarded["actions"][-1]["action"] == "bootstrap_snapshot"


@pytest.mark.parametrize(
    "method",
    [
        "bootstrap_plan_status",
        "bootstrap_summary",
        "bootstrap_calibration_report",
        "bootstrap_mitigation_effectiveness",
    ],
)
def test_readiness_gate_propagates_each_dependency_error(tmp_path, monkeypatch, method):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    failure = make_error(MCPError.INVALID_ARGS, method)

    monkeypatch.setattr(manager, method, lambda *_args, **_kwargs: failure)
    result = manager.bootstrap_readiness_gate(sid)

    assert result["code"] == MCPError.INVALID_ARGS


def test_finalize_report_propagates_each_stage_and_builds_risk_flags(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    failure = make_error(MCPError.INVALID_ARGS, "stage failure")
    stages = (
        "bootstrap_plan_status",
        "bootstrap_readiness_gate",
        "bootstrap_readiness_trend",
        "bootstrap_mitigation_effectiveness",
        "bootstrap_summary",
    )
    for stage in stages:
        for name in stages:
            monkeypatch.setattr(manager, name, lambda *_a, **_k: {"ok": True})
        monkeypatch.setattr(manager, stage, lambda *_a, **_k: failure)
        assert manager.bootstrap_finalize_report(sid)["code"] == MCPError.INVALID_ARGS

    monkeypatch.setattr(
        manager,
        "bootstrap_plan_status",
        lambda _sid: {"ok": True, "overall": {"coverage": 100}},
    )
    monkeypatch.setattr(
        manager,
        "bootstrap_readiness_gate",
        lambda _sid: {"ok": True, "readiness": True},
    )
    monkeypatch.setattr(
        manager,
        "bootstrap_readiness_trend",
        lambda *_a, **_k: {"ok": True, "enough_data": True, "regressing": True},
    )
    monkeypatch.setattr(
        manager,
        "bootstrap_mitigation_effectiveness",
        lambda *_a, **_k: {"ok": True, "enough_data": True, "tier": "poor"},
    )
    monkeypatch.setattr(
        manager,
        "bootstrap_summary",
        lambda _sid: {"ok": True, "calibration": {"ece": 0.3}},
    )
    report = manager.bootstrap_finalize_report(sid)
    assert report["stage"] == "needs_attention"
    assert set(report["risk_flags"]) == {
        "readiness_regressing",
        "mitigation_effectiveness_poor",
        "ece_above_recommended",
    }


def test_suggestion_embedding_and_global_fallback_modes(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    manager._save_skills(
        sid,
        {
            "skills": {
                "local": {
                    "q_value": 0.4,
                    "description": "inspect imports",
                    "tags": ["imports"],
                }
            },
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )

    class Embedder:
        def embed_vector(self, _text):
            return [1.0, 0.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.8

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", Embedder
    )
    monkeypatch.setattr(
        manager,
        "_find_global_skills",
        lambda **_kwargs: [
            {"skill_id": "local", "description": "duplicate", "tags": []},
            {"skill_id": "global", "description": "inspect imports", "tags": ["imports"]},
        ],
    )

    suggestions = manager.suggest_strategy(sid, "imports")

    assert suggestions["ok"] is True
    assert {row["skill_id"] for row in suggestions["suggestions"]} == {
        "local", "global"
    }
    local = next(row for row in suggestions["suggestions"] if row["skill_id"] == "local")
    assert local["context_match"] is True

    class NoneEmbedder:
        def embed_vector(self, _text):
            return None

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", NoneEmbedder
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True

    class ErrorEmbedder:
        def embed_vector(self, _text):
            raise RuntimeError("embedding failed")

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", ErrorEmbedder
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True

    class PartialEmbedder:
        def __init__(self):
            self.calls = 0

        def embed_vector(self, _text):
            self.calls += 1
            if self.calls == 1:
                return [1.0, 0.0]
            if self.calls == 2:
                return None
            raise RuntimeError("candidate embedding failed")

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", PartialEmbedder
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True

    class ErrorAfterContextEmbedder:
        def __init__(self):
            self.calls = 0

        def embed_vector(self, _text):
            self.calls += 1
            if self.calls == 1:
                return [1.0, 0.0]
            raise RuntimeError("candidate embedding failed")

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder",
        ErrorAfterContextEmbedder,
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True

    class GlobalNoneEmbedder:
        def __init__(self):
            self.calls = 0

        def embed_vector(self, _text):
            self.calls += 1
            if self.calls < 3:
                return [1.0, 0.0]
            return None

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder",
        GlobalNoneEmbedder,
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True

    monkeypatch.setattr(
        manager,
        "_find_global_skills",
        lambda **_kwargs: [{"skill_id": "global", "description": "network", "tags": []}],
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder",
        lambda: (_ for _ in ()).throw(RuntimeError("model unavailable")),
    )
    assert manager.suggest_strategy(sid, "imports")["ok"] is True


def test_dead_end_detector_exercises_nonmatching_search_and_loop_paths(tmp_path):
    manager = _manager(tmp_path)
    short_search = [
        {"tool": "search", "action": "find", "result": "one"}
        for _ in range(3)
    ]
    short_search.extend(
        {"tool": "misc", "action": f"health-{i}", "result": str(i)}
        for i in range(7)
    )
    assert manager._detect_dead_end(short_search) is None

    non_loop = [
        {"tool": f"tool-{i}", "action": "action", "result": str(i)}
        for i in range(10)
    ]
    assert manager._detect_dead_end(non_loop) is None


def test_list_skills_ignores_blank_tags_and_triage_clamps_limit(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    sid = "SKILL001"
    manager._save_skills(
        sid,
        {
            "skills": {"one": {"q_value": 0.8, "tags": ["", "imports"]}},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    monkeypatch.setattr(manager, "_find_global_skills", lambda **kwargs: [])
    assert manager.list_skills(sid, global_skills=True)["global_count"] == 0
    manager._save_skills(
        sid,
        {
            "skills": {"blank": {"q_value": 0.8, "tags": [""]}},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    assert manager.list_skills(sid, global_skills=True)["global_count"] == 0
    tag_manager = _manager(tmp_path / "tags")
    monkeypatch.setattr(
        tag_manager,
        "_load_skills",
        lambda _sid: {
            "skills": {"blank": {"q_value": 0.8, "tags": [""]}},
            "q_table": {},
            "activity_log": [],
            "hypotheses": [],
        },
    )
    monkeypatch.setattr(tag_manager, "_find_global_skills", lambda **kwargs: [])
    assert tag_manager.list_skills(sid, global_skills=True)["global_count"] == 0

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.context.get_assembler",
        lambda: SimpleNamespace(suggest_next_targets=lambda *_a, **_k: ["target"]),
    )
    triage = manager.suggest_triage(sid, limit=1000)
    assert triage["limit"] == 50
    assert triage["suggestions"] == ["target"]
    assert manager.dashboard("missing")["code"] == MCPError.SESSION_NOT_FOUND
