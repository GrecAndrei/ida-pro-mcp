from tests._isolated_repo_loader import load_host_module

_casefile_helpers = load_host_module("casefile_helpers")
build_chain_of_custody = _casefile_helpers.build_chain_of_custody
build_risk_summary = _casefile_helpers.build_risk_summary
to_markdown_casefile = _casefile_helpers.to_markdown_casefile


def test_build_risk_summary_scores_debt_and_risk_level():
    findings = [
        {"title": "Process injection", "tags": ["dangerous"], "evidence": [{"a": 1}]},
        {"title": "Normal helper", "tags": [], "evidence": [{"a": 1}, {"b": 2}]},
    ]
    hyps = [{"status": "unknown"}, {"status": "supported"}]
    ai = [{"approved": False}, {"approved": True}]
    out = build_risk_summary(findings, hyps, ai)
    assert out["high_risk_findings"] >= 1
    assert out["knowledge_debt_index"] >= 1
    assert out["risk_level"] in ("low", "medium", "high")


def test_build_chain_of_custody_merges_ordered_events():
    sessions = [{"session_id": "s1", "created_at": "2026-01-01T00:00:00", "binary_path": "a.bin"}]
    replay = [{"timestamp": "2026-01-01T00:01:00", "tool": "code", "action_name": "decompile"}]
    ai = [{"timestamp": "2026-01-01T00:02:00", "reviewer": "alice", "target": "fn", "approved": True}]
    out = build_chain_of_custody(sessions, replay, ai)
    assert len(out) == 3
    assert out[0]["type"] == "session"


def test_to_markdown_casefile_contains_integrity_and_summary():
    md = to_markdown_casefile(
        {
            "generated_at": "2026-01-01T00:00:00",
            "summary": {"sessions": 1, "findings": 2, "hypotheses": 3, "ai_records": 4},
            "risk_summary": {"risk_level": "medium", "high_risk_findings": 1, "knowledge_debt_index": 7},
            "integrity": {"sha256": "abc"},
        }
    )
    assert "# Casefile Export" in md
    assert "SHA256: abc" in md
