"""Behavior coverage for the host session-resume context builder."""

from types import SimpleNamespace

from ida_pro_mcp.host.response_signals import build_session_resume


class _ResumeManager:
    def __init__(self, session, skills=None, notebook=""):
        self.session = session
        self.skills = skills or {"activity_log": [], "hypotheses": [], "skills": {}}
        self.notebook = notebook

    def get_session(self, sid):
        return self.session if self.session and sid == self.session.session_id else None

    def _load_skills(self, sid):
        assert sid == self.session.session_id
        return self.skills

    def _load_notebook(self, sid):
        assert sid == self.session.session_id
        return self.notebook


def test_resume_returns_none_without_a_manager_session_or_content():
    assert build_session_resume(None, "ABC12345") is None
    assert build_session_resume(_ResumeManager(None), "ABC12345") is None
    session = SimpleNamespace(session_id="ABC12345", phase="triage")
    manager = _ResumeManager(session)
    assert build_session_resume(manager, "") is None
    assert build_session_resume(manager, "MISSING1") is None
    assert build_session_resume(manager, session.session_id) is None


def test_resume_collects_decompiles_hypotheses_skills_progress_and_notebook():
    session = SimpleNamespace(session_id="ABC12345", phase="deep_analysis")
    activity = [
        {"action": "decompile", "result": "0x401000"},
        {"action": "semantic_decompile", "result": '{"addresses": ["0x402000"]}'},
        {"action": "decompile", "result": {"addresses": ["0x403000"]}},
        {"action": "decompile", "result": "not JSON"},
        {"action": "rename", "result": "0x404000"},
    ]
    hypotheses = [
        {"status": "pending", "id": f"p{i}", "statement": f"pending {i}"}
        for i in range(7)
    ] + [
        {"status": "confirmed", "id": f"c{i}", "statement": f"confirmed {i}"}
        for i in range(7)
    ]
    skills = {
        "low": {"name": "low", "description": "ignored", "q_value": 0.5},
        "high": {"name": "high", "description": "x" * 200, "q_value": 0.9},
    }
    notebook = "\n".join(f"line {i}" for i in range(12))
    manager = _ResumeManager(
        session,
        {"activity_log": activity, "hypotheses": hypotheses, "skills": skills},
        notebook,
    )

    resume = build_session_resume(manager, session.session_id)

    assert resume["previously_decompiled"] == ["0x401000", "0x402000", "0x403000"]
    assert len(resume["pending_hypotheses"]) == 5
    assert len(resume["confirmed_findings"]) == 5
    assert resume["available_skills"] == [{"name": "high", "description": "x" * 100}]
    assert resume["analysis_progress"] == {
        "total_actions": 5,
        "phase": "deep_analysis",
    }
    assert resume["last_notebook_entry"] == "\n".join(f"line {i}" for i in range(2, 12))


def test_resume_ignores_malformed_address_payloads_and_keeps_valid_dicts():
    session = SimpleNamespace(session_id="ABC12345", phase="triage")
    manager = _ResumeManager(
        session,
        {
            "activity_log": [
                {"action": "decompile", "result": {"addresses": []}},
                {"action": "decompile", "result": {"addresses": [" 0x405000 "]}},
                {"action": "decompile", "result": "[1, 2, 3]"},
            ],
            "hypotheses": [],
            "skills": {},
        },
    )

    resume = build_session_resume(manager, session.session_id)

    assert resume["previously_decompiled"] == ["0x405000"]
    assert resume["analysis_progress"]["total_actions"] == 3
