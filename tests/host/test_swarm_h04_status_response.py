"""h04 status/response shaping: live analysis signals, resume gate, notices.

Standalone response-pipeline tests (no live IDA) for the revamp of the
session open -> background-load -> safe-mode -> analysis-complete ->
automatic-resume lifecycle, from the response-shaping side:

- ``analysis_ready`` / ``analysis_active`` (the "runtime alive but still
  busy" live signals) survive compact ``drop_false`` alongside the surviving
  state flags ``safe_mode`` / ``analysis_complete`` / ``background`` /
  ``auto_backgrounded`` / ``ok``, while unrelated false keys still drop.
- The session-resume gate is a monotonic per-session counter: it fires for
  the first 2 enriched calls only, persists past them (no pop on the 3rd),
  and is reset by the session OPEN/close path so a re-opened session starts
  fresh. It keys on the ``idb=``-targeted session, not ``current_session``.
- The analysis-completion notice is one-shot per session: it pops onto the
  next dict-shaped response for that session (generic completion message,
  code ``analysis_complete`` = "confirmed complete at least once"), is left
  pending for list/scalar payloads, and a second response carries no warning.
"""

from __future__ import annotations

import threading

import pytest

from ida_pro_mcp.host.server.server_response import ServerResponseMixin
from ida_pro_mcp.host.server.server_response_compact import (
    ServerResponseCompactMixin,
)
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin
from ida_pro_mcp.host.server.session import Session

_COMPACT_OPTS = {
    "mode": "compact",
    "fields": [],
    "omit": [],
    "max_items": 100,
    "max_string": 100_000,
    "char_budget": 0,
    "drop_empty": True,
    "drop_false": True,
    "drop_ok": True,
    "dedupe_counts": True,
    "strip_meta": True,
    "table_mode": False,
    "batch_compact": True,
    "error_details": "basic",
}


class _FakeBlackboard:
    def observe_code(self, addr, kind, text):
        return {"stale_marked": 0}

    def recall_lines(self, addrs, limit=4):
        return []

    def examination(self, addr):
        return None


class _FakeAssembler:
    def __init__(self):
        self.calls = []

    def assemble(self, **kwargs):
        self.calls.append(kwargs)
        return {"related_findings": []}


class _FakeSessionMgr:
    def __init__(self, sessions):
        self._sessions = {s.session_id: s for s in sessions}

    def get_session(self, sid):
        return self._sessions.get(sid)

    def _load_skills(self, sid):
        return {
            "activity_log": [],
            "hypotheses": [
                {"status": "pending", "id": "h1", "statement": "test hypothesis"}
            ],
            "skills": {},
        }


class _Host(ServerResponseMixin, ServerRuntimeMixin):
    """A real-mixin host: response helpers resolve through production MRO."""

    enable_response_enrichment = False
    current_session = None
    assembler = None
    _pointer_note_min_signal = 1.0
    _pointer_note_pending_signal = 0.0
    _pointer_note_last_shown_at = 0.0
    _pointer_note_min_interval = 0.0

    def __init__(self):
        self.blackboard_sessions: list = []
        self._pending_truncation = {}
        self._truncation_owner_id = lambda: ""
        self._pending_session_notices = {}
        self._session_resume_calls: dict[str, int] = {}
        self._session_resume_calls_lock = threading.Lock()
        self.session_runtimes = {}
        self._pending_analysis = set()
        self.session_mgr = _FakeSessionMgr([])

    def _blackboard_store_for(self, session):
        self.blackboard_sessions.append(session)
        return _FakeBlackboard()

    def _get_blackboard_store(self):
        self.blackboard_sessions.append(getattr(self, "current_session", None))
        return _FakeBlackboard()


@pytest.fixture()
def host() -> _Host:
    return _Host()


def _session(sid="AAAA0001", idb="/tmp/a.i64", binary="/tmp/a.bin"):
    return Session(sid, idb, binary)


# ---------------------------------------------------------------------------
# Live analysis signals survive compact drop_false
# ---------------------------------------------------------------------------


class TestLiveAnalysisSignalsSurviveCompact:
    def test_state_boolean_keys_include_live_analysis_signals(self):
        keys = set(ServerResponseCompactMixin._STATE_BOOLEAN_KEYS)
        assert {"analysis_ready", "analysis_active"} <= keys, keys
        # Surviving-state flags keep their semantics unchanged.
        assert {
            "safe_mode",
            "analysis_complete",
            "background",
            "auto_backgrounded",
            "ok",
        } <= keys, keys

    def test_compact_status_keeps_ready_and_active_but_drops_other_false(self):
        stub = ServerResponseCompactMixin.__new__(ServerResponseCompactMixin)
        payload = {
            "ok": True,
            "safe_mode": False,
            "analysis_complete": False,
            "analysis_ready": False,
            "analysis_active": True,
            "is_running": True,
            "some_unrelated_flag": False,
        }
        out = stub._compact_value(payload, dict(_COMPACT_OPTS))
        assert out["analysis_ready"] is False, out
        assert out["analysis_active"] is True, out
        assert out["safe_mode"] is False, out
        assert out["analysis_complete"] is False, out
        assert out["is_running"] is True, out
        assert "some_unrelated_flag" not in out, out

    def test_status_pipeline_keeps_live_signals(self, host):
        b = _session()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.assembler = _FakeAssembler()

        status = {
            "ok": True,
            "session": {
                "safe_mode": True,
                "analysis_complete": False,
                "analysis_ready": False,
                "analysis_active": True,
                "background": True,
                "auto_backgrounded": False,
                "is_running": True,
                "aux_flag": False,
            },
            "total_sessions": 1,
        }
        out = host._prepare_response_payload(
            status,
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={"action": "status"},
        )
        sess = out.get("session") or {}
        assert sess["analysis_ready"] is False, out
        assert sess["analysis_active"] is True, out
        assert sess["safe_mode"] is True, out
        assert sess["analysis_complete"] is False, out
        assert sess["background"] is True, out
        assert sess["auto_backgrounded"] is False, out
        assert "aux_flag" not in sess, out


# ---------------------------------------------------------------------------
# Session resume: first 2 calls only, monotonic counter
# ---------------------------------------------------------------------------


class TestSessionResumeGate:
    def _enrich(self, host):
        return host._prepare_response_payload(
            {"ok": True, "items": [1, 2, 3]},
            dict(_COMPACT_OPTS),
            tool_name="search",
            call_args={"query": "x"},
        )

    def test_first_two_calls_fire_resume_third_does_not(self, host):
        b = _session()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.enable_response_enrichment = True
        host.assembler = _FakeAssembler()

        out1 = self._enrich(host)
        assert host._session_resume_calls == {"AAAA0001": 1}
        assert out1.get("_session_resume") is not None, "1st call builds a resume"

        out2 = self._enrich(host)
        assert host._session_resume_calls == {"AAAA0001": 2}
        assert out2.get("_session_resume") is not None, "2nd call builds a resume"

        out3 = self._enrich(host)
        # The counter is NOT popped on the 3rd call: it is monotonic and
        # persists for the life of the session so the resume can never re-fire.
        assert host._session_resume_calls == {"AAAA0001": 3}
        assert out3.get("_session_resume") is None

        out4 = self._enrich(host)
        assert host._session_resume_calls == {"AAAA0001": 4}
        assert out4.get("_session_resume") is None

    def test_resume_counter_resets_on_session_reopen(self, host):
        b = _session()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.enable_response_enrichment = True
        host.assembler = _FakeAssembler()

        self._enrich(host)
        self._enrich(host)
        assert host._session_resume_calls == {"AAAA0001": 2}
        assert self._enrich(host).get("_session_resume") is None

        # Session OPEN/close reset (the live host drops the key in
        # _forget_analysis_state / bootstrap): a re-opened session starts from
        # 0 and fires the resume again.
        host._session_resume_calls.pop("AAAA0001", None)
        out_reopen = self._enrich(host)
        assert out_reopen.get("_session_resume") is not None, "re-opened session fires again"
        assert host._session_resume_calls == {"AAAA0001": 1}

    def test_resume_keys_on_targeted_session_when_idb_targeted(self, host):
        a = _session("AAAA0001", "/tmp/a.i64", "/tmp/a.bin")
        b = _session("BBBB0002", "/tmp/b.i64", "/tmp/b.bin")
        host.session_mgr = _FakeSessionMgr([a, b])
        host.current_session = a
        host.enable_response_enrichment = True
        host.assembler = _FakeAssembler()

        host._prepare_response_payload(
            {"ok": True, "items": [1, 2, 3]},
            dict(_COMPACT_OPTS),
            tool_name="search",
            call_args={"idb": "BBBB0002", "query": "x"},
        )
        # The resume counter was incremented for B (the targeted session), not A.
        assert host._session_resume_calls == {"BBBB0002": 1}

        # A second idb=-targeted call increments B's counter; A stays clean.
        host._prepare_response_payload(
            {"ok": True, "items": [1, 2, 3]},
            dict(_COMPACT_OPTS),
            tool_name="search",
            call_args={"idb": "BBBB0002", "query": "y"},
        )
        assert host._session_resume_calls == {"BBBB0002": 2}


# ---------------------------------------------------------------------------
# One-shot analysis-completion notice
# ---------------------------------------------------------------------------


class TestAnalysisCompletionNotice:
    def _status_call(self, host):
        return host._prepare_response_payload(
            {"ok": True, "session": {"session_id": "AAAA0001", "safe_mode": False}},
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={"action": "status"},
        )

    def test_notice_pops_onto_next_dict_response_for_session(self, host):
        b = _session()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.assembler = _FakeAssembler()
        host._pending_session_notices = {
            "AAAA0001": {
                "code": "analysis_complete",
                "message": "IDA auto-analysis completed.",
            }
        }

        out1 = self._status_call(host)
        assert out1.get("warning", {}).get("code") == "analysis_complete"
        assert out1.get("warning", {}).get("message") == "IDA auto-analysis completed."
        assert host._pending_session_notices == {}

        out2 = self._status_call(host)
        assert "warning" not in out2

    def test_list_payload_leaves_notice_pending(self, host):
        b = _session()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.assembler = _FakeAssembler()
        host._pending_session_notices = {
            "AAAA0001": {
                "code": "analysis_complete",
                "message": "IDA auto-analysis completed.",
            }
        }

        out = host._prepare_response_payload(
            [{"ok": True, "name": "a"}, {"ok": True, "name": "b"}],
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={"action": "list"},
        )
        assert isinstance(out, list)
        # A non-dict payload cannot carry the warning, so the notice stays
        # pending for the session's next dict response.
        assert "AAAA0001" in host._pending_session_notices

        out2 = self._status_call(host)
        assert out2.get("warning", {}).get("code") == "analysis_complete"
        assert host._pending_session_notices == {}

    def test_notice_is_consumed_for_the_targeted_session(self, host):
        a = _session("AAAA0001", "/tmp/a.i64", "/tmp/a.bin")
        b = _session("BBBB0002", "/tmp/b.i64", "/tmp/b.bin")
        host.session_mgr = _FakeSessionMgr([a, b])
        host.current_session = a
        host.assembler = _FakeAssembler()
        host._pending_session_notices = {
            "AAAA0001": {
                "code": "analysis_complete",
                "message": "for A",
            },
            "BBBB0002": {
                "code": "analysis_complete",
                "message": "for B",
            },
        }

        out = host._prepare_response_payload(
            {"ok": True, "session": {"session_id": "BBBB0002", "safe_mode": False}},
            dict(_COMPACT_OPTS),
            tool_name="session",
            call_args={"idb": "BBBB0002", "action": "status"},
        )
        assert out.get("warning", {}).get("message") == "for B"
        assert host._pending_session_notices == {
            "AAAA0001": {"code": "analysis_complete", "message": "for A"}
        }
