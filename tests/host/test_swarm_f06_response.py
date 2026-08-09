"""Regression tests for the f06 response-pipeline audit findings.

Covers:

- [security/high] idb=-targeted calls on a shared connection must enrich,
  recall, annotate, and resume against the session the call actually ran in,
  not ``self.current_session`` (cross-session workspace/notice/resume leaks).
- [correctness/high] per-call truncation is consumed exactly once: when
  dispatch (call_tool) already truncated the raw result, the response layer
  must not truncate the compacted view again (which caps at
  default_truncate_tokens and orphans the first ``_continue`` token).
- [error_handling/medium] an invalid grep regex returns a make_error envelope
  instead of silently returning the unfiltered result.
- [perf/medium] a failed image-base probe is negative-cached so the response
  path does not re-fire a synchronous 1s RPC per code-rendering call.
- [error_handling/low] a make_error envelope passes through post-processing
  unchanged (not stamped ``ok: True`` and post-processed).
- [resource_leak/low] the session-resume counter is a monotonic count that
  fires only for the first two calls and is reset by the session OPEN/close
  path (not the response path), so churned sessions don't accumulate forever
  while re-opened sessions still get a fresh resume.
- [error_handling/low] ``_assemble_and_inject_context`` surfaces failures in
  ``_context_error`` instead of swallowing them.
- [dead_code/low] ``build_session_resume`` no longer carries the unused
  ``_blackboard_entries`` parameter.
- batch output→input chaining: a step that fails to resolve a reference emits
  an INVALID_ARGS envelope that passes through post-processing unchanged, so a
  chained batch error reaches the client as an error, never as a false ok.
"""

from __future__ import annotations

import threading

import pytest

from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error
from ida_pro_mcp.host.response_signals import build_session_resume
from ida_pro_mcp.host.server.postprocess import apply_post_processing
from ida_pro_mcp.host.server.server_response import ServerResponseMixin
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin
from ida_pro_mcp.host.server.session import Session
from ida_pro_mcp.host.stores.truncation import peek_truncated, truncate_response

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
    """A real-mixin host: response helpers resolve through production MRO.

    ``ServerRuntimeMixin`` supplies ``_resolve_session_from_idb_ref`` and
    ``_json_safe_value``; ``ServerResponseMixin`` supplies the response
    pipeline under test. Instance attributes are set per test.
    """

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


def _session_a():
    return Session("AAAA0001", "/tmp/a.i64", "/tmp/a.bin")


def _session_b():
    return Session("BBBB0002", "/tmp/b.i64", "/tmp/b.bin")


# ---------------------------------------------------------------------------
# [security/high] enrichment must follow the idb=-resolved target session
# ---------------------------------------------------------------------------


class TestResponseSessionTargeting:
    def test_resolve_response_session_prefers_idb_target(self, host):
        host.session_mgr = _FakeSessionMgr([_session_a(), _session_b()])
        host.current_session = _session_a()
        target = host._resolve_response_session({"idb": "BBBB0002"})
        assert target is not None
        assert target.session_id == "BBBB0002"

    def test_resolve_response_session_prefers_session_id_arg(self, host):
        host.session_mgr = _FakeSessionMgr([_session_a(), _session_b()])
        host.current_session = _session_a()
        target = host._resolve_response_session({"session_id": "BBBB0002"})
        assert target is not None
        assert target.session_id == "BBBB0002"

    def test_resolve_response_session_falls_back_to_current(self, host):
        host.session_mgr = _FakeSessionMgr([_session_a(), _session_b()])
        current = _session_a()
        host.current_session = current
        target = host._resolve_response_session({"action": "decompile"})
        assert target is current

    def test_enrichment_uses_target_session_not_current(self, host):
        """A decompile targeted at B via idb= must recall/annotate B's
        workspace, never the shared active session A's."""
        a, b = _session_a(), _session_b()
        host.session_mgr = _FakeSessionMgr([a, b])
        host.current_session = a
        host.assembler = _FakeAssembler()

        payload = {"ok": True, "pseudocode": "int f() { return 1; }"}
        host._prepare_response_payload(
            payload,
            dict(_COMPACT_OPTS),
            tool_name="code",
            call_args={"idb": "BBBB0002", "action": "decompile", "addrs": "0x401000"},
        )

        assert host.blackboard_sessions, "no blackboard store was resolved"
        assert all(s is b for s in host.blackboard_sessions), host.blackboard_sessions
        assert host.assembler.calls, "context assembler never ran"
        assert host.assembler.calls[-1]["session_id"] == b.session_id
        assert host.assembler.calls[-1]["idb_path"] == b.idb_path

    def test_enrichment_uses_current_session_when_not_targeted(self, host):
        """Without an idb= reference the enrichment keeps using current_session."""
        a = _session_a()
        host.session_mgr = _FakeSessionMgr([a, _session_b()])
        host.current_session = a
        host.assembler = _FakeAssembler()

        payload = {"ok": True, "pseudocode": "int f() { return 1; }"}
        host._prepare_response_payload(
            payload,
            dict(_COMPACT_OPTS),
            tool_name="code",
            call_args={"action": "decompile", "addrs": "0x401000"},
        )

        assert host.blackboard_sessions
        assert all(s is a for s in host.blackboard_sessions), host.blackboard_sessions
        assert host.assembler.calls[-1]["session_id"] == a.session_id

    def test_analysis_notice_consumed_for_target_not_current(self, host):
        """B's one-shot analysis-complete notice is consumed when a call targets
        B; A's notice stays pending for A's own next response."""
        a, b = _session_a(), _session_b()
        host.session_mgr = _FakeSessionMgr([a, b])
        host.current_session = a
        host._pending_session_notices = {"AAAA0001": "A notice", "BBBB0002": "B notice"}
        host.assembler = _FakeAssembler()

        out = host._prepare_response_payload(
            {"ok": True, "pseudocode": "int f() { return 1; }"},
            dict(_COMPACT_OPTS),
            tool_name="code",
            call_args={"idb": "BBBB0002", "action": "decompile", "addrs": "0x401000"},
        )
        assert out.get("warning") == "B notice", out
        assert host._pending_session_notices == {"AAAA0001": "A notice"}


# ---------------------------------------------------------------------------
# [correctness/high] per-call truncation consumed exactly once
# ---------------------------------------------------------------------------


class TestTruncationConsumedOnce:
    def test_payload_not_truncated_again_after_call_tool(self, host):
        """Simulate a full round-trip: call_tool truncates the raw result,
        then _prepare_response_payload must NOT truncate the compacted view
        again. The surviving _continue token must still reference the FULL raw
        result (3000 chars), proving a single truncation."""
        raw = {"ok": True, "pseudocode": "x" * 3000}
        # call_tool (server_dispatch.py) truncates the raw RPC result at
        # default_truncate_tokens=2000 and leaves _pending_truncation set.
        host._pending_truncation = {"max_tokens": None}
        truncated = truncate_response(raw, max_tokens=2000)
        assert truncated.get("_truncated") is True

        opts = dict(_COMPACT_OPTS)
        opts["char_budget"] = 500  # small enough that a 2nd truncation WOULD fire
        host.assembler = _FakeAssembler()
        out = host._prepare_response_payload(
            truncated,
            opts,
            tool_name="search",
            call_args={"query": "foo"},
        )

        assert host._pending_truncation == {}
        cont = out.get("_continue")
        assert cont, "continuation token was lost"
        meta = peek_truncated(cont["token"])
        assert meta["fields"]["pseudocode"]["total"] == 3000, meta

    def test_response_layer_still_truncates_when_dispatch_did_not(self, host):
        """A payload dispatch did NOT truncate (no _truncated marker) is still
        truncated by the response layer using the per-call budget."""
        host._pending_truncation = {"max_tokens": 500}
        payload = {"ok": True, "matches": [{"name": f"i{k}"} for k in range(50)]}
        opts = dict(_COMPACT_OPTS)
        opts["char_budget"] = 1000
        host.assembler = _FakeAssembler()
        out = host._prepare_response_payload(
            payload,
            opts,
            tool_name="search",
            call_args={"query": "x"},
        )
        assert host._pending_truncation == {}
        assert out.get("_truncated") is True


# ---------------------------------------------------------------------------
# [error_handling/medium] invalid grep regex -> error envelope
# ---------------------------------------------------------------------------


class TestInvalidGrepRegex:
    def test_apply_post_processing_returns_error_envelope(self):
        res = apply_post_processing(
            {"ok": True, "items": [{"name": "foo"}]},
            {"grep": "[invalid", "grep_regex": True, "field": "items"},
        )
        assert is_error_result(res), res
        assert res["code"] == MCPError.INVALID_ARGS

    def test_apply_grep_still_raises_for_callers_that_want_the_raw_signal(self):
        with pytest.raises(ValueError, match="Invalid grep regex"):
            from ida_pro_mcp.host.server.postprocess import apply_grep

            apply_grep([{"name": "foo"}], {"grep": "[invalid", "grep_regex": True})


# ---------------------------------------------------------------------------
# [error_handling/low] error envelope passes through post-processing
# ---------------------------------------------------------------------------


class TestErrorEnvelopePassthrough:
    def test_make_error_envelope_not_stamped_ok(self):
        err = make_error(MCPError.INVALID_ARGS, "bad input")
        out = apply_post_processing(err, {"grep": "x", "field": "results"})
        assert out == err, out
        assert out.get("error") is True
        assert "ok" not in out
        assert "results" not in out

    def test_batch_chaining_error_envelope_passes_through_unchanged(self):
        """An unresolved output→input step reference produces an INVALID_ARGS
        envelope that must reach the client unmodified — the response layer
        must never stamp a chained-batch step error ``ok: True`` or grep/filter
        its body as if it were a successful payload."""
        err = make_error(
            MCPError.INVALID_ARGS,
            "Batch step 1: unresolved result reference 'step0.result.missing'",
        )
        out = apply_post_processing(
            err,
            {"grep": "missing", "grep_regex": True, "field": "results"},
        )
        assert out == err, out
        assert out.get("error") is True
        assert out.get("code") == MCPError.INVALID_ARGS
        assert "ok" not in out


# ---------------------------------------------------------------------------
# [perf/medium] imagebase probe is negative-cached
# ---------------------------------------------------------------------------


class TestImagebaseNegativeCache:
    def test_failed_probe_fires_rpc_once(self, host):
        host.session_runtimes = {"BBBB0002": {"port": 1234, "auth_token": None}}
        calls = []

        def _fail(payload, port, timeout, auth_token):
            calls.append(payload)
            raise TimeoutError("simulated meta timeout")

        host._send_rpc_raw = _fail
        assert host._get_session_imagebase("BBBB0002") is None
        assert len(calls) == 1
        # The miss is cached: a second code-rendering response must not re-fire
        # the synchronous 1s RPC.
        assert host._get_session_imagebase("BBBB0002") is None
        assert len(calls) == 1

    def test_empty_probe_result_is_cached(self, host):
        host.session_runtimes = {"BBBB0002": {"port": 1234, "auth_token": None}}
        calls = []

        def _empty(payload, port, timeout, auth_token):
            calls.append(payload)
            return {"ok": True}

        host._send_rpc_raw = _empty
        assert host._get_session_imagebase("BBBB0002") is None
        assert len(calls) == 1
        assert host._get_session_imagebase("BBBB0002") is None
        assert len(calls) == 1

    def test_success_is_cached_and_returned(self, host):
        host.session_runtimes = {"BBBB0002": {"port": 1234, "auth_token": None}}
        calls = []

        def _ok(payload, port, timeout, auth_token):
            calls.append(payload)
            return {"ok": True, "image_base": "0x140000000"}

        host._send_rpc_raw = _ok
        assert host._get_session_imagebase("BBBB0002") == 0x140000000
        assert len(calls) == 1
        assert host._get_session_imagebase("BBBB0002") == 0x140000000
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# [resource_leak/low] resume counter freed after first two calls
# ---------------------------------------------------------------------------


class TestSessionResumeCounter:
    def _enrich(self, host):
        return host._prepare_response_payload(
            {"ok": True, "items": [1, 2, 3]},
            dict(_COMPACT_OPTS),
            tool_name="search",
            call_args={"query": "x"},
        )

    def test_counter_persists_after_first_two_calls(self, host):
        b = _session_b()
        host.session_mgr = _FakeSessionMgr([b])
        host.current_session = b
        host.enable_response_enrichment = True
        host.assembler = _FakeAssembler()

        out1 = self._enrich(host)
        assert host._session_resume_calls == {"BBBB0002": 1}
        assert out1.get("_session_resume") is not None, "first call should build a resume"

        out2 = self._enrich(host)
        assert host._session_resume_calls == {"BBBB0002": 2}
        assert out2.get("_session_resume") is not None

        out3 = self._enrich(host)
        # The counter is NOT freed: it is a monotonic count that keeps the
        # resume from re-firing for the life of the session. Resetting is the
        # session OPEN/close path's job (drop the key in _forget_analysis_state
        # and on create/reuse), not the response path's.
        assert host._session_resume_calls == {"BBBB0002": 3}
        assert out3.get("_session_resume") is None

        out4 = self._enrich(host)
        assert host._session_resume_calls == {"BBBB0002": 4}
        assert out4.get("_session_resume") is None

        # Simulating the session-close reset: once the key is dropped, a
        # re-opened session starts from 0 and fires the resume again.
        host._session_resume_calls.pop("BBBB0002", None)
        out5 = self._enrich(host)
        assert host._session_resume_calls == {"BBBB0002": 1}
        assert out5.get("_session_resume") is not None, "re-opened session fires the resume again"

    def test_resume_uses_target_session_when_idb_targeted(self, host):
        a, b = _session_a(), _session_b()
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


# ---------------------------------------------------------------------------
# [error_handling/low] _assemble_and_inject_context surfaces failures
# ---------------------------------------------------------------------------


class TestContextErrorSurfaced:
    def test_assembler_failure_reports_context_error(self, host):
        class _RaisingAssembler:
            def assemble(self, **kwargs):
                raise RuntimeError("assembler boom")

        host.assembler = _RaisingAssembler()
        payload = {"pseudocode": "int f() { return 1; }"}
        host._assemble_and_inject_context(
            "code", "decompile", payload, "0x401000", opts={"mode": "compact"}
        )
        assert "_context_error" in payload
        assert "RuntimeError" in payload["_context_error"]


# ---------------------------------------------------------------------------
# [dead_code/low] build_session_resume signature
# ---------------------------------------------------------------------------


class TestBuildSessionResumeSignature:
    def test_build_session_resume_builds_without_blackboard_entries(self, host):
        b = _session_b()
        mgr = _FakeSessionMgr([b])
        resume = build_session_resume(mgr, b.session_id)
        assert resume is not None
        assert resume.get("pending_hypotheses")

    def test_dead_blackboard_entries_parameter_removed(self, host):
        b = _session_b()
        mgr = _FakeSessionMgr([b])
        with pytest.raises(TypeError):
            build_session_resume(mgr, b.session_id, [])
