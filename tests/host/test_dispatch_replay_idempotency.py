"""Regression tests for the f03_dispatch finding wave.

Covers (all non-live-IDA, unit-level):
  * finding #2  — next_token continuation replay re-enforces the guardrail
                  strict-write / blackboard-strict / phase-preflight gates that
                  page 1 ran, and the policy ack expression honours a page-1
                  ``_guardrail_ack`` carried in the cached base args.
  * finding #3  — audit / usage-intel attribute a call to the idb-resolved
                  session it actually ran in, not the shared active default.
  * finding #5  — session/health tolerates a failing session-store discovery
                  instead of raising out of the envelope.
  * finding #6  — truncation tokens are scoped to the executed session and
                  _handle_truncation resolves idb the same way.
  * finding #7  — the session LONG_RUNNING_ACTIONS entries are gone (dead).
  * finding #11 — a non-string ``action`` on a tool with a known action list is
                  rejected instead of silently dropped.
  * finding #12 — unparseable int-like field values are rejected instead of
                  silently forwarded to the IDA bridge (schema unions that
                  admit strings are respected).
"""

from __future__ import annotations

import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None

importlib.import_module("ida_pro_mcp.host")

from ida_pro_mcp.host.errors import MCPError, is_error_result  # noqa: E402
from ida_pro_mcp.host.server.server_args import ServerArgsMixin  # noqa: E402
from ida_pro_mcp.host.server.server_dispatch import (  # noqa: E402
    LONG_RUNNING_ACTIONS,
    ServerDispatchMixin,
)


class _Session:
    def __init__(self, sid="active", idb_path="/tmp/active.idb"):
        self.session_id = sid
        self.idb_path = idb_path


# ---------------------------------------------------------------------------
# Shared harness pieces
# ---------------------------------------------------------------------------

class _GuardrailStubs:
    """Minimal host stubs for the response-mixin methods the gates read."""

    def _guardrail_mode_from_args(self, call_args):
        mode = str((call_args or {}).get("_guardrail_mode") or "").strip().lower()
        if mode in {"off", "none"}:
            return "off"
        if mode in {"enforce", "strict"}:
            return "enforce"
        return "assist"

    def _compute_pointer_note_signal(self, tool_name, call_args, payload):
        return 0.0


class _AuditRecorder:
    def __init__(self):
        self.last = None

    def log(self, **kwargs):
        self.last = kwargs


class _RateLimiter:
    def __init__(self, allowed=True, reason=""):
        self._allowed = allowed
        self._reason = reason

    def check(self, tool):
        return self._allowed, self._reason


class _ContinuationHarness(ServerArgsMixin, ServerDispatchMixin, _GuardrailStubs):
    """Harness that drives the real ``_handle_next_continuation`` replay path."""

    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 1800
        self.current_session = _Session()
        self._guardrail_strict_writes = True
        self._calls = []
        self._next_cache_obj = None

    def _policy_baseline_mode(self):
        return "assist"

    def _resolve_session_from_idb_ref(self, ref):
        return None

    def _truncation_owner_id(self):
        return "owner"

    def call_tool(self, tool_name, idb_path, **kwargs):
        self._calls.append((tool_name, idb_path, dict(kwargs)))
        return {"ok": True}

    def _seed_continuation(self, tool, action, args, token="TKN0000000001"):
        self._next_cache[token] = {
            "tool": tool,
            "action": action,
            "args": dict(args),
            "next_offset": 1,
            "session_id": self.current_session.session_id,
            "owner_id": self._truncation_owner_id(),
            "created_at": time.time(),
        }
        return token


# ---------------------------------------------------------------------------
# Finding #2 — continuation replay re-enforces the page-1 gates
# ---------------------------------------------------------------------------

class TestContinuationReplayGates:
    def test_replay_blocks_risky_write_without_guardrail_ack(self):
        h = _ContinuationHarness()
        # Page 1 acked via _risk_ack (so policy allows), but the replayed args
        # carry no _guardrail_ack. Strict guardrails are on: the replay must be
        # blocked by the guardrail gate before it re-executes modify/rename.
        token = h._seed_continuation(
            "modify", "rename", {"_risk_ack": True, "idb": "/tmp/target.idb"}
        )
        res = h._handle_next_continuation("modify", token, {"next_token": token})
        assert is_error_result(res)
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "guardrail" in str(res.get("message", "")).lower()
        # The gate fired before call_tool: the write must not re-execute.
        assert h._calls == []

    def test_replay_guardrail_ack_allows_continuation(self):
        h = _ContinuationHarness()
        # Page 1 acked with only _guardrail_ack=true. Both the policy ack
        # expression (base_args._guardrail_ack) and the guardrail gate must
        # honour it, so the continuation executes.
        token = h._seed_continuation(
            "modify", "rename", {"_guardrail_ack": True, "idb": "/tmp/target.idb"}
        )
        res = h._handle_next_continuation("modify", token, {"next_token": token})
        assert not is_error_result(res)
        assert res.get("ok") is True
        assert res.get("continued_from") == token
        assert h._calls and h._calls[0][0] == "modify"
        assert h._calls[0][1] == "/tmp/target.idb"
        assert h._calls[0][2].get("action") == "rename"

    def test_replay_guardrail_ack_avoids_spurious_policy_denied(self):
        h = _ContinuationHarness()
        h._guardrail_strict_writes = False
        # A caller who acked page 1 with only _guardrail_ack=true must NOT get a
        # spurious POLICY_DENIED on the continuation (the ack expression now
        # includes base_args._guardrail_ack).
        token = h._seed_continuation(
            "modify", "rename", {"_guardrail_ack": True, "idb": "/tmp/target.idb"}
        )
        res = h._handle_next_continuation("modify", token, {"next_token": token})
        assert not is_error_result(res)
        assert res.get("code") != MCPError.POLICY_DENIED

    def test_replay_blackboard_strict_gate(self):
        class _BbHarness(_ContinuationHarness):
            def _bb_policy_bump(self):
                return {"strict_mode": True}

            def _bb_policy_check(self, state):
                return {
                    "ok": False,
                    "reasons": ["no evidence chain"],
                    "recommendation": "build evidence first",
                    "policy": {},
                }

            def _phase_state(self):
                return {"phase": "scout"}

            def _bb_policy_enforced_for_phase(self, state, phase):
                return True

        h = _BbHarness()
        # A READ-tier replay (search/find — no policy ack needed, so policy
        # passes) must still be stopped by the blackboard strict gate when it
        # fires on the continuation path.
        token = h._seed_continuation(
            "search", "find", {"query": "memcpy", "idb": "/tmp/target.idb"}
        )
        res = h._handle_next_continuation("search", token, {"next_token": token})
        assert is_error_result(res)
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "blackboard" in str(res.get("message", "")).lower()
        assert h._calls == []

    def test_guardrail_gate_helper_blocked_and_allowed(self):
        h = _ContinuationHarness()
        blocked = h._guardrail_strict_gate("modify", {"action": "rename"})
        assert blocked is not None
        assert blocked.get("code") == MCPError.INVALID_ARGS
        allowed = h._guardrail_strict_gate(
            "modify", {"action": "rename", "_guardrail_ack": True}
        )
        assert allowed is None
        # Non-risky tool / non-risky action are never gated.
        assert h._guardrail_strict_gate("search", {"action": "find"}) is None
        assert h._guardrail_strict_gate("modify", {"action": "list"}) is None


# ---------------------------------------------------------------------------
# Finding #3 — audit / usage-intel attribute the executed session
# ---------------------------------------------------------------------------

class _ExecToolHarness(ServerArgsMixin, ServerDispatchMixin, _GuardrailStubs):
    def __init__(self):
        self.current_session = _Session("active", "/tmp/active.idb")
        self.audit = _AuditRecorder()
        self._usage_intel = None
        self.rate_limiter = _RateLimiter()
        self._pending_pp = {}
        self._pending_tool_args = {}

    def _resolve_session_from_idb_ref(self, ref):
        if ref == "target":
            return _Session("target", "/tmp/target.idb")
        if ref == "active":
            return self.current_session
        return None

    def _execute_tool_inner(self, tool_name, original_tool_name, args):
        return {"ok": True, "action": "rename"}


class TestExecutedSessionAttribution:
    def test_audit_attributes_to_idb_targeted_session(self):
        h = _ExecToolHarness()
        h._execute_tool("modify", {"action": "rename", "idb": "target"})
        assert h.audit.last is not None
        assert h.audit.last["session_id"] == "target"
        assert h.audit.last["tool"] == "modify"

    def test_audit_falls_back_to_current_session_without_idb(self):
        h = _ExecToolHarness()
        h._execute_tool("modify", {"action": "rename"})
        assert h.audit.last is not None
        assert h.audit.last["session_id"] == "active"

    def test_rate_limit_audit_uses_target_session(self):
        h = _ExecToolHarness()
        h.rate_limiter = _RateLimiter(allowed=False, reason="too many")
        res = h._execute_tool("modify", {"action": "rename", "idb": "target"})
        assert is_error_result(res)
        assert res.get("code") == MCPError.RATE_LIMIT
        assert h.audit.last["session_id"] == "target"
        assert "rate_limited" in h.audit.last["error"]


class _CountingIntel:
    """Fake usage intelligence that counts observe calls."""

    def __init__(self):
        self.calls = []

    def observe(self, tool, action, session_id, **kwargs):
        self.calls.append((tool, action, session_id, kwargs))


class TestUsageObserveExactlyOnce:
    """H2: the dispatch path feeds usage intelligence exactly once per call."""

    def test_execute_tool_observes_once(self):
        h = _ExecToolHarness()
        intel = _CountingIntel()
        h._usage_intel = intel
        res = h._execute_tool("modify", {"action": "rename"})
        assert "error" not in res
        assert len(intel.calls) == 1
        tool, action, sid, kwargs = intel.calls[0]
        assert tool == "modify"
        assert action == "rename"
        assert sid == "active"
        # The rich observation carries latency and error fields.
        assert "latency_ms" in kwargs and "error" in kwargs

    def test_execute_tool_error_result_still_observes_once(self):
        h = _ExecToolHarness()
        intel = _CountingIntel()
        h._usage_intel = intel
        h._execute_tool_inner = lambda tool_name, original_tool_name, args: {
            "error": True,
            "code": "ACTION_NOT_FOUND",
            "message": "nope",
        }
        res = h._execute_tool("modify", {"action": "rename"})
        assert is_error_result(res)
        # The dispatch observe is the rich one and fires for errors too, but
        # only once — _record_activity must not add a second, defaulted call.
        assert len(intel.calls) == 1
        tool, action, sid, kwargs = intel.calls[0]
        assert "error" in kwargs and kwargs["error"]


class TestGadgetsSemanticFindRegistered:
    """H3: gadgets(action='semantic_find') must be a registered, documented,
    READ-classified action (it was reachable via dispatch but absent from
    _TOOL_ACTIONS, the schema enum, and policy -> UNKNOWN tier)."""

    def test_semantic_find_in_gadgets_action_list(self):
        from ida_pro_mcp.host.server.tool_registry import _TOOL_ACTIONS

        assert "semantic_find" in _TOOL_ACTIONS["gadgets"]
        # The schema enum is derived from the same list.
        from ida_pro_mcp.host.schemas_data import TOOL_ARG_SCHEMAS

        action_schema = TOOL_ARG_SCHEMAS["gadgets"]["action"]
        assert "semantic_find" in action_schema["enum"]
        # Its args are admitted by the gadgets arg schema.
        for key in ("query", "source_actions", "limit", "offset", "min_score",
                    "source_limit", "max_insns", "rebuild_index"):
            assert key in TOOL_ARG_SCHEMAS["gadgets"], key

    def test_semantic_find_classifies_read(self):
        from ida_pro_mcp.host.policy import RiskTier, classify_tool_action

        assert classify_tool_action("gadgets", "semantic_find") == RiskTier.READ

    def test_dispatch_routes_gadgets_semantic_find(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "src" / "ida_pro_mcp" / "host" / "server" / "server_dispatch.py"
        ).read_text(encoding="utf-8")
        assert 'tool_name == "gadgets"' in source
        assert "_handle_gadgets_semantic_find" in source


# ---------------------------------------------------------------------------
# Finding #5 — session/health must not raise on a failing session store
# ---------------------------------------------------------------------------

class _HealthHarness(ServerDispatchMixin):
    def __init__(self):
        self._runtime_lock = threading.Lock()
        self.session_runtimes = {}
        self._session_inflight_calls = {}
        self.cache_dir = "/tmp/nonexistent-cache-dir-xyz"
        self.ida_dir = "/tmp/nonexistent-ida-dir-xyz"
        self.idat_exe = ""
        self.current_session = None

    def _resolve_wiki_root(self):
        return None


class _BrokenStore:
    def discover_sessions(self):
        raise OSError("session store is corrupt")


class _HappyStore:
    def __init__(self, n):
        self._n = n

    def discover_sessions(self):
        return [object() for _ in range(self._n)]


class TestSessionHealthResilience:
    def test_health_survives_discover_failure(self):
        h = _HealthHarness()
        h.session_mgr = _BrokenStore()
        payload = h._handle_session_health({})
        assert payload.get("ok") is True
        assert payload["sessions"]["total"] == 0
        assert payload["sessions"]["discovery_error"] == "session store is corrupt"

    def test_health_reports_total_on_success(self):
        h = _HealthHarness()
        h.session_mgr = _HappyStore(3)
        payload = h._handle_session_health({})
        assert payload["sessions"]["total"] == 3
        assert payload["sessions"]["discovery_error"] is None


# ---------------------------------------------------------------------------
# Finding #6 — truncation tokens scoped to the executed session
# ---------------------------------------------------------------------------

class _TruncationHarness(ServerDispatchMixin):
    def __init__(self):
        self.current_session = _Session("active", "/tmp/active.idb")

    def _truncation_owner_id(self):
        return "owner"

    def _resolve_session_from_idb_ref(self, ref):
        if ref == "target":
            return _Session("target", "/tmp/target.idb")
        return None


class TestTruncationSessionScoping:
    def test_handle_truncation_resolves_idb_target(self, monkeypatch):
        captured = {}

        def fake_continue(token, **kwargs):
            captured.update(kwargs)
            return {"ok": True}

        # _handle_truncation imports continue_truncated from ..stores.truncation
        # at call time, so patching the store module intercepts the dispatch.
        import ida_pro_mcp.host.stores.truncation as truncation_store
        monkeypatch.setattr(truncation_store, "continue_truncated", fake_continue)

        h = _TruncationHarness()
        res = h._handle_truncation(
            {"action": "continue", "token": "ABC123", "idb": "target"}
        )
        assert res.get("ok") is True
        assert captured["session_id"] == "target"

    def test_handle_truncation_falls_back_to_current_session(self, monkeypatch):
        captured = {}

        def fake_continue(token, **kwargs):
            captured.update(kwargs)
            return {"ok": True}

        import ida_pro_mcp.host.stores.truncation as truncation_store
        monkeypatch.setattr(truncation_store, "continue_truncated", fake_continue)

        h = _TruncationHarness()
        res = h._handle_truncation({"action": "continue", "token": "ABC123"})
        assert res.get("ok") is True
        assert captured["session_id"] == "active"


# ---------------------------------------------------------------------------
# Finding #7 — dead session LONG_RUNNING_ACTIONS entries removed
# ---------------------------------------------------------------------------

class TestLongRunningActions:
    def test_session_actions_are_not_whitelisted(self):
        assert ("session", "idle_purge") not in LONG_RUNNING_ACTIONS
        assert ("session", "cleanup_stale") not in LONG_RUNNING_ACTIONS


# ---------------------------------------------------------------------------
# Finding #11 — non-string action rejected when a known action list exists
# ---------------------------------------------------------------------------

class _ArgsHarness(ServerArgsMixin):
    pass


class TestNonStringAction:
    def test_non_string_action_rejected_with_valid_actions(self):
        h = _ArgsHarness()
        res = h._normalize_tool_call_args("funcs", {"action": 123})
        assert is_error_result(res)
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "action" in str(res.get("message", "")).lower()

    def test_string_action_still_normalizes(self):
        h = _ArgsHarness()
        res = h._normalize_tool_call_args("funcs", {"action": "metrics"})
        assert not is_error_result(res)
        assert res.get("action") == "metrics"

    def test_non_string_action_passthrough_when_no_action_list(self):
        h = _ArgsHarness()
        # Tools with no registered action list stay lenient (open tools).
        res = h._normalize_tool_call_args("no_such_tool", {"action": 123})
        assert not is_error_result(res)
        assert res.get("action") == 123


# ---------------------------------------------------------------------------
# Finding #12 — unparseable int-like fields rejected (schema unions respected)
# ---------------------------------------------------------------------------

class TestIntFieldCoercion:
    def test_unparseable_int_like_rejected(self):
        h = _ArgsHarness()
        res = h._normalize_tool_call_args("search", {"action": "find", "limit": "abc"})
        assert is_error_result(res)
        assert res.get("code") == MCPError.INVALID_ARGS
        assert "limit" in str(res.get("message", ""))

    def test_hex_and_decimal_strings_still_coerce(self):
        h = _ArgsHarness()
        res = h._normalize_tool_call_args("search", {"action": "find", "limit": "0x10"})
        assert not is_error_result(res)
        assert res["limit"] == 16
        res = h._normalize_tool_call_args("search", {"action": "find", "limit": "10"})
        assert not is_error_result(res)
        assert res["limit"] == 10

    def test_string_union_fields_keep_raw_string(self):
        # session baseaddr/start_ea are typed 'string'|'integer': a non-numeric
        # string must be preserved, not rejected.
        h = _ArgsHarness()
        res = h._normalize_tool_call_args(
            "session", {"action": "create", "baseaddr": "0x400000"}
        )
        assert not is_error_result(res)
        assert res["baseaddr"] == 0x400000
        res = h._normalize_tool_call_args(
            "session", {"action": "create", "baseaddr": "not-a-number"}
        )
        assert not is_error_result(res)
        assert res["baseaddr"] == "not-a-number"
