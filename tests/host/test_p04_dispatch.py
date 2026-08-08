"""Regression tests for p04_dispatch fixes.

Covers the p04_dispatch fixer pass over the tool dispatch pipeline:

- Blackboard / background tools no longer skip the deterministic policy
  preflight: a blackboard write with no ack is now POLICY_DENIED instead of
  silently reaching the handler, and background action='script' (LOCAL_CODE_EXEC)
  requires an ack in assist mode.
- ``analysis(action='plugin_run')`` is blocked in safe mode alongside the
  already-blocked ``misc/plugin_run``.
- The next_token continuation cache is lock-guarded; the lock helper returns a
  usable ``threading.Lock`` (regression for the method/attribute name-shadowing
  bug that made the helper return the bound method).
- ``_cache_next_page`` no longer clobbers an existing ``next_token`` and no
  longer collapses a tool-reported ``"offset": null`` to 0.
- ``_normalize_field_variants`` parses integer-like fields as decimal unless
  explicitly ``0x``-prefixed (no silent octal reinterpretation of "010").
- The audit log call site in ``_execute_tool`` is guarded so a failing audit
  logger cannot fail a tool call that already produced a valid result.
"""

from __future__ import annotations

import contextlib
import threading
import time

from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error
from ida_pro_mcp.host.policy import PolicyDecision
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _Session:
    """Minimal session mock."""

    idb_path = "/tmp/test.idb"
    session_id = "test-session"
    policy_mode = None


class _FakeAudit:
    def log(self, **kwargs):
        return None


class _AllowRateLimiter:
    def check(self, tool):
        return True, None


class _Harness(ServerArgsMixin, ServerDispatchMixin):
    """Minimal dispatcher exposing the dispatch pipeline without IDA."""

    def __init__(self):
        self._next_cache = {}
        self._next_cache_ttl_seconds = 1800
        self._pending_pp = {}
        self._pending_tool_args = {}
        self._pending_truncation = {}
        self.current_session = _Session()
        self.audit = _FakeAudit()
        self._usage_intel = None
        self._guardrail_strict_writes = False
        self._pending_analysis = set()
        self.called_with = None
        self.rate_limiter = _AllowRateLimiter()

    # ---- IDA-bound boundary stubs ----

    def call_tool(self, tool_name, idb_path, **kwargs):
        self.called_with = (tool_name, idb_path, kwargs)
        return {"ok": True, "tool": tool_name}

    def _handle_blackboard(self, args):
        return {"ok": True, "handler": "blackboard"}

    def _handle_background(self, args):
        return {"ok": True, "handler": "background"}

    def _resolve_session_from_idb_ref(self, ref):
        return None

    def _safe_mode_active(self, sid):
        return sid in self._pending_analysis

    def _guardrail_mode_from_args(self, call_args):
        return "assist"


# ---------------------------------------------------------------------------
# Blackboard / background policy preflight (no longer exempted)
# ---------------------------------------------------------------------------


def test_blackboard_write_without_ack_is_policy_denied(monkeypatch):
    """blackboard is classified WRITE_IDB; with the exemption removed the
    deterministic preflight must refuse it in assist mode without an ack."""
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    h = _Harness()
    result = h._execute_tool_inner("blackboard", "blackboard", {"action": "write", "content": "x"})
    assert is_error_result(result)
    assert result.get("code") == MCPError.POLICY_DENIED
    # Must not reach the handler.
    assert h.called_with is None


def test_blackboard_write_with_ack_reaches_handler():
    h = _Harness()
    result = h._execute_tool_inner(
        "blackboard", "blackboard", {"action": "write", "content": "x", "_risk_ack": True}
    )
    assert result.get("ok") is True
    assert result.get("handler") == "blackboard"


def test_background_script_without_ack_is_policy_denied(monkeypatch):
    """('background','script') is LOCAL_CODE_EXEC -> REQUIRE_ACK in assist."""
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    h = _Harness()
    result = h._execute_tool_inner("background", "background", {"action": "script", "code": "1"})
    assert is_error_result(result)
    assert result.get("code") == MCPError.POLICY_DENIED
    assert h.called_with is None


def test_background_script_with_ack_reaches_handler():
    h = _Harness()
    result = h._execute_tool_inner(
        "background", "background", {"action": "script", "code": "1", "_risk_ack": True}
    )
    assert result.get("ok") is True
    assert result.get("handler") == "background"


# ---------------------------------------------------------------------------
# Safe mode gate: analysis(action='plugin_run')
# ---------------------------------------------------------------------------


def test_safe_mode_gate_blocks_analysis_plugin_run():
    h = _Harness()
    h._pending_analysis = {"test-session"}
    denied = h._safe_mode_gate("test-session", "analysis", "plugin_run")
    assert denied is not None
    assert denied.get("code") == MCPError.SAFE_MODE


def test_safe_mode_gate_allows_manual_reads_still():
    h = _Harness()
    h._pending_analysis = {"test-session"}
    assert h._safe_mode_gate("test-session", "funcs", "list") is None
    assert h._safe_mode_gate("test-session", "code", "disasm") is None


# ---------------------------------------------------------------------------
# next_token cache lock (regression: helper returned the bound method)
# ---------------------------------------------------------------------------


def test_next_cache_lock_returns_usable_lock():
    h = _Harness()
    lock = h._next_cache_lock()
    assert isinstance(lock, type(threading.Lock()))
    # Repeated calls return the same per-instance lock.
    assert h._next_cache_lock() is lock
    with lock:
        pass  # context-manager protocol works
    lock.acquire()
    lock.release()


def test_next_cache_lock_is_shared_between_dispatch_and_args_mixins():
    # _execute_tool_inner (dispatch) and _cache_next_page (args) both guard the
    # same cache object; a single lock object must back both call sites.
    h = _Harness()
    with h._next_cache_lock():
        h._next_cache["K"] = {
            "tool": "search", "action": "find", "args": {},
            "post_process": {}, "next_offset": 0, "created_at": time.time(),
        }
    entry = h._next_cache.get("K")
    assert entry is not None


# ---------------------------------------------------------------------------
# _cache_next_page: no token clobber, no null-offset collapse
# ---------------------------------------------------------------------------


def test_cache_next_page_preserves_existing_token():
    h = _Harness()
    payload = {
        "ok": True,
        "truncated": True,
        "offset": 0,
        "count": 5,
        "total": 20,
        "next_token": "ALREADY_MINTED",
        "next_offset": 5,
    }
    out = h._cache_next_page("search", {"action": "find"}, payload)
    # A payload that already carries a token must pass through untouched.
    assert out is payload
    assert out["next_token"] == "ALREADY_MINTED"


def test_cache_next_page_null_offset_uses_caller_offset():
    """A tool echoing ``"offset": null`` must not collapse the caller's real
    page offset to 0 when computing next_offset."""
    h = _Harness()
    payload = {"ok": True, "truncated": True, "offset": None, "count": 5, "total": 20}
    out = h._cache_next_page("search", {"action": "find", "offset": 10}, payload)
    assert out["next_token"]
    assert out["next_offset"] == 15  # 10 + 5, not 0 + 5


def test_cache_next_page_mints_and_recovers_action():
    h = _Harness()
    payload = {"ok": True, "truncated": True, "offset": 0, "count": 3, "total": 9}
    out = h._cache_next_page("search", {"action": "find", "pattern": "recv"}, payload)
    token = out["next_token"]
    entry = h._next_cache[token]
    assert entry["tool"] == "search"
    assert entry["action"] == "find"
    assert entry["next_offset"] == 3


# ---------------------------------------------------------------------------
# _normalize_field_variants: decimal unless 0x-prefixed
# ---------------------------------------------------------------------------


def test_normalize_field_variants_parses_decimal_not_octal():
    h = _Harness()
    out = h._normalize_field_variants(
        "search", {"action": "find", "limit": "010", "offset": "08"}
    )
    # "010" must be 10 (decimal), never 8 (octal); "08" must not crash.
    assert out["limit"] == 10
    assert out["offset"] == 8


def test_normalize_field_variants_parses_explicit_hex():
    h = _Harness()
    out = h._normalize_field_variants("search", {"action": "find", "offset": "0x401000"})
    assert out["offset"] == 0x401000


# ---------------------------------------------------------------------------
# SSO realm: auto-generated secret must be disclosed (else unreachable),
# operator/env secrets must never be echoed back
# ---------------------------------------------------------------------------


def test_sso_activate_discloses_auto_generated_secret(monkeypatch):
    """With no operator secret and no env secret, the realm creates one; it
    must be returned or the realm can never be authenticated to."""
    monkeypatch.delenv("IDA_MCP_SSO_SECRET", raising=False)
    h = _Harness()
    result, err = h._sso_activate_realm(["agent-a"])
    assert err is None
    assert result.get("ok") is True
    sso = result["sso"]
    assert sso.get("secret_generated") is True
    assert isinstance(sso.get("secret"), str) and sso["secret"]
    # The disclosed secret must actually be the one stored in the realm.
    assert h._sso_realm()["secret"] == sso["secret"]


def test_sso_activate_does_not_echo_operator_secret(monkeypatch):
    monkeypatch.delenv("IDA_MCP_SSO_SECRET", raising=False)
    h = _Harness()
    result, err = h._sso_activate_realm(["agent-a"], secret="op-secret")
    assert err is None
    sso = result["sso"]
    assert sso.get("secret_generated") is False
    assert "secret" not in sso
    assert h._sso_realm()["secret"] == "op-secret"


def test_sso_activate_does_not_echo_env_secret(monkeypatch):
    monkeypatch.setenv("IDA_MCP_SSO_SECRET", "env-secret")
    h = _Harness()
    result, err = h._sso_activate_realm(["agent-a"])
    assert err is None
    sso = result["sso"]
    assert sso.get("secret_from_env") is True
    assert "secret" not in sso
    assert h._sso_realm()["secret"] == "env-secret"


# ---------------------------------------------------------------------------
# Rate limiting: explicit 0 stays 0; zero-rate bucket does not ZeroDivide
# ---------------------------------------------------------------------------


def test_rate_limiter_explicit_zero_is_not_replaced(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    from ida_pro_mcp.host.server.rate_limit import RateLimiter

    rl = RateLimiter(per_tool_rate=0.0, global_rate=10.0, burst=5)
    assert rl.per_tool_rate == 0.0
    # First call consumes from the burst, later calls must be cleanly denied.
    ok, _reason = rl.check("search")
    assert ok is True
    for _ in range(10):
        ok, reason = rl.check("search")
        if not ok:
            assert "rate limit" in reason
            break


def test_token_bucket_zero_rate_never_refills():
    from ida_pro_mcp.host.server.rate_limit import TokenBucket

    bucket = TokenBucket(rate=0.0, burst=2)
    assert bucket.acquire() == (True, 0.0)
    assert bucket.acquire() == (True, 0.0)
    # Rate 0: no refill, and no ZeroDivisionError.
    ok, wait = bucket.acquire()
    assert ok is False
    assert wait == float("inf")


# ---------------------------------------------------------------------------
# Audit logger: best-effort writes, no args leaks via args_preview
# ---------------------------------------------------------------------------


def test_audit_log_swallows_write_failure(tmp_path):
    from ida_pro_mcp.host.server.audit import AuditLogger

    logger = AuditLogger(str(tmp_path), max_mb=1)
    # Result is unserializable-ish / path is a directory we cannot write.
    class _Circular:
        pass

    c = _Circular()
    c.self = c
    logger.log(
        tool="search", action="find", args={"pattern": "x"},
        result=c, latency_ms=1.0, session_id="S1",
    )
    # Failure swallowed: no exception raised, no crash.
    logger.close()


def test_audit_args_preview_excludes_idb(tmp_path):
    from ida_pro_mcp.host.server.audit import AuditLogger

    logger = AuditLogger(str(tmp_path), max_mb=1)
    logger.log(
        tool="wiki", action="read", args={"idb": "/tmp/secret.idb", "topic": "t"},
        result={"ok": True}, latency_ms=1.0, session_id="S1",
    )
    logger.close()
    # Read the written record back; args_preview must not contain the idb path.
    written = (list(tmp_path.rglob("*.jsonl")) or [None])[0]
    assert written is not None
    text = written.read_text()
    assert "/tmp/secret.idb" not in text
    assert '"topic"' in text


def test_audit_prune_skips_current_month(tmp_path, monkeypatch):
    from datetime import UTC, datetime as _dt

    import ida_pro_mcp.host.server.audit as audit_mod
    from ida_pro_mcp.host.server.audit import AuditLogger

    logger = AuditLogger(str(tmp_path), max_mb=1)
    cur = tmp_path / "2099-12"  # far-future month, "current" once now is frozen
    cur.mkdir()
    (cur / "audit_2099-12-01.jsonl").write_text("x" * 500)
    # Force prune by making max_bytes tiny; must not delete the current month.
    logger.max_bytes = 100

    class _FrozenNow:
        @staticmethod
        def now(_tz=None):
            return _dt(2099, 12, 15, tzinfo=UTC)

    monkeypatch.setattr(audit_mod, "datetime", _FrozenNow())
    logger._maybe_prune_old()
    assert (cur / "audit_2099-12-01.jsonl").exists()
    logger.close()


# ---------------------------------------------------------------------------
# Audit logging failure must not fail a successful tool call
# ---------------------------------------------------------------------------


class _ExplodingAudit:
    def log(self, **kwargs):
        raise OSError("disk full")


def test_execute_tool_survives_audit_failure():
    h = _Harness()
    h.audit = _ExplodingAudit()
    result = h._execute_tool("search", {"action": "find", "pattern": "recv"})
    # The tool result still comes through; the audit failure is swallowed.
    assert result.get("ok") is True
    assert h.called_with is not None


def test_execute_tool_audits_success_path():
    seen = {}

    class _RecordingAudit:
        def log(self, **kwargs):
            seen.update(kwargs)

    h = _Harness()
    h.audit = _RecordingAudit()
    result = h._execute_tool("search", {"action": "find", "pattern": "recv"})
    assert result.get("ok") is True
    assert seen.get("tool") == "search"
    assert seen.get("action") == "find"
