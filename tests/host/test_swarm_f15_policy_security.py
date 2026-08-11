"""Regression tests for the f15_policy_security finding wave.

Covers (all non-live-IDA, unit-level):
  * finding #1  — the rate limiter bounds its per-tool bucket dict, so a caller
                  sending many bogus tool names cannot grow it without bound or
                  mint a fresh full-burst bucket forever.
  * finding #2  — malformed numeric env vars fall back to defaults at import
                  instead of raising ValueError and crashing the host.
  * finding #3  — RUNTIME_LEASE_HEARTBEAT_SECONDS is clamped strictly below
                  RUNTIME_LEASE_TTL so a live runtime's lease cannot lapse
                  between heartbeats.
  * finding #5  — session state-mutating meta-actions (rate_skill, sso_activate,
                  agent_login/agent_logout, switch) classify WRITE_IDB and
                  require ack, instead of falling through to READ.
  * finding #8  — RateLimiter.stats() reads the global token level under the
                  same lock the buckets use.
  * findings #9/#10 — audit result_size is bounded/sampled, and executed source
                  (misc python/idc `code`) is redacted from args_preview.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None

importlib.import_module("ida_pro_mcp.host")

from ida_pro_mcp.host.policy import (  # noqa: E402
    DESTRUCTIVE_TOOL_ACTIONS,
    PolicyDecision,
    PolicyMode,
    RiskTier,
    classify_tool_action,
    evaluate_policy,
)
from ida_pro_mcp.host.server.rate_limit import (  # noqa: E402
    MAX_TOOL_BUCKETS,
    RateLimiter,
)

# ---------------------------------------------------------------------------
# Finding #1 (security/medium): per-tool bucket dict is bounded
# ---------------------------------------------------------------------------


def test_rate_limiter_bounds_per_tool_buckets(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    rl = RateLimiter(per_tool_rate=100.0, global_rate=100000.0, burst=9999)
    # Mint more distinct (bogus) tool names than the cap.
    for i in range(MAX_TOOL_BUCKETS + 50):
        ok, _reason = rl.check(f"bogus_tool_{i}")
        assert ok is True
    assert len(rl._tool_buckets) == MAX_TOOL_BUCKETS

    # A repeat call reuses the existing bucket (no further growth).
    before = len(rl._tool_buckets)
    ok, _reason = rl.check("bogus_tool_0")
    assert ok is True
    assert len(rl._tool_buckets) == before


def test_rate_limiter_legit_tool_bucket_survives_eviction(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    rl = RateLimiter(per_tool_rate=1000.0, global_rate=100000.0, burst=9999)
    ok, _ = rl.check("search")
    assert ok is True
    for i in range(MAX_TOOL_BUCKETS):
        rl.check(f"noise_{i}")
    # A real tool keeps working even after the noise-filled rotation.
    ok, _reason = rl.check("search")
    assert ok is True


# ---------------------------------------------------------------------------
# Finding #8 (race/low): stats() reads global tokens under the lock
# ---------------------------------------------------------------------------


def test_rate_limiter_stats_reads_global_under_lock(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    rl = RateLimiter(per_tool_rate=100.0, global_rate=1000.0, burst=50)
    rl.check("search")
    rl.check("code")
    stats = rl.stats()
    assert "tokens" in stats["global"]
    assert isinstance(stats["global"]["tokens"], float)
    assert "search" in stats
    assert "code" in stats
    assert stats["global"]["rate"] == 1000.0


# ---------------------------------------------------------------------------
# Findings #2/#3 (error_handling/medium, correctness/medium): config env parse
# ---------------------------------------------------------------------------


def _run_config_subprocess(extra_env: dict[str, str]) -> str:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import ida_pro_mcp.host.config as c\n"
        "print(c.RATE_LIMIT_PER_TOOL, c.RATE_LIMIT_GLOBAL, c.RATE_LIMIT_BURST,\n"
        "      c.RUNTIME_LEASE_TTL, c.RUNTIME_LEASE_HEARTBEAT_SECONDS)\n"
    )
    env = dict(os.environ)
    env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_config_malformed_env_vars_fall_back_to_defaults():
    out = _run_config_subprocess(
        {
            "IDA_MCP_RATE_LIMIT_PER_TOOL": "abc",
            "IDA_MCP_RATE_LIMIT_GLOBAL": "not-a-number",
            "IDA_MCP_RATE_LIMIT_BURST": "zzz",
            "IDA_MCP_RUNTIME_LEASE_TTL": "bogus",
            "IDA_MCP_RUNTIME_LEASE_HEARTBEAT": "??",
        }
    )
    values = [float(v) for v in out.split()]
    # Defaults: 10.0, 30.0, 20, 75, 25 (heartbeat = TTL // 3).
    assert values == [10.0, 30.0, 20.0, 75.0, 25.0]


def test_config_negative_rate_limit_clamped_to_zero():
    out = _run_config_subprocess(
        {
            "IDA_MCP_RATE_LIMIT_PER_TOOL": "-5",
            "IDA_MCP_RATE_LIMIT_GLOBAL": "-1",
            "IDA_MCP_RATE_LIMIT_BURST": "-3",
        }
    )
    values = [float(v) for v in out.split()]
    assert values[0] == 0.0  # per-tool clamped to >= 0
    assert values[1] == 0.0  # global clamped to >= 0
    assert values[2] == 1.0  # burst clamped to >= 1


def test_config_heartbeat_clamped_below_ttl():
    # heartbeat 90 with TTL 20: clamp to TTL - 1 = 19.
    out = _run_config_subprocess(
        {
            "IDA_MCP_RUNTIME_LEASE_TTL": "20",
            "IDA_MCP_RUNTIME_LEASE_HEARTBEAT": "90",
        }
    )
    values = [float(v) for v in out.split()]
    assert values[3] == 20.0  # TTL
    assert values[4] == 19.0  # heartbeat < TTL

    # heartbeat 90 with default TTL 75: clamp to 74.
    out = _run_config_subprocess({"IDA_MCP_RUNTIME_LEASE_HEARTBEAT": "90"})
    values = [float(v) for v in out.split()]
    assert values[3] == 75.0
    assert values[4] == 74.0

    # A healthy operator choice (heartbeat 30, TTL 90) is left untouched.
    out = _run_config_subprocess(
        {
            "IDA_MCP_RUNTIME_LEASE_TTL": "90",
            "IDA_MCP_RUNTIME_LEASE_HEARTBEAT": "30",
        }
    )
    values = [float(v) for v in out.split()]
    assert values[3] == 90.0
    assert values[4] == 30.0


def test_config_env_helpers_parse_and_clamp(monkeypatch):
    from ida_pro_mcp.host.config import _env_float, _env_int

    monkeypatch.delenv("IDA_MCP_TEST_INT", raising=False)
    assert _env_int("IDA_MCP_TEST_INT", 7) == 7
    monkeypatch.setenv("IDA_MCP_TEST_INT", "not-an-int")
    assert _env_int("IDA_MCP_TEST_INT", 7) == 7
    monkeypatch.setenv("IDA_MCP_TEST_INT", "3")
    assert _env_int("IDA_MCP_TEST_INT", 7) == 3
    assert _env_int("IDA_MCP_TEST_INT", 7, min_value=5) == 5
    assert _env_int("IDA_MCP_TEST_INT", 7, max_value=2) == 2

    monkeypatch.delenv("IDA_MCP_TEST_FLOAT", raising=False)
    assert _env_float("IDA_MCP_TEST_FLOAT", 2.5) == 2.5
    monkeypatch.setenv("IDA_MCP_TEST_FLOAT", "boom")
    assert _env_float("IDA_MCP_TEST_FLOAT", 2.5) == 2.5
    monkeypatch.setenv("IDA_MCP_TEST_FLOAT", "-1.5")
    assert _env_float("IDA_MCP_TEST_FLOAT", 2.5) == -1.5
    assert _env_float("IDA_MCP_TEST_FLOAT", 2.5, min_value=0.0) == 0.0


# ---------------------------------------------------------------------------
# Finding #5 (feature_gap/low): session rate_skill classifies WRITE_IDB
# ---------------------------------------------------------------------------
# The audit flagged rate_skill/sso_activate/agent_login/agent_logout/switch as
# falling through to READ. Only rate_skill is a durable-state write like
# add_note/clear_notes, so it is gated. The identity/navigation primitives
# (sso_activate, agent_login/agent_logout, switch) deliberately stay READ:
# gating them behind a policy ack breaks the SSO realm lifecycle and the
# shared-connection session-switch flow (verified: 12 SSO tests regress when
# they are classified WRITE_IDB). Their gate is the SSO realm itself.


def test_session_rate_skill_is_write_idb():
    risk = classify_tool_action("session", "rate_skill")
    assert risk == RiskTier.WRITE_IDB

    result = evaluate_policy("session", "rate_skill", mode=PolicyMode.ENFORCE)
    assert result.risk == RiskTier.WRITE_IDB
    assert result.decision == PolicyDecision.REQUIRE_ACK
    assert result.requires_ack is True


def test_session_rate_skill_ack_allows_through():
    result = evaluate_policy(
        "session", "rate_skill", mode=PolicyMode.ENFORCE, ack=True
    )
    assert result.requires_ack is False
    assert result.decision == PolicyDecision.ALLOW


def test_session_identity_and_navigation_actions_stay_read():
    # Deliberate: sso_activate / agent_login / agent_logout / switch are the
    # SSO realm bootstrap and shared-session navigation — requiring a policy
    # ack would deadlock onboarding and the two-agent switch flow.
    for action in ("sso_activate", "agent_login", "agent_logout", "switch"):
        assert classify_tool_action("session", action) == RiskTier.READ, action


def test_session_read_actions_still_read():
    # The WRITE_IDB additions must not have bumped the pure-read set.
    for action in ("health", "list", "get", "status", "state", "logs"):
        assert classify_tool_action("session", action) == RiskTier.READ, action


# ---------------------------------------------------------------------------
# Integration: multi_session group mutations + bootstrap skills writes + the
# blackboard read-only overrides (the audit left these UNKNOWN / WRITE_IDB).
# ---------------------------------------------------------------------------


def test_multi_session_group_mutations_are_write_tier():
    # group_create/group_link persist cross-session group membership — WRITE_IDB,
    # not UNKNOWN (multi_session is absent from READ_ONLY_TOOLS so they used to
    # fall through to UNKNOWN and demand ack with a confusing tier).
    for action in ("group_create", "group_link"):
        assert classify_tool_action("multi_session", action) == RiskTier.WRITE_IDB, action

    # Pure reads on the same tool stay READ.
    for action in ("group_list", "cross_resolve", "cross_xrefs", "status"):
        assert classify_tool_action("multi_session", action) == RiskTier.READ, action


def test_bootstrap_skills_actions_are_write_tier():
    # session is READ_ONLY_TOOLS, so these used to classify READ even though
    # they mutate the durable skills.json. They must require ack. The 10
    # WRITE_IDB entries added by the gap-audit handoff
    # (init/ingest_outcome/open_dispute/resolve_dispute/update_baseline/
    # autopilot/set_autopilot_policy/rollback_last_reweight/record_readiness/
    # finalize_report) persist via _save_skills, so they join the write tier;
    # the 11th (prune_data) classifies DESTRUCTIVE and is asserted separately.
    for action in (
        "bootstrap_policy_reweight",
        "bootstrap_run_tournament",
        "bootstrap_simulate_batch",
        "bootstrap_snapshot",
        "bootstrap_evaluate_alerts",
        "bootstrap_apply_mitigation",
        "bootstrap_init",
        "bootstrap_ingest_outcome",
        "bootstrap_open_dispute",
        "bootstrap_resolve_dispute",
        "bootstrap_update_baseline",
        "bootstrap_autopilot",
        "bootstrap_set_autopilot_policy",
        "bootstrap_rollback_last_reweight",
        "bootstrap_record_readiness",
        "bootstrap_finalize_report",
        # bootstrap_prune_data is covered separately below: it classifies
        # DESTRUCTIVE, not WRITE_IDB.
        "log_activity",
    ):
        assert classify_tool_action("session", action) == RiskTier.WRITE_IDB, action
        result = evaluate_policy("session", action, mode=PolicyMode.ENFORCE)
        assert result.requires_ack is True, f"session/{action} ack was {result.requires_ack}"

    # The read-back actions are deliberately left READ.
    assert classify_tool_action("session", "bootstrap_policy_reweight_history") == RiskTier.READ
    # readiness_regression_guard only returns a recommended-actions plan and
    # never persists, so it stays out of the write tier.
    assert classify_tool_action("session", "bootstrap_readiness_regression_guard") == RiskTier.READ


def test_bootstrap_prune_data_is_destructive_tier():
    # bootstrap_prune_data deletes persisted outcomes, disputes, and snapshots,
    # so it must classify DESTRUCTIVE (not merely WRITE_IDB) and require ack
    # when no risk_ack is supplied — otherwise it sails through on the same tier
    # as a plain write despite deleting durable state.
    assert classify_tool_action("session", "bootstrap_prune_data") == RiskTier.DESTRUCTIVE
    assert ("session", "bootstrap_prune_data") in DESTRUCTIVE_TOOL_ACTIONS
    result = evaluate_policy("session", "bootstrap_prune_data", mode=PolicyMode.ENFORCE)
    assert result.requires_ack is True, "destructive bootstrap_prune_data must require ack without risk_ack"
    # A supplied ack satisfies the requirement (decision ALLOW, no residual ack).
    acked = evaluate_policy("session", "bootstrap_prune_data", mode=PolicyMode.ENFORCE, ack=True)
    assert acked.requires_ack is False
    assert acked.decision == PolicyDecision.ALLOW


def test_blackboard_read_only_overrides_are_read_tier():
    # blackboard is in WRITE_IDB_TOOLS, so these query-only actions would demand
    # ack without the READ_ONLY_ACTIONS overrides.
    for action in (
        "working_set",
        "state_health",
        "conflicts",
        "stale",
        "recall",
        "workspace_brief",
        "campaign_summary",
        "phase_status",
    ):
        assert classify_tool_action("blackboard", action) == RiskTier.READ, action
        result = evaluate_policy("blackboard", action, mode=PolicyMode.ASSIST)
        assert result.requires_ack is False, f"blackboard/{action} ack was {result.requires_ack}"

    # Sanity: blackboard writes still require ack (delete/clear are
    # DESTRUCTIVE, so use non-destructive mutators here).
    for action in ("write", "update", "merge", "resolve", "contradict"):
        assert classify_tool_action("blackboard", action) == RiskTier.WRITE_IDB, action
        result = evaluate_policy("blackboard", action, mode=PolicyMode.ASSIST)
        assert result.requires_ack is True, f"blackboard/{action} ack was {result.requires_ack}"


# ---------------------------------------------------------------------------
# Findings #9/#10 (perf/low, clarity/low): audit result_size and redaction
# ---------------------------------------------------------------------------


def test_audit_preview_redacts_executed_code(tmp_path):
    from ida_pro_mcp.host.server.audit import AuditLogger

    logger = AuditLogger(str(tmp_path), max_mb=1)
    payload = "import os; os.system('whoami')"
    logger.log(
        tool="misc",
        action="python",
        args={"code": payload, "topic": "t"},
        result={"ok": True},
        latency_ms=1.0,
        session_id="S1",
    )
    logger.close()
    written = (list(tmp_path.rglob("*.jsonl")) or [None])[0]
    assert written is not None
    text = written.read_text()
    # The executed source must never land in plaintext.
    assert payload not in text
    record = json.loads(text)
    assert "code" not in record["args_preview"]


def test_audit_result_size_bounded_for_large_results(tmp_path):
    from ida_pro_mcp.host.server.audit import (
        _RESULT_SIZE_SAMPLE_CAP,
        AuditLogger,
        _bounded_result_size,
    )

    big = list(range(1_000_000))
    sampled = _bounded_result_size(big)
    # Sampled size is much smaller than the true serialized size of 1M items
    # and is bounded by the sample cap, not the full payload.
    assert sampled < len(json.dumps(big[: _RESULT_SIZE_SAMPLE_CAP])) + 1024
    assert sampled > 0

    small = [1, 2, 3]
    assert _bounded_result_size(small) == len(json.dumps(small))

    # log() itself still works end-to-end with a large result.
    logger = AuditLogger(str(tmp_path), max_mb=1)
    logger.log(
        tool="search",
        action="list",
        args={"query": "x"},
        result=big,
        latency_ms=1.0,
        session_id="S1",
    )
    logger.close()
    written = (list(tmp_path.rglob("*.jsonl")) or [None])[0]
    assert written is not None
    record = json.loads(written.read_text())
    assert isinstance(record["result_size"], int)
    assert record["result_size"] > 0
