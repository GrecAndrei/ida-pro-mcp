"""Deterministic boundary coverage for the host token buckets."""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.server import rate_limit


def test_token_bucket_reports_precise_wait_when_partially_refilled(monkeypatch):
    clock = iter((100.0, 100.0, 100.25))
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: next(clock))

    bucket = rate_limit.TokenBucket(rate=2.0, burst=1)
    assert bucket.acquire() == (True, 0.0)
    allowed, wait = bucket.acquire()

    assert allowed is False
    assert wait == pytest.approx(0.25)


def test_token_bucket_refund_is_capped_at_burst():
    bucket = rate_limit.TokenBucket(rate=1.0, burst=2)

    assert bucket.acquire(2.0) == (True, 0.0)
    bucket.return_tokens(10.0)

    assert bucket.tokens == 2.0


def test_global_rejection_refunds_the_per_tool_reservation(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    limiter = rate_limit.RateLimiter(per_tool_rate=100.0, global_rate=0.0, burst=1)

    assert limiter.check("first-tool")[0] is True
    allowed, reason = limiter.check("second-tool")

    assert allowed is False
    assert reason.startswith("global rate limit")
    assert limiter.stats()["second-tool"]["tokens"] == pytest.approx(1.0)


def test_refund_handles_existing_and_unknown_tools(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    limiter = rate_limit.RateLimiter(per_tool_rate=100.0, global_rate=100.0, burst=1)

    assert limiter.check("search")[0] is True
    limiter.refund("search")
    limiter.refund(None)

    stats = limiter.stats()
    assert stats["search"]["tokens"] == pytest.approx(1.0)
    assert stats["global"]["tokens"] == pytest.approx(1.0)
