"""Rate-limit configuration validation at the public limiter boundary."""

from __future__ import annotations

import math

import pytest

from ida_pro_mcp.host.server.rate_limit import RateLimiter


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"per_tool_rate": -1.0}, "rate must be a non-negative number"),
        ({"global_rate": float("nan")}, "rate must be a non-negative number"),
        ({"burst": 0}, "burst must be positive"),
    ],
)
def test_rate_limiter_rejects_invalid_programmatic_limits(monkeypatch, kwargs, message):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)
    with pytest.raises(ValueError, match=message):
        RateLimiter(**kwargs)


def test_rate_limiter_retains_supported_zero_and_unlimited_rates(monkeypatch):
    monkeypatch.delenv("IDA_MCP_DISABLE_RATE_LIMIT", raising=False)

    blocked = RateLimiter(per_tool_rate=0.0, global_rate=1.0, burst=1)
    assert blocked.check("search")[0] is True
    assert blocked.check("search")[0] is False

    unlimited = RateLimiter(per_tool_rate=math.inf, global_rate=math.inf, burst=1)
    assert unlimited.check("search")[0] is True
    assert unlimited.check("search")[0] is True
