#!/usr/bin/env python3
"""
Token-bucket rate limiting for MCP tool calls.

Two scopes:
  - Per-tool: each tool gets its own bucket (prevents one tool from monopolizing)
  - Global: shared bucket across all tools (prevents total overload)
"""
from __future__ import annotations

import os
import threading
import time

from ..config import RATE_LIMIT_BURST, RATE_LIMIT_GLOBAL, RATE_LIMIT_PER_TOOL


class TokenBucket:
    """Thread-safe token bucket."""

    def __init__(self, rate: float, burst: int):
        self.rate = float(rate)      # tokens per second
        self.burst = int(burst)      # max tokens
        self.tokens = float(burst)   # current tokens
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> tuple[bool, float]:
        """Try to acquire tokens. Returns (ok, wait_seconds)."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            if self.rate <= 0:
                # Rate of 0 means "never refill": once the initial burst is
                # spent the bucket stays empty. Avoid the ZeroDivisionError and
                # return a clean denial (the caller formats it as RATE_LIMIT).
                return False, float("inf")
            wait = (tokens - self.tokens) / self.rate
            return False, wait

    def return_tokens(self, tokens: float = 1.0) -> None:
        """Return unconsumed tokens (thread-safe)."""
        with self._lock:
            self.tokens = min(self.burst, self.tokens + tokens)


class RateLimiter:
    """
    Rate limiter with per-tool and global buckets.

    Default: 10 calls/sec per tool, 30 calls/sec globally.
    Configurable via env vars:
      IDA_MCP_RATE_LIMIT_PER_TOOL  (default 10)
      IDA_MCP_RATE_LIMIT_GLOBAL    (default 30)
      IDA_MCP_RATE_LIMIT_BURST     (default 20)
    """

    def __init__(
        self,
        per_tool_rate: float | None = None,
        global_rate: float | None = None,
        burst: int | None = None,
    ):
        # Allow tests to disable rate limiting
        if os.environ.get("IDA_MCP_DISABLE_RATE_LIMIT") == "1":
            self.per_tool_rate = float("inf")
            self.global_rate = float("inf")
            self.burst = 999999
        else:
            # `is not None` (not `or`): an explicit 0 is a legitimate operator
            # choice (hard-block a tool) and must not be replaced by the default.
            self.per_tool_rate = (
                per_tool_rate if per_tool_rate is not None else RATE_LIMIT_PER_TOOL
            )
            self.global_rate = (
                global_rate if global_rate is not None else RATE_LIMIT_GLOBAL
            )
            self.burst = burst if burst is not None else RATE_LIMIT_BURST
        self._tool_buckets: dict[str, TokenBucket] = {}
        self._global_bucket = TokenBucket(self.global_rate, self.burst)
        self._lock = threading.Lock()

    def _get_tool_bucket(self, tool: str) -> TokenBucket:
        with self._lock:
            if tool not in self._tool_buckets:
                self._tool_buckets[tool] = TokenBucket(self.per_tool_rate, self.burst)
            return self._tool_buckets[tool]

    def check(self, tool: str) -> tuple[bool, str]:
        """
        Check if call is allowed. Returns (allowed, reason).
        If not allowed, reason explains which limit was hit.
        """
        # Check per-tool first (avoids returning tokens to global bucket)
        bucket = self._get_tool_bucket(tool)
        ok, wait = bucket.acquire()
        if not ok:
            return False, f"rate limit for tool '{tool}' ({self.per_tool_rate}/s); wait {wait:.1f}s"
        # Check global
        ok, wait = self._global_bucket.acquire()
        if not ok:
            bucket.return_tokens()
            return False, f"global rate limit ({self.global_rate}/s); wait {wait:.1f}s"
        return True, ""

    def stats(self) -> dict[str, any]:
        """Current bucket levels for diagnostics."""
        out = {
            "global": {
                "rate": self.global_rate,
                "burst": self.burst,
                "tokens": round(self._global_bucket.tokens, 2),
            },
            "per_tool_rate": self.per_tool_rate,
        }
        with self._lock:
            for tool, bucket in self._tool_buckets.items():
                out[tool] = {"tokens": round(bucket.tokens, 2)}
        return out
