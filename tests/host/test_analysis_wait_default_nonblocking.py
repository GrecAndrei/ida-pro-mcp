"""Regression: analysis/wait host handler must default to non-blocking.

The host's ``_handle_analysis_wait`` used to default ``max_wait=300`` (5 minutes)
when no caller argument was passed. This caused the smoke runner to time out at
its 120s per-call budget on a binary whose auto-analysis was still running
(host would keep polling past the smoke deadline).

The fix: when the caller passes no `max_wait`/`timeout`, the host performs ONE
status check and returns immediately. The caller is responsible for explicitly
requesting a wait window if they want polling behavior.

These tests pin that contract.
"""
import os
import sys
from unittest.mock import Mock, patch

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin  # noqa: E402
from ida_pro_mcp.services import MCPError, Session  # noqa: E402


def _session() -> Session:
    return Session(
        session_id="A1B2C3D4",
        idb_path="/tmp/a.i64",
        binary_path="/tmp/a.bin",
    )


class _Host(ServerDispatchMixin):
    """Minimal host stand-in exercising only _handle_analysis_wait."""

    def __init__(self):
        self.current_session = _session()
        self.session_runtimes = {
            "A1B2C3D4": {
                "process": Mock(),
                "port": 9999,
                "stdout_log": "",
                "stderr_log": "",
            }
        }
        # Provide a real attribute so patch.object() can resolve it.
        self._send_rpc_raw = lambda *a, **kw: None

    @staticmethod
    def _runtime_alive(runtime):
        return runtime is not None


def test_default_args_return_after_one_poll():
    """No caller arg => single IDA round-trip, no sleeping, return immediately.

    The host must NOT default to a 5-minute polling window.
    """
    h = _Host()
    calls = []

    def fake_rpc(payload, port, recv_timeout=None):
        calls.append((payload, recv_timeout))
        return {"ok": True, "analysis_complete": True, "functions": 100}

    with patch.object(h, "_send_rpc_raw", side_effect=fake_rpc):
        res = h._handle_analysis_wait({})

    assert res.get("analysis_complete") is True
    assert res.get("host_waited_sec") is not None
    # Exactly one poll - no loop, no sleep
    assert len(calls) == 1, f"expected single poll, got {len(calls)}"


def test_max_wait_zero_returns_one_poll():
    """Explicit max_wait=0 => single poll, return immediately."""
    h = _Host()
    calls = []

    def fake_rpc(payload, port, recv_timeout=None):
        calls.append((payload, recv_timeout))
        return {"ok": True, "analysis_complete": False, "functions": 50}

    with patch.object(h, "_send_rpc_raw", side_effect=fake_rpc):
        res = h._handle_analysis_wait({"max_wait": 0})

    assert res.get("analysis_complete") is False
    assert res.get("host_waited_sec") is not None
    assert len(calls) == 1


def test_caller_supplied_max_wait_keeps_polling():
    """Explicit max_wait>0 + analysis_complete=False => multiple polls."""
    h = _Host()
    calls = []

    def fake_rpc(payload, port, recv_timeout=None):
        calls.append((payload, recv_timeout))
        return {"ok": True, "analysis_complete": False, "functions": 50}

    with patch.object(h, "_send_rpc_raw", side_effect=fake_rpc), \
         patch("time.sleep", lambda *_a, **_kw: None):
        # max_wait=0.1s, poll_interval default 5s clamped to 1s min.
        # The loop should make at least 2 calls before max_wait trips.
        h._handle_analysis_wait({"max_wait": 0.1, "poll_timeout": 0.05})

    assert len(calls) >= 2, f"expected polling, got {len(calls)} call(s)"


def test_timeout_key_alias_still_works():
    """The `timeout` arg spelling still caps polling duration."""
    h = _Host()
    calls = []

    def fake_rpc(payload, port, recv_timeout=None):
        calls.append((payload, recv_timeout))
        return {"ok": True, "analysis_complete": True, "functions": 10}

    with patch.object(h, "_send_rpc_raw", side_effect=fake_rpc), \
         patch("time.sleep", lambda *_a, **_kw: None):
        res = h._handle_analysis_wait({"timeout": 0})

    assert res.get("analysis_complete") is True
    assert len(calls) == 1


def test_no_session_returns_session_required():
    """No active session => SESSION_REQUIRED, no RPC attempted."""
    h = _Host()
    h.current_session = None
    calls = []

    def fake_rpc(*_a, **_kw):
        calls.append(1)
        return {}

    with patch.object(h, "_send_rpc_raw", side_effect=fake_rpc):
        res = h._handle_analysis_wait({})

    assert res.get("code") == "SESSION_REQUIRED"
    assert calls == []
