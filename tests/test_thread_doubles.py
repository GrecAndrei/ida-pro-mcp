"""Regression tests for the shared threading.Thread test doubles."""

from __future__ import annotations

import threading
from unittest.mock import patch

from tests._thread_doubles import CaptureThread, SyncThread


def test_thread_doubles_keep_timer_functional() -> None:
    """Thread test doubles must not break threading.Timer.

    Regression guard: MagicMock replacements of threading.Thread left Timer
    instances uninitialized, so a background timer thread firing mid-test
    died with RuntimeError("Thread.__init__() not called") (surfacing as a
    flaky PytestUnhandledThreadExceptionWarning from the embedder
    idle-shutdown reschedule path). Subclassing the real Thread keeps Timer
    construction and ``daemon =`` assignment working under the patch.
    """
    for double in (CaptureThread, SyncThread):
        with patch("threading.Thread", double):
            timer = threading.Timer(60.0, lambda: None)
            timer.daemon = True
            timer.cancel()


def test_capture_thread_holds_and_replays_target() -> None:
    """CaptureThread never spawns and can drive its target more than once."""
    calls = []

    with patch("threading.Thread", CaptureThread):
        thread = threading.Thread(target=calls.append, args=("ping",), daemon=True)
        assert isinstance(thread, CaptureThread)
        assert calls == []
        thread.run_captured()
        thread.run_captured()
    assert calls == ["ping", "ping"]


def test_sync_thread_runs_target_on_start() -> None:
    """SyncThread executes the target synchronously instead of spawning."""
    calls = []

    with patch("threading.Thread", SyncThread):
        thread = threading.Thread(target=calls.append, args=("pong",), daemon=True)
        assert calls == []
        thread.start()
    assert calls == ["pong"]


def test_doubles_join_and_is_alive_without_real_start() -> None:
    """join()/is_alive() stay usable even though the doubles never spawn."""
    for double in (CaptureThread, SyncThread):
        thread = double(target=lambda: None, daemon=True)
        assert thread.is_alive() is False
        assert thread.join(timeout=1) is None
