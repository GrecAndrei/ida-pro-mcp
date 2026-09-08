"""Timer-safe ``threading.Thread`` test doubles.

Why this module exists: several tests replace ``threading.Thread`` to keep
background work synchronous or captured. A ``MagicMock`` (or any stub whose
``__init__`` does not run the real initializer) breaks ``threading.Timer``,
because ``Timer.__init__`` calls the module-global ``Thread.__init__``: the
resulting Timer has no ``_initialized`` flag, so ``timer.daemon = True``
raises ``RuntimeError("Thread.__init__() not called")`` in any timer thread
that fires while the patch is active. That surfaced as a flaky
``PytestUnhandledThreadExceptionWarning`` from the intelligence embedder's
idle-shutdown reschedule path.

Rules for every double in this module:

- subclass the real ``threading.Thread`` so ``Timer`` construction keeps
  working while the patch is active;
- never override ``__init__`` (an override breaks the ``super()`` contract
  when ``self`` is a ``Timer``, which is not an instance of the double);
- only override ``start``/``run`` behavior or add new methods.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace


class CaptureThread(threading.Thread):
    """Record construction without spawning; drive manually via run_captured."""

    def start(self) -> None:
        return None

    def run_captured(self) -> None:
        """Invoke the captured target (repeatable; Thread.run() is one-shot)."""
        target, args, kwargs = self._target, self._args, self._kwargs
        try:
            self.run()
        finally:
            # Thread.run() deletes _target/_args/_kwargs after one use;
            # restore so tests can drive the target more than once.
            self._target, self._args, self._kwargs = target, args, kwargs

    def join(self, timeout: float | None = None) -> None:
        # Never spawned: there is nothing to wait for. (The real join()
        # refuses threads that were never started.)
        return None

    def is_alive(self) -> bool:
        return False


class SyncThread(threading.Thread):
    """Run the target synchronously in the calling thread on start()."""

    def start(self) -> None:
        self.run()

    def join(self, timeout: float | None = None) -> None:
        # The target already completed inline in start(); nothing to wait for.
        return None

    def is_alive(self) -> bool:
        return False


_MIRRORED_THREADING_ATTRS = (
    "Thread",
    "Timer",
    "Event",
    "Lock",
    "RLock",
    "Semaphore",
    "Condition",
    "get_ident",
    "current_thread",
)


def consumer_namespace(**overrides):
    """Build a consumer-module ``threading`` stand-in with selective stubs.

    Prefer ``monkeypatch.setattr(producer, "threading", consumer_namespace(...))``
    over ``monkeypatch.setattr(producer.threading, "Timer", ...)``: the latter
    mutates the GLOBAL threading module, so every other consumer in the process
    sees the stub (background ``threading.Timer`` instances lose their real
    ``Thread.__init__``/``finished`` event). Interposing on the consumer module
    confines the stub to that module; everything else keeps working.
    """
    namespace = {name: getattr(threading, name) for name in _MIRRORED_THREADING_ATTRS}
    namespace.update(overrides)
    return SimpleNamespace(**namespace)
