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
