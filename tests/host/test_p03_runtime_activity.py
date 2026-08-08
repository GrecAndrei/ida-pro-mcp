"""Regression tests for p03_runtime: _activity_log thread safety.

Covers the fix in server_runtime.py where the activity log was appended and
sliced in place without a lock while other threads iterated it, which could
raise ``RuntimeError: list changed size during iteration`` in daemon mode.
"""

import threading
import time

from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _ActivityHost(ServerRuntimeMixin):
    def __init__(self):
        self._activity_log = []
        self._activity_log_max = 4000
        self._session_last_activity = {}
        self.current_session = None
        self._usage_intel = None
        self.session_mgr = type(
            "Mgr", (), {"log_activity": staticmethod(lambda *a, **k: None)}
        )()


def _entry(**overrides):
    args = {
        "session_id": "AB12CDEF",
        "addr": "0x400000",
        "action": "decompile",
    }
    args.update(overrides)
    return args


def test_record_activity_appends_and_bounds_log():
    host = _ActivityHost()
    host._activity_log_max = 3
    for i in range(10):
        host._record_activity(
            "code", _entry(addr=f"0x{0x400000 + i:x}"), {"ok": True, "items": []},
            session_id="AB12CDEF",
        )
    assert len(host._activity_log) == 3  # bounded to _activity_log_max


def test_record_activity_replaces_list_instead_of_mutating_in_place():
    """Concurrent readers holding the old object must never observe an
    in-place resize."""
    host = _ActivityHost()
    host._record_activity(
        "code", _entry(), {"ok": True, "items": []}, session_id="AB12CDEF"
    )
    old = host._activity_log
    host._record_activity(
        "code", _entry(addr="0x400001"), {"ok": True, "items": []},
        session_id="AB12CDEF",
    )
    # The list object is replaced, not appended to.
    assert host._activity_log is not old
    assert list(old) == list(host._activity_log)[:-1]


def test_concurrent_record_and_iterate_raises_no_runtime_error():
    """Two writers appending while readers iterate must not raise RuntimeError."""
    host = _ActivityHost()
    stop = threading.Event()
    errors = []

    def writer():
        while not stop.is_set():
            try:
                host._record_activity(
                    "code", _entry(addr="0x400000"), {"ok": True, "items": []},
                    session_id="AB12CDEF",
                )
            except Exception as exc:  # pragma: no cover - failure branch
                errors.append(exc)

    def reader():
        while not stop.is_set():
            try:
                host._build_recent_workset(
                    "AB12CDEF", 20, include_bookmarks=False, include_items=False
                )
            except Exception as exc:  # pragma: no cover - failure branch
                errors.append(exc)

    threads = [threading.Thread(target=writer, daemon=True) for _ in range(2)] + [
        threading.Thread(target=reader, daemon=True) for _ in range(2)
    ]
    for t in threads:
        t.start()
    time.sleep(0.4)
    stop.set()
    for t in threads:
        t.join(timeout=3)

    assert errors == [], errors


def test_build_recent_workset_returns_only_matching_session():
    host = _ActivityHost()
    host._record_activity(
        "code", {"session_id": "AB12CDEF", "addr": "0x400000", "action": "decompile"},
        {"ok": True, "items": []},
        session_id="AB12CDEF",
    )
    host._record_activity(
        "data", {"session_id": "ZZZZZZZZ", "addr": "0x500000", "action": "strings"},
        {"ok": True, "items": []},
        session_id="ZZZZZZZZ",
    )
    workset = host._build_recent_workset(
        "AB12CDEF", 20, include_bookmarks=False, include_items=False
    )
    assert workset["ok"] is True
    assert "0x400000" in workset["workset"]
    assert "0x500000" not in workset["workset"]
