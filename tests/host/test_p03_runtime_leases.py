"""Regression tests for p03_runtime: stale runtime-lease cleanup safety.

Covers the runtime-lease ownership/cleanup fixes in server_runtime_leases.py:
non-Linux PID identity verification, dead/recycled PID handling, TOCTOU-safe
removal, and the bounded startup cleanup budget.
"""

import json
import os
import threading
import time
from types import SimpleNamespace

from ida_pro_mcp.host.server import server_runtime_leases
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin

TMP_SID = "A1B2C3D4"


class _LeaseRuntime(ServerRuntimeLeasesMixin):
    def __init__(self, lease_dir):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self.idat_exe = ""

    @staticmethod
    def _ida_binary_names():
        return ["idat64"]


def _write_lease(tmp_path, sid=TMP_SID, *, pid=54321, updated=0.0):
    path = tmp_path / f"SID_{sid}.lease.json"
    path.write_text(
        json.dumps(
            {
                "session_id": sid,
                "pid": pid,
                "updated_at": updated,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_is_expected_ida_process_non_linux_refuses_unverified_pid(tmp_path, monkeypatch):
    """On non-Linux the identity guard must not be skipped: unverified or
    non-IDA pids are refused so a recycled PID is never signalled."""
    monkeypatch.setattr(server_runtime_leases.sys, "platform", "darwin")
    runtime = _LeaseRuntime(tmp_path)

    # ps reports an unrelated process -> refuse.
    monkeypatch.setattr(
        server_runtime_leases.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout="bash\n"),
    )
    assert runtime._is_expected_ida_process(54321, {"idat_exe": ""}) is False

    # ps reports an IDA-named process -> safe to signal.
    monkeypatch.setattr(
        server_runtime_leases.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout="idat64\n"),
    )
    assert runtime._is_expected_ida_process(54321, {"idat_exe": ""}) is True

    # process lister fails -> refuse (never kill what we cannot verify).
    monkeypatch.setattr(
        server_runtime_leases.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")),
    )
    assert runtime._is_expected_ida_process(54321, {"idat_exe": ""}) is False


def test_is_expected_ida_process_win32_matches_image_name(tmp_path, monkeypatch):
    monkeypatch.setattr(server_runtime_leases.sys, "platform", "win32")
    runtime = _LeaseRuntime(tmp_path)
    runtime._ida_binary_names = lambda: ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]

    monkeypatch.setattr(
        server_runtime_leases.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout='"ida64.exe","54321","Console","1","12,345 K"\n'),
    )
    assert runtime._is_expected_ida_process(54321, {"idat_exe": ""}) is True

    monkeypatch.setattr(
        server_runtime_leases.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout='"notepad.exe","54321","Console","1","12,345 K"\n'),
    )
    assert runtime._is_expected_ida_process(54321, {"idat_exe": ""}) is False


def test_cleanup_removes_stale_lease_when_recorded_pid_is_dead(tmp_path, monkeypatch):
    """A lease whose recorded pid is gone (ProcessLookupError) is removed —
    previously the not-an-IDA-process skip branch kept it forever on Linux."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, pid=999999, updated=0.0)

    def _kill(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(server_runtime_leases.os, "kill", _kill)
    runtime._cleanup_stale_runtime_leases()

    assert not lease_path.exists()


def test_cleanup_drops_lease_but_never_signals_recycled_live_pid(tmp_path, monkeypatch):
    """A live pid that is NOT an IDA process must not be killed; its stale
    lease is dropped so the shared cache does not accumulate."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)

    killed = []
    monkeypatch.setattr(runtime, "_is_expected_ida_process", lambda pid, lease: False)
    monkeypatch.setattr(runtime, "_kill_stale_pid", lambda pid: killed.append(pid) or True)
    monkeypatch.setattr(server_runtime_leases.os, "kill", lambda pid, sig: None)
    runtime._cleanup_stale_runtime_leases()

    assert killed == []
    assert not lease_path.exists()


def test_remove_lease_if_unchanged_skips_rewritten_lease(tmp_path):
    """TOCTOU guard: a lease rewritten since the initial read (a fresh runtime
    for the same sid) must not be deleted by a stale-cleanup that started
    earlier."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, updated=100.0)

    assert runtime._remove_lease_if_unchanged(str(lease_path), 100.0) is True
    assert not lease_path.exists()

    # Recreate, then rewrite with a fresh updated_at between read and remove.
    _write_lease(tmp_path, updated=100.0)
    _write_lease(tmp_path, updated=200.0)
    assert runtime._remove_lease_if_unchanged(str(lease_path), 100.0) is False
    assert lease_path.exists()


def test_cleanup_defers_kills_when_startup_budget_exhausted(tmp_path, monkeypatch):
    """The startup stale-cleanup is time-bounded so a host with many orphans
    can still serve its first request; deferred leases are re-checked next
    startup."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)

    killed = []
    monkeypatch.setattr(runtime, "_is_expected_ida_process", lambda pid, lease: True)
    monkeypatch.setattr(runtime, "_kill_stale_pid", lambda pid: killed.append(pid) or True)
    monkeypatch.setattr(server_runtime_leases.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(server_runtime_leases, "STALE_CLEANUP_BUDGET_SECONDS", -1.0)
    runtime._cleanup_stale_runtime_leases()

    assert killed == []
    assert lease_path.exists()  # deferred to a later startup


def test_live_foreign_owner_lease_is_never_touched(tmp_path, monkeypatch):
    """Reuse the existing invariant: a live foreign host's lease is kept and no
    pid is signalled."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = tmp_path / "SID_A1B2C3D4.lease.json"
    lease_path.write_text(
        json.dumps(
            {
                "session_id": "A1B2C3D4",
                "pid": 54321,
                "owner_pid": 424242,
                "updated_at": 0,
            }
        ),
        encoding="utf-8",
    )
    runtime._is_expected_ida_process = lambda pid, lease: True
    runtime._kill_stale_pid = lambda pid: True

    with monkeypatch.context() as m:
        m.setattr(server_runtime_leases.os, "kill", lambda pid, sig: None)
        runtime._cleanup_stale_runtime_leases()

    assert lease_path.exists()
