"""Regression tests for f05: runtime-lease lifecycle safety.

Covers the runtime-lease fixes in server_runtime_leases.py:
- heartbeat liveness rewrite / dead-process lease removal
- exception guard keeping the daemon heartbeat thread alive
- pid-guarded heartbeat lease removal (no TOCTOU clobber of a fresh lease)
- terminate_failed backoff rewrite that never clobbers a fresh owner's lease
- _kill_stale_pid verified/unverifiable termination
- shutdown() teardown ordering + idempotence
- per-instance atexit lifecycle registration
"""

import json
import os
import signal
import threading
from types import SimpleNamespace

from ida_pro_mcp.host.server import server_runtime_leases as srl
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin

TMP_SID = "A1B2C3D4"


class _Proc:
    def __init__(self, pid, poll_result=None):
        self.pid = pid
        self._poll = poll_result

    def poll(self):
        return self._poll


class _LeaseRuntime(ServerRuntimeLeasesMixin):
    def __init__(self, lease_dir):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self.idat_exe = ""
        self._shutdown_requested = False
        self._lease_thread_stop = threading.Event()

    @staticmethod
    def _ida_binary_names():
        return ["idat64"]


class _FullRuntime(ServerRuntimeLeasesMixin):
    def __init__(self, lease_dir):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self.idat_exe = ""
        self._shutdown = False
        self._shutdown_requested = False
        self._lease_thread_stop = threading.Event()
        self._lease_thread = None
        self.assembler = None
        self._usage_intel = None
        self._insight_indexes = {}
        self._global_facts = SimpleNamespace(close=lambda: None)
        self.audit = None
        self._cleanup_calls = 0

    def _cleanup_all_runtimes(self):
        self._cleanup_calls += 1

    @staticmethod
    def _ida_binary_names():
        return ["idat64"]


class _AuditStub:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _write_lease(tmp_path, sid=TMP_SID, *, pid=54321, updated=0.0):
    path = tmp_path / f"SID_{sid}.lease.json"
    path.write_text(
        json.dumps({"session_id": sid, "pid": pid, "updated_at": updated}),
        encoding="utf-8",
    )
    return path


class _OneHeartbeatWait:
    """Allow exactly one heartbeat pass without waiting on wall-clock time."""

    def __init__(self):
        self._waits = 0

    def wait(self, _timeout=None):
        self._waits += 1
        return self._waits > 1

    def set(self):
        return None


def _run_heartbeat(runtime):
    runtime._lease_thread_stop = _OneHeartbeatWait()
    t = threading.Thread(target=runtime._lease_heartbeat_loop, daemon=True)
    t.start()
    t.join(timeout=2.0)
    assert not t.is_alive()
    return t


def test_heartbeat_refreshes_live_lease_and_removes_dead_lease(tmp_path, monkeypatch):
    """The heartbeat rewrites a live runtime's lease (fresh updated_at) and
    removes the lease for a runtime whose process has exited."""
    runtime = _LeaseRuntime(tmp_path)
    live_sid = "AAAAAAAA"
    dead_sid = "BBBBBBBB"
    runtime.session_runtimes = {
        live_sid: {"process": _Proc(1111, None), "port": 1234},
        dead_sid: {"process": _Proc(2222, 1), "port": 5678},
    }
    # Pre-existing leases for both sids; the live one must be refreshed, the
    # dead one removed.
    _write_lease(tmp_path, sid=live_sid, pid=1111, updated=100.0)
    _write_lease(tmp_path, sid=dead_sid, pid=2222, updated=100.0)

    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    _run_heartbeat(runtime)

    live_path = tmp_path / f"SID_{live_sid}.lease.json"
    dead_path = tmp_path / f"SID_{dead_sid}.lease.json"
    assert live_path.exists()
    lease = json.loads(live_path.read_text(encoding="utf-8"))
    assert lease["pid"] == 1111
    assert lease["port"] == 1234
    assert lease["updated_at"] > 100.0  # refreshed, not the pre-existing value
    assert not dead_path.exists()


def test_heartbeat_does_not_clobber_fresh_lease_on_removal(tmp_path, monkeypatch):
    """A fresh lease written for a concurrently restarted runtime (new pid)
    must survive the heartbeat's dead-process removal."""
    runtime = _LeaseRuntime(tmp_path)
    # Directly exercise the guarded removal: lease records pid 77777 (the new
    # runtime), removal is attempted for the old runtime's pid 54321.
    _write_lease(tmp_path, pid=77777, updated=500.0)
    runtime._remove_runtime_lease_if_pid_matches(TMP_SID, 54321)
    assert (tmp_path / f"SID_{TMP_SID}.lease.json").exists()

    # A matching pid removes the lease.
    runtime._remove_runtime_lease_if_pid_matches(TMP_SID, 77777)
    assert not (tmp_path / f"SID_{TMP_SID}.lease.json").exists()

    # An unverifiable (None) pid never removes anything.
    _write_lease(tmp_path, pid=77777, updated=500.0)
    runtime._remove_runtime_lease_if_pid_matches(TMP_SID, None)
    assert (tmp_path / f"SID_{TMP_SID}.lease.json").exists()


def test_concurrent_lease_writes_keep_json_valid_and_leave_no_shared_tmp(tmp_path):
    """Same-session heartbeat writers must not interleave their temp file."""
    runtime = _LeaseRuntime(tmp_path)
    errors: list[Exception] = []

    def writer(index: int) -> None:
        try:
            runtime._write_runtime_lease(
                TMP_SID,
                {"process": _Proc(50000 + index, None), "port": 12000 + index},
            )
        except Exception as exc:  # pragma: no cover - defensive assertion path
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    lease_path = tmp_path / f"SID_{TMP_SID}.lease.json"
    assert json.loads(lease_path.read_text(encoding="utf-8"))["session_id"] == TMP_SID
    assert not list(tmp_path.glob(f"{lease_path.name}.*.tmp"))


def test_heartbeat_survives_raised_exception_in_body(tmp_path, monkeypatch):
    """A single raised exception (e.g. int(None) for a pid-less process) must
    not kill the daemon heartbeat thread; later sids still get their leases."""
    runtime = _LeaseRuntime(tmp_path)
    runtime.session_runtimes = {
        "AAAAAAAA": {"process": _Proc(None, None), "port": 1234},  # pid None -> int() raises
        "BBBBBBBB": {"process": _Proc(3333, None), "port": 9999},
    }
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    _run_heartbeat(runtime)

    # Thread is still alive across ticks (it was joined via the stop event,
    # not by dying) and the second sid's lease was still written.
    assert (tmp_path / "SID_BBBBBBBB.lease.json").exists()


def test_terminate_failed_backoff_does_not_clobber_rewritten_lease(tmp_path, monkeypatch):
    """Regression: a fresh lease a new owner writes during the kill window must
    survive the terminate_failed backoff rewrite."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)

    def _kill_stale_pid(pid):
        # A new owner claims this sid mid-kill, rewriting the lease.
        lease_path.write_text(
            json.dumps(
                {
                    "session_id": TMP_SID,
                    "pid": 77777,
                    "updated_at": 500.0,
                    "owner_pid": 99999,
                }
            ),
            encoding="utf-8",
        )
        return False

    runtime._is_expected_ida_process = lambda pid, lease: True
    runtime._kill_stale_pid = _kill_stale_pid
    with monkeypatch.context() as m:
        m.setattr(srl.os, "kill", lambda pid, sig: None)
        runtime._cleanup_stale_runtime_leases()

    written = json.loads(lease_path.read_text(encoding="utf-8"))
    assert written["pid"] == 77777
    assert written["updated_at"] == 500.0
    assert written.get("last_error") != "terminate_failed"


def test_terminate_failed_backoff_rewrites_unchanged_lease(tmp_path, monkeypatch):
    """When the lease was NOT rewritten during the kill window, the backoff
    marker (updated_at + last_error) is written so the lease is retried."""
    runtime = _LeaseRuntime(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)
    runtime._is_expected_ida_process = lambda pid, lease: True
    runtime._kill_stale_pid = lambda pid: False
    with monkeypatch.context() as m:
        m.setattr(srl.os, "kill", lambda pid, sig: None)
        runtime._cleanup_stale_runtime_leases()

    written = json.loads(lease_path.read_text(encoding="utf-8"))
    assert written["pid"] == 54321
    assert written.get("last_error") == "terminate_failed"
    assert written["updated_at"] > 0.0


def test_kill_stale_pid_already_dead_returns_true(tmp_path, monkeypatch):
    runtime = _LeaseRuntime(tmp_path)

    def _kill(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(srl.os, "kill", _kill)
    assert runtime._kill_stale_pid(54321) is True


def test_kill_stale_pid_terminates_and_verifies(tmp_path, monkeypatch):
    runtime = _LeaseRuntime(tmp_path)
    monkeypatch.setattr(srl, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.01)
    calls = []

    def _kill(pid, sig):
        calls.append(sig)
        if len(calls) <= 2:
            return None  # alive probe + SIGTERM delivery
        raise ProcessLookupError()  # process gone after SIGTERM

    monkeypatch.setattr(srl.os, "kill", _kill)
    assert runtime._kill_stale_pid(54321) is True
    assert signal.SIGTERM in calls


def test_kill_stale_pid_unverifiable_returns_false(tmp_path, monkeypatch):
    runtime = _LeaseRuntime(tmp_path)
    monkeypatch.setattr(srl, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.01)
    # Process never dies: SIGTERM, SIGKILL, and the final probe all succeed.
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    assert runtime._kill_stale_pid(54321) is False


def test_write_and_remove_runtime_lease(tmp_path):
    runtime = _LeaseRuntime(tmp_path)
    runtime._runtime_owner_id = "testowner"
    runtime.session_runtimes[TMP_SID] = {"process": _Proc(1111, None), "port": 1234}
    runtime._write_runtime_lease(TMP_SID, runtime.session_runtimes[TMP_SID])
    path = tmp_path / f"SID_{TMP_SID}.lease.json"
    lease = json.loads(path.read_text(encoding="utf-8"))
    assert lease["session_id"] == TMP_SID
    assert lease["pid"] == 1111
    assert lease["port"] == 1234
    assert lease["owner_pid"] == os.getpid()
    assert lease["owner_id"] == "testowner"

    # A runtime without a process writes no lease.
    runtime.session_runtimes["CCCCCCCC"] = {"process": None}
    runtime._write_runtime_lease("CCCCCCCC", runtime.session_runtimes["CCCCCCCC"])
    assert not (tmp_path / "SID_CCCCCCCC.lease.json").exists()

    runtime._remove_runtime_lease(TMP_SID)
    assert not path.exists()


def test_shutdown_stops_heartbeat_runs_cleanup_and_is_idempotent(tmp_path, monkeypatch):
    runtime = _FullRuntime(tmp_path)
    runtime.audit = _AuditStub()
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    runtime._start_runtime_lease_heartbeat()
    assert runtime._lease_thread and runtime._lease_thread.is_alive()

    runtime.shutdown()

    assert not runtime._lease_thread.is_alive()
    assert runtime._cleanup_calls == 1
    assert runtime._shutdown is True
    assert runtime.audit.closed
    # Idempotent: a second shutdown() does not re-run cleanup.
    runtime.shutdown()
    assert runtime._cleanup_calls == 1


def test_register_lifecycle_handlers_registers_atexit_for_every_instance(tmp_path, monkeypatch):
    """Each server instance registers its own atexit shutdown; the class-level
    flag that skipped the second+ instance is gone."""
    registered = []
    fake_atexit = SimpleNamespace(register=registered.append)
    monkeypatch.setattr(srl, "atexit", fake_atexit)
    monkeypatch.setattr(srl.signal, "signal", lambda *a, **k: None)

    first = _FullRuntime(tmp_path)
    first._register_lifecycle_handlers()
    second = _FullRuntime(tmp_path)
    second._register_lifecycle_handlers()

    assert len(registered) == 2
    assert registered[0] == first.shutdown
    assert registered[1] == second.shutdown
