"""Regression tests for s07-h02: runtime-lease tree liveness and tree teardown.

Covers the s3 lease fixes in server_runtime_leases.py:

- Heartbeat keeps a session lease while an ida-named descendant (the real
  analysis process, spawned by the idat launcher) is still alive after the
  launcher exits — a launcher exit must not drop the lease early.
- Stale-lease cleanup terminates the WHOLE process tree of an
  identity-verified IDA launcher (taskkill /T on Windows, the launcher's own
  process group or pgrep -P descendants on POSIX) so an orphaned ida child
  cannot keep the unpacked .id0/.id1 files open.
- Every D5 keep=true lease rule survives: never signal an unverified/recycled
  live pid, drop the lease when the recorded pid is dead, TOCTOU-guard
  rewritten leases, keep the startup budget bound, never touch a live foreign
  owner.
- shutdown() stops analysis-completion watchers/background spawns via the
  existing helper and lease-heartbeat threads shut down cleanly (no leaked
  ``ida-mcp-runtime-lease-heartbeat`` threads across tests).

NO live IDA is required: analysis processes are faked with _FakeIdaHost /
_Proc-style fakes; the only real subprocesses spawned are generic
``python`` helpers used to exercise POSIX process-group mechanics.
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time

from ida_pro_mcp.host.server import server_runtime_leases as srl
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin

TMP_SID = "A1B2C3D4"


def test_stale_lease_cleanup_budget_rejects_invalid_float_env_values():
    """A bad startup cleanup budget must never make lease recovery unbounded."""
    code = (
        "from ida_pro_mcp.host.server.server_runtime_leases "
        "import _resolve_stale_cleanup_budget; print(_resolve_stale_cleanup_budget())"
    )
    for raw, expected in (("oops", 10.0), ("inf", 10.0), ("nan", 10.0), ("-5", 1.0)):
        env = dict(os.environ, IDA_MCP_STALE_LEASE_CLEANUP_BUDGET=raw)
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0, proc.stderr
        assert float(proc.stdout) == expected


class _Proc:
    def __init__(self, pid, poll_result=None):
        self.pid = pid
        self._poll = poll_result

    def poll(self):
        return self._poll


class _FakeIdaHost(ServerRuntimeLeasesMixin):
    """Minimal host composing the leases mixin, with the session-mixin
    teardown stub the mixin's shutdown() reaches via getattr."""

    def __init__(self, lease_dir):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self.idat_exe = "/opt/ida/9.2/idat64"
        self._shutdown = False
        self._shutdown_requested = False
        self._lease_thread_stop = threading.Event()
        self._lease_thread = None
        self._watchers_stopped = False
        self._cleanup_runs = 0

    @staticmethod
    def _ida_binary_names():
        return ["idat", "idat64", "ida", "ida64"]

    def _stop_analysis_completion_watchers(self):
        self._watchers_stopped = True

    def _cleanup_all_runtimes(self):
        self._cleanup_runs += 1


def _write_lease(tmp_path, sid=TMP_SID, *, pid=54321, updated=0.0, **extra):
    data = {"session_id": sid, "pid": pid, "updated_at": updated}
    data.update(extra)
    path = tmp_path / f"SID_{sid}.lease.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _run_heartbeat(runtime, seconds=0.08):
    t = threading.Thread(target=runtime._lease_heartbeat_loop, daemon=True)
    t.start()
    time.sleep(seconds)
    runtime._lease_thread_stop.set()
    t.join(timeout=2.0)
    assert not t.is_alive()
    return t


# --------------------------------------------------------------------------
# Heartbeat: launcher-exit must not drop the lease while an ida child lives
# --------------------------------------------------------------------------


def test_heartbeat_keeps_lease_when_launcher_exit_but_ida_child_alive(tmp_path, monkeypatch):
    """The idat launcher exited (proc.poll() != None) but an ida-named
    descendant keeps running; the heartbeat must refresh the lease instead of
    removing it, so coverage is not dropped early."""
    runtime = _FakeIdaHost(tmp_path)
    runtime.session_runtimes = {
        TMP_SID: {"process": _Proc(54321, 1), "port": 1234},
    }
    _write_lease(tmp_path, pid=54321, updated=100.0)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(runtime, "_runtime_tree_still_alive", lambda pid: True)
    _run_heartbeat(runtime)

    path = tmp_path / f"SID_{TMP_SID}.lease.json"
    assert path.exists()
    lease = json.loads(path.read_text(encoding="utf-8"))
    assert lease["pid"] == 54321
    assert lease["port"] == 1234
    assert lease["updated_at"] > 100.0  # refreshed, not dropped


def test_heartbeat_removes_lease_when_tree_dead_after_launcher_exit(tmp_path, monkeypatch):
    """The launcher exited AND no descendant is alive: the lease is removed so
    a dead tree does not keep ownership of the shared cache."""
    runtime = _FakeIdaHost(tmp_path)
    runtime.session_runtimes = {
        TMP_SID: {"process": _Proc(54321, 1), "port": 1234},
    }
    _write_lease(tmp_path, pid=54321, updated=100.0)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(runtime, "_runtime_tree_still_alive", lambda pid: False)
    _run_heartbeat(runtime)

    assert not (tmp_path / f"SID_{TMP_SID}.lease.json").exists()


def test_heartbeat_does_not_touch_alive_launcher_path(tmp_path, monkeypatch):
    """A live launcher (poll() == None) still refreshes the lease and the tree
    liveness helper is NOT consulted — the alive path is unchanged."""
    runtime = _FakeIdaHost(tmp_path)
    runtime.session_runtimes = {
        TMP_SID: {"process": _Proc(54321, None), "port": 1234},
    }
    checked = []
    monkeypatch.setattr(runtime, "_runtime_tree_still_alive", lambda pid: checked.append(pid) or True)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    _run_heartbeat(runtime)

    assert checked == []
    lease = json.loads((tmp_path / f"SID_{TMP_SID}.lease.json").read_text(encoding="utf-8"))
    assert lease["pid"] == 54321


def test_runtime_tree_still_alive_probes_real_process_group(tmp_path, monkeypatch):
    """The POSIX tree-liveness probe tracks a real launcher's process group:
    alive while the (ida-named, faked) member runs, gone once the tree drains.
    Exercises the real killpg + /proc-group scan with a generic subprocess."""
    runtime = _FakeIdaHost(tmp_path)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        monkeypatch.setattr(runtime, "_proc_is_ida_named", lambda pid: True)
        assert runtime._runtime_tree_still_alive(child.pid) is True
        child.kill()
        child.wait(timeout=10)
        assert runtime._runtime_tree_still_alive(child.pid) is False
    finally:
        with __import__("contextlib").suppress(Exception):
            child.kill()
        with __import__("contextlib").suppress(Exception):
            child.wait(timeout=5)


def test_runtime_tree_still_alive_unknown_group_keeps_lease(tmp_path, monkeypatch):
    """When the process group cannot be probed (e.g. EPERM), the tree is
    assumed alive so the lease is never dropped for a tree we cannot inspect."""
    runtime = _FakeIdaHost(tmp_path)

    def _killpg(pgid, sig):
        raise PermissionError("cannot probe")

    monkeypatch.setattr(srl.os, "killpg", _killpg)
    assert runtime._runtime_tree_still_alive(54321) is True


# --------------------------------------------------------------------------
# Stale cleanup: tree termination for an identity-verified IDA launcher
# --------------------------------------------------------------------------


def test_cleanup_terminates_tree_for_verified_ida_launcher_and_removes_lease(tmp_path, monkeypatch):
    """An identity-verified ida launcher's stale lease is tree-killed (not just
    single-pid signalled) and then removed."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)
    tree_kills = []
    runtime._is_expected_ida_process = lambda pid, lease: True
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == [54321]
    assert not lease_path.exists()


def test_cleanup_never_signals_recycled_live_pid(tmp_path, monkeypatch):
    """D5: a live pid that is NOT an IDA process must never be signalled — even
    the new tree-kill path is bypassed and the stale lease is dropped."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)
    tree_kills = []
    runtime._is_expected_ida_process = lambda pid, lease: False
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == []
    assert not lease_path.exists()


def test_cleanup_drops_lease_when_recorded_pid_dead(tmp_path, monkeypatch):
    """D5: when the recorded pid is gone the stale lease is removed without any
    tree-kill attempt."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=999999, updated=0.0)
    tree_kills = []
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )

    def _kill(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(srl.os, "kill", _kill)
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == []
    assert not lease_path.exists()


def test_cleanup_keeps_live_foreign_owner_lease(tmp_path, monkeypatch):
    """D5: a live foreign owner's lease is kept and never tree-killed."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0, owner_pid=424242)
    tree_kills = []
    runtime._is_expected_ida_process = lambda pid, lease: True
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)  # foreign owner alive
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == []
    assert lease_path.exists()


def test_cleanup_tou_guard_keeps_rewritten_lease_after_tree_kill(tmp_path, monkeypatch):
    """D5 TOCTOU: a lease rewritten by a fresh owner during the tree-kill
    window must survive the post-kill removal."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)
    runtime._is_expected_ida_process = lambda pid, lease: True

    def _tree_kill(pid):
        # A fresh runtime claims this sid mid-cleanup, rewriting the lease.
        lease_path.write_text(
            json.dumps(
                {"session_id": TMP_SID, "pid": 77777, "updated_at": 500.0}
            ),
            encoding="utf-8",
        )
        return True

    monkeypatch.setattr(runtime, "_kill_stale_process_tree", _tree_kill)
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    runtime._cleanup_stale_runtime_leases()

    written = json.loads(lease_path.read_text(encoding="utf-8"))
    assert written["pid"] == 77777
    assert written["updated_at"] == 500.0


def test_cleanup_defers_tree_kill_when_budget_exhausted(tmp_path, monkeypatch):
    """D5 budget: the startup cleanup is time-bounded; an exhausted budget
    defers even tree kills to the next startup."""
    runtime = _FakeIdaHost(tmp_path)
    lease_path = _write_lease(tmp_path, pid=54321, updated=0.0)
    tree_kills = []
    runtime._is_expected_ida_process = lambda pid, lease: True
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(srl, "STALE_CLEANUP_BUDGET_SECONDS", -1.0)
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == []
    assert lease_path.exists()


# --------------------------------------------------------------------------
# _kill_stale_process_tree itself: group path, descendant fallback, real tree
# --------------------------------------------------------------------------


def test_kill_stale_process_tree_group_path_signals_group(tmp_path, monkeypatch):
    """A launcher that leads its own process group is killed via the group
    (killpg SIGTERM), which also reaches reparented children."""
    runtime = _FakeIdaHost(tmp_path)
    calls = []

    def _killpg(pgid, sig):
        calls.append((pgid, sig))
        raise ProcessLookupError()  # drained immediately

    monkeypatch.setattr(srl.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(srl.os, "killpg", _killpg)
    assert runtime._kill_stale_process_tree(54321) is True
    assert calls == [(54321, signal.SIGTERM)]


def test_kill_stale_process_tree_fallback_kills_descendants_then_root(tmp_path, monkeypatch):
    """A non-group-leader launcher (e.g. launched manually from a shell) is
    killed via its parent-PID descendants plus the recorded pid — never an
    unrelated process group."""
    runtime = _FakeIdaHost(tmp_path)
    signaled = []
    root_calls = []
    monkeypatch.setattr(srl.os, "getpgid", lambda pid: pid + 1000)  # not a group leader
    monkeypatch.setattr(runtime, "_collect_descendant_pids", lambda pid: [9, 10])
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: signaled.append((pid, sig)))
    runtime._kill_stale_pid = lambda pid: root_calls.append(pid) or True

    assert runtime._kill_stale_process_tree(54321) is True
    assert (9, signal.SIGKILL) in signaled
    assert (10, signal.SIGKILL) in signaled
    assert root_calls == [54321]


def test_kill_stale_process_tree_real_tree(tmp_path, monkeypatch):
    """Kill a real 2-level launcher tree (like idat -> ida) via the group path
    and verify both the launcher and its child are gone."""
    runtime = _FakeIdaHost(tmp_path)
    launcher = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys, time\n"
            "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "print(c.pid, flush=True)\n"
            "time.sleep(30)\n",
        ],
        start_new_session=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        child_pid = int(launcher.stdout.readline().strip())
        assert os.getpgid(launcher.pid) == launcher.pid  # leads its own group
        assert os.getpgid(child_pid) == launcher.pid  # child in the same group

        monkeypatch.setattr(srl, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 2.0)
        assert runtime._kill_stale_process_tree(launcher.pid) is True
        assert launcher.wait(timeout=10) is not None

        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("tree child survived the group kill")
    finally:
        with __import__("contextlib").suppress(Exception):
            launcher.kill()
        with __import__("contextlib").suppress(Exception):
            os.killpg(launcher.pid, signal.SIGKILL)
        with __import__("contextlib").suppress(Exception):
            launcher.wait(timeout=5)


# --------------------------------------------------------------------------
# shutdown(): stop analysis watchers/background spawns + clean heartbeat
# --------------------------------------------------------------------------


def test_shutdown_stops_analysis_watchers_and_heartbeat(tmp_path, monkeypatch):
    """shutdown() stops the lease-heartbeat thread AND the analysis-completion
    watchers/background-spawn teardown helper (existing _stop_analysis_
    completion_watchers), then runs runtime cleanup. Idempotent."""
    runtime = _FakeIdaHost(tmp_path)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    runtime._start_runtime_lease_heartbeat()
    assert runtime._lease_thread and runtime._lease_thread.is_alive()

    runtime.shutdown()

    assert not runtime._lease_thread.is_alive()
    assert runtime._watchers_stopped is True
    assert runtime._cleanup_runs == 1
    assert runtime._shutdown is True
    # Idempotent: a second shutdown() does not re-run cleanup.
    runtime.shutdown()
    assert runtime._cleanup_runs == 1


def test_no_leaked_lease_heartbeat_threads_after_shutdown(tmp_path, monkeypatch):
    """Teardown leaves no leaked ida-mcp-runtime-lease-heartbeat threads."""
    def _count():
        return len(
            [
                t
                for t in threading.enumerate()
                if t.name == "ida-mcp-runtime-lease-heartbeat"
            ]
        )

    before = _count()
    runtime = _FakeIdaHost(tmp_path)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    runtime._start_runtime_lease_heartbeat()
    assert runtime._lease_thread and runtime._lease_thread.is_alive()

    runtime.shutdown()

    assert not runtime._lease_thread.is_alive()
    assert _count() == before


def test_heartbeat_restart_after_shutdown_beats_again(tmp_path, monkeypatch):
    """A restarted heartbeat on the same instance actually beats (the stale
    stop event is cleared by _start_runtime_lease_heartbeat), so a teardown can
    never leave a silently-dead heartbeat thread."""
    runtime = _FakeIdaHost(tmp_path)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    runtime._start_runtime_lease_heartbeat()
    runtime._stop_runtime_lease_heartbeat()
    assert not runtime._lease_thread.is_alive()

    runtime._start_runtime_lease_heartbeat()
    assert runtime._lease_thread and runtime._lease_thread.is_alive()
    runtime._stop_runtime_lease_heartbeat()
    assert not runtime._lease_thread.is_alive()


# --------------------------------------------------------------------------
# Opaque raw-blob / RISC-V scenarios
# --------------------------------------------------------------------------


def test_heartbeat_keeps_lease_for_opaque_riscv_raw_blob_after_launcher_exit(tmp_path, monkeypatch):
    """Opaque raw-blob/RISC-V analysis: idat64 launches ida64 as its real
    analysis child. The launcher can exit while ida64 keeps analyzing the raw
    firmware blob (holding its unpacked .id0/.id1). The heartbeat must keep the
    lease until that tree is gone — a launcher exit must not drop it early."""
    runtime = _FakeIdaHost(tmp_path)
    runtime.idat_exe = "/opt/ida/9.2/idat64"
    runtime.session_runtimes = {
        TMP_SID: {"process": _Proc(1111, 1), "port": 9876},
    }
    _write_lease(tmp_path, pid=1111, updated=100.0)
    monkeypatch.setattr(srl, "RUNTIME_LEASE_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(runtime, "_runtime_tree_still_alive", lambda pid: True)
    _run_heartbeat(runtime)

    lease = json.loads(
        (tmp_path / f"SID_{TMP_SID}.lease.json").read_text(encoding="utf-8")
    )
    assert lease["pid"] == 1111
    assert lease["port"] == 9876
    assert lease["updated_at"] > 100.0


def test_cleanup_tree_kills_opaque_riscv_raw_blob_launcher(tmp_path, monkeypatch):
    """A stale lease for an opaque raw-blob/RISC-V session whose idat64 launcher
    is identity-verified must be tree-killed (freeing the ida64 child holding
    the raw blob's unpacked .id0/.id1) and then removed."""
    runtime = _FakeIdaHost(tmp_path)
    runtime.idat_exe = "/opt/ida/9.2/idat64"
    lease_path = _write_lease(
        tmp_path, pid=54321, updated=0.0, idat_exe="/opt/ida/9.2/idat64"
    )
    tree_kills = []
    runtime._is_expected_ida_process = lambda pid, lease: True
    monkeypatch.setattr(
        runtime, "_kill_stale_process_tree", lambda pid: tree_kills.append(pid) or True
    )
    monkeypatch.setattr(srl.os, "kill", lambda pid, sig: None)
    runtime._cleanup_stale_runtime_leases()

    assert tree_kills == [54321]
    assert not lease_path.exists()
