"""Regression tests for p03_runtime: assorted small robustness fixes.

Covers: shlex empty-entry rejection in _normalize_ida_args, sibling stderr-log
derivation, host-wide RUSAGE labels in the state snapshot, the startup-timeout
env fallback, the orphan-cleanup own-group guard, and the analysis watchdog's
use of analysis.active to avoid false stall verdicts.
"""

import io
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin

SID = "AB12CDEF"


class _Host(ServerRuntimeMixin):
    pass


def test_normalize_ida_args_rejects_empty_shlex_entries():
    """shlex.split('a "" b') -> ['a', '', 'b']; the empty entry must be
    rejected just like an explicit empty list element."""
    host = _Host()
    with pytest.raises(ValueError):
        host._normalize_ida_args('a "" b')


def test_normalize_ida_args_accepts_clean_shlex_string():
    host = _Host()
    assert host._normalize_ida_args(" -p arm ") == ["-p", "arm"]


def test_get_ida_diagnostics_derives_sibling_stderr_log(tmp_path):
    """ida_stdout.log must map to ida_stderr.log (no trailing underscore)."""
    host = _Host()
    out = tmp_path / "ida_stdout.log"
    err = tmp_path / "ida_stderr.log"
    out.write_text("stdout line", encoding="utf-8")
    err.write_text("stderr line", encoding="utf-8")

    diag = host._get_ida_diagnostics(str(out), None, tail_lines=40)

    assert "[stdout]" in diag
    assert "stdout line" in diag
    assert "[stderr]" in diag
    assert "stderr line" in diag


def test_collect_snapshot_labels_rusage_as_host_wide():
    """RUSAGE_CHILDREN stats are cumulative across the host, so they must not
    be presented as per-session process stats."""
    host = _Host()

    class _Proc:
        pid = 12345

        def poll(self):
            return None

    snapshot = host._collect_ida_state_snapshot(
        runtime={"process": _Proc()}, include_process_stats=True
    )
    assert snapshot.get("process_alive") is True
    assert "host_rusage_cpu_user_sec" in snapshot
    assert "process_cpu_user_sec" not in snapshot


def test_resolve_startup_timeout_falls_back_on_bad_env(monkeypatch):
    monkeypatch.setenv("IDA_MCP_STARTUP_TIMEOUT", "300s")
    assert server_runtime_mod._resolve_startup_timeout() == 240
    monkeypatch.setenv("IDA_MCP_STARTUP_TIMEOUT", "30")
    assert server_runtime_mod._resolve_startup_timeout() == 30


def test_terminate_ida_processes_does_not_killpg_shared_group(monkeypatch):
    """A stale process that shares another process group must be signalled by
    pid only — killpg would take out the MCP server's whole group."""
    host = _Host()
    target = "/tmp/target.bin"

    # Force the dependency-free /proc fallback: production prefers psutil when
    # it is installed, and this test's mocks target the /proc scanner.
    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(server_runtime_mod.os, "listdir", lambda path: ["4242"])
    real_open = open

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/4242/cmdline":
            return io.BytesIO(
                b"/opt/ida/idat64\x00/tmp/target.bin\x00"
            )
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    monkeypatch.setattr(
        os.path, "realpath",
        lambda p: "/opt/ida/idat64" if "/exe" in str(p) else str(p),
    )
    calls = []
    monkeypatch.setattr(server_runtime_mod.os, "getpgid", lambda pid: 9999)
    monkeypatch.setattr(
        server_runtime_mod.os, "kill", lambda pid, sig: calls.append(("kill", sig))
    )
    monkeypatch.setattr(
        server_runtime_mod.os, "killpg", lambda pgid, sig: calls.append(("killpg", sig))
    )

    killed = host._terminate_ida_processes_for_path(target)

    assert killed == [4242]
    assert calls == [("kill", server_runtime_mod.signal.SIGTERM)]
    assert not any(kind == "killpg" for kind, _ in calls)


def test_terminate_ida_processes_killpgs_own_group(monkeypatch):
    """A stale process that leads its own process group may still have the
    whole tree signalled."""
    host = _Host()
    target = "/tmp/target.bin"

    # Force the dependency-free /proc fallback: production prefers psutil when
    # it is installed, and this test's mocks target the /proc scanner.
    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(server_runtime_mod.os, "listdir", lambda path: ["4242"])
    real_open = open

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/4242/cmdline":
            return io.BytesIO(
                b"/opt/ida/idat64\x00/tmp/target.bin\x00"
            )
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    monkeypatch.setattr(
        os.path, "realpath",
        lambda p: "/opt/ida/idat64" if "/exe" in str(p) else str(p),
    )
    calls = []
    monkeypatch.setattr(server_runtime_mod.os, "getpgid", lambda pid: pid)  # own group
    monkeypatch.setattr(
        server_runtime_mod.os, "kill", lambda pid, sig: calls.append(("kill", sig))
    )
    monkeypatch.setattr(
        server_runtime_mod.os, "killpg", lambda pgid, sig: calls.append(("killpg", sig))
    )

    killed = host._terminate_ida_processes_for_path(target)

    assert killed == [4242]
    assert calls == [("killpg", server_runtime_mod.signal.SIGTERM)]


# ---------------------------------------------------------------------------
# Analysis watchdog: analysis.active must suppress false stall verdicts
# ---------------------------------------------------------------------------


class _WatchdogHost(ServerRuntimeMixin):
    def __init__(self, state):
        self._analysis_watchdog_lock = threading.RLock()
        self._analysis_watchdog_threads = {}
        self._analysis_watchdog_stop_events = {}
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {SID: {"port": 9999}}
        self._analysis_watchdog_interval = 0.01
        self._analysis_watchdog_stall_seconds = 0.05
        self.state = state
        self.verdicts = []

    def _runtime_alive(self, runtime):
        return True

    def _query_ida_state(self, sid, timeout=3.0):
        return self.state

    def _update_session_indexing_metadata(self, session_id, **updates):
        self.verdicts.append(updates.get("analysis_state"))


def test_watchdog_never_flags_active_analysis_as_stalled():
    """A flat function count during an active analysis pass (FLIRT/struct
    layout etc.) must not be reported as 'stalled'."""
    state = {
        "ok": True,
        "analysis": {"is_ok": False, "active": True},
        "inventory": {"functions_qty": 5},
    }
    host = _WatchdogHost(state)
    host._start_analysis_watchdog(SID, 9999)
    time.sleep(0.3)
    host._stop_analysis_watchdog(SID)

    assert host.verdicts[0] == "starting"
    assert "stalled" not in host.verdicts


def test_watchdog_flags_inactive_flat_analysis_as_stalled():
    """When analysis is NOT active and the function count is flat past the
    threshold, the session is genuinely stalled."""
    state = {
        "ok": True,
        "analysis": {"is_ok": False, "active": False},
        "inventory": {"functions_qty": 5},
    }
    host = _WatchdogHost(state)
    host._start_analysis_watchdog(SID, 9999)
    time.sleep(0.3)
    host._stop_analysis_watchdog(SID)

    assert "stalled" in host.verdicts
