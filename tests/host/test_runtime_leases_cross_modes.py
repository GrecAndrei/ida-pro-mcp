"""Cross-platform and lifecycle coverage for runtime lease ownership."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import types

import pytest

from ida_pro_mcp.host.server import server_runtime_leases as leases
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin


class _Runtime(ServerRuntimeLeasesMixin):
    def __init__(self, root):
        self._runtime_lease_dir = str(root)
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self.idat_exe = "/opt/ida/idat64"
        self._runtime_owner_id = "owner-a"
        self._shutdown = False
        self._shutdown_requested = False
        self._lease_thread = None
        self._lease_thread_stop = threading.Event()

    @staticmethod
    def _ida_binary_names():
        return ["idat", "idat64", "ida"]


class _Proc:
    def __init__(self, pid=4242, state=None):
        self.pid = pid
        self._state = state
        self.writes = 0

    def poll(self):
        return self._state


def _lease(root, sid="A1B2C3D4", updated_at=0.0, **overrides):
    record = {
        "session_id": sid,
        "pid": 4242,
        "port": 18000,
        "idat_exe": "/opt/ida/idat64",
        "updated_at": updated_at,
    }
    record.update(overrides)
    path = root / f"SID_{sid}.lease.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_lease_value_parsers_and_proc_stat_are_fail_closed():
    assert [leases._lease_pid(v) for v in (12, " 13 ", True, 0, -1, "", "1.5", "１２")] == [12, 13, 0, 0, 0, 0, 0, 0]
    assert leases._lease_timestamp("4.5") == 4.5
    assert leases._lease_timestamp(float("inf")) == 0.0
    assert leases._lease_timestamp(-1) == 0.0
    assert ServerRuntimeLeasesMixin._parse_proc_stat("42 (ida worker) S 1 2 3 4") == {
        "state": "S",
        "ppid": 1,
        "pgrp": 2,
        "session": 3,
    }
    assert ServerRuntimeLeasesMixin._parse_proc_stat("missing close (S 1 2 3") is None
    assert ServerRuntimeLeasesMixin._parse_proc_stat("42 (ida) S bad 2 3") is None


def test_lease_write_remove_and_pid_guard_round_trip(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    proc = _Proc()
    runtime._write_runtime_lease("A1B2C3D4", {"process": proc, "port": "19000"})
    path = tmp_path / "SID_A1B2C3D4.lease.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["pid"] == 4242
    assert record["port"] == 19000
    assert record["owner_id"] == "owner-a"

    runtime._remove_runtime_lease_if_pid_matches("A1B2C3D4", 99)
    assert path.exists()
    runtime._remove_runtime_lease_if_pid_matches("A1B2C3D4", 4242)
    assert not path.exists()
    runtime._remove_runtime_lease("missing")

    monkeypatch.setattr(leases, "fcntl", None)
    runtime._write_runtime_lease("A1B2C3D4", {"process": proc, "port": 19001})
    assert path.exists()
    monkeypatch.setattr(leases.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("replace")))
    runtime._write_runtime_lease_record(str(path), {"bad": True})
    assert path.exists()


def test_process_identity_and_group_scans_cover_linux_fallbacks(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases.sys, "platform", "linux")

    def fake_realpath(path):
        return "/opt/ida/idat64" if str(path).endswith("/exe") else str(path)

    monkeypatch.setattr(leases.os.path, "realpath", fake_realpath)
    monkeypatch.setattr("builtins.open", lambda path, *args, **kwargs: types.SimpleNamespace(
        read=lambda: b"/opt/ida/idat64\x00--ida-arg\x00" if str(path).endswith("cmdline") else ""
    ))
    assert runtime._proc_is_ida_named(4242) is True
    assert runtime._is_expected_ida_process(4242, {}) is True

    monkeypatch.setattr(leases.os.path, "realpath", lambda _path: "/usr/bin/python")
    assert runtime._is_expected_ida_process(4242, {}) is True  # cmdline remains authoritative
    runtime.idat_exe = ""
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("hidden")))
    assert runtime._proc_is_ida_named(4242) is False
    assert runtime._is_expected_ida_process(4242, {}) is False

    proc_stat = "12 (ida worker) S 1 77 77 0"
    monkeypatch.setattr(leases.os, "listdir", lambda _path: ["12", "bad", "13"])
    # Use a real context-manager wrapper because the production scanner uses ``with open``.
    class _File:
        def __init__(self, value):
            self.value = value
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return self.value
    monkeypatch.setattr("builtins.open", lambda path, *args, **kwargs: _File(proc_stat.encode()) if str(path).endswith("/12/stat") else (_ for _ in ()).throw(OSError("gone")))
    runtime._proc_is_ida_named = lambda pid: pid == 12
    assert runtime._proc_group_has_ida_member(77) is True
    runtime._proc_is_ida_named = lambda _pid: False
    assert runtime._proc_group_has_ida_member(77) is False
    assert runtime._proc_group_has_live_member(77) is True
    monkeypatch.setattr(leases.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("proc")))
    assert runtime._proc_group_has_live_member(77) is True


def test_windows_process_map_descendant_and_identity_modes(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases.sys, "platform", "win32")
    runtime._ida_binary_names = lambda: ["idat64.exe", "ida.exe"]
    output = """Name=idat64.exe
ParentProcessId=10
ProcessId=20

Name=ida.exe
ParentProcessId=20
ProcessId=30

Name=bad.exe
ParentProcessId=x
ProcessId=bad
"""
    monkeypatch.setattr(leases.subprocess, "run", lambda *args, **kwargs: types.SimpleNamespace(stdout=output))
    children, names = runtime._win32_process_map()
    assert children == {10: [20], 20: [30]}
    assert names[20] == "idat64.exe"
    assert runtime._win32_ida_descendant_alive(10) is True
    assert runtime._win32_ida_descendant_alive(30) is False
    assert runtime._collect_descendant_pids(10) == [20, 30]
    monkeypatch.setattr(leases.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("wmic")))
    assert runtime._win32_process_map() == ({}, {})
    assert runtime._win32_ida_descendant_alive(10) is False


def test_stale_kill_paths_escalate_and_preserve_uncertain_processes(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases.time, "time", lambda: 0.0)
    monkeypatch.setattr(leases.time, "sleep", lambda _seconds: None)
    calls = []
    probe_count = {"value": 0}

    def kill(pid, sig):
        calls.append((pid, sig))
        if sig == 0:
            probe_count["value"] += 1
            if probe_count["value"] > 2:
                raise ProcessLookupError()

    monkeypatch.setattr(leases.os, "kill", kill)
    monkeypatch.setattr(leases, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.1)
    assert runtime._kill_stale_pid(4242) is True
    assert (4242, signal.SIGTERM) in calls
    assert runtime._kill_stale_pid(0) is False
    assert runtime._kill_stale_process_group(0) is False

    monkeypatch.setattr(leases.os, "getpgid", lambda _pid: 4242)
    group_calls = []
    def killpg(pid, sig):
        group_calls.append((pid, sig))
        if sig == 0:
            raise ProcessLookupError()
    monkeypatch.setattr(leases.os, "killpg", killpg)
    assert runtime._kill_stale_process_tree(4242) is True
    assert group_calls[0] == (4242, signal.SIGTERM)
    monkeypatch.setattr(leases.sys, "platform", "darwin")
    monkeypatch.setattr(runtime, "_collect_descendant_pids", lambda _pid: [11, 12])
    monkeypatch.setattr(leases.os, "getpgid", lambda _pid: 9999)
    assert runtime._kill_stale_process_tree(4242) is True


def test_stale_cleanup_handles_malformed_fresh_dead_recycled_and_failed_records(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases.time, "time", lambda: 1000.0)
    (tmp_path / "not-a-lease").write_text("x", encoding="utf-8")
    (tmp_path / "SID_BADC0DE6.lease.json").write_text("not json", encoding="utf-8")
    _lease(tmp_path, sid="BADC0DE1", session_id="WRONG")
    _lease(tmp_path, sid="BADC0DE2", pid=0)
    _lease(tmp_path, sid="BADC0DE3", pid=111, updated_at=9999999999.0)
    _lease(tmp_path, sid="BADC0DE4", pid=222)
    _lease(tmp_path, sid="BADC0DE5", pid=333)

    def kill(pid, sig):
        if pid in {111, 222, 333}:
            if pid == 111:
                return None
            if pid == 222:
                raise ProcessLookupError()
            return None
        raise ProcessLookupError()

    monkeypatch.setattr(leases.os, "kill", kill)
    monkeypatch.setattr(runtime, "_is_expected_ida_process", lambda pid, _lease: pid == 333)
    monkeypatch.setattr(runtime, "_kill_stale_process_tree", lambda pid: pid == 333 and False)
    monkeypatch.setattr(leases, "STALE_CLEANUP_BUDGET_SECONDS", 100.0)
    runtime._cleanup_stale_runtime_leases()
    assert not (tmp_path / "SID_BADC0DE6.lease.json").exists()
    assert not (tmp_path / "SID_BADC0DE1.lease.json").exists()
    assert not (tmp_path / "SID_BADC0DE2.lease.json").exists()
    assert (tmp_path / "SID_BADC0DE3.lease.json").exists()
    assert not (tmp_path / "SID_BADC0DE4.lease.json").exists()
    failed = json.loads((tmp_path / "SID_BADC0DE5.lease.json").read_text(encoding="utf-8"))
    assert failed["last_error"] == "terminate_failed"


def test_heartbeat_transitions_and_shutdown_are_idempotent(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    live = _Proc(state=None)
    exited = _Proc(state=0)
    runtime.session_runtimes = {"A1B2C3D4": {"process": live, "port": 1}, "BADC0DE1": {"process": exited, "port": 2}, "BADC0DE2": {}}
    runtime._runtime_tree_still_alive = lambda pid: pid == exited.pid
    runtime._write_runtime_lease = lambda sid, item: item["process"].__setattr__("writes", item["process"].writes + 1)
    removed = []
    runtime._remove_runtime_lease_if_pid_matches = lambda sid, pid: removed.append((sid, pid))
    runtime._lease_thread_stop.set()
    runtime._lease_thread_stop.clear()
    stop = runtime._lease_thread_stop
    stop.set()
    runtime._lease_heartbeat_loop()
    assert live.writes == 0  # stop is checked before a tick

    class _StopAfterFirst:
        def __init__(self):
            self.calls = 0
        def wait(self, _seconds):
            self.calls += 1
            return self.calls > 1
        def clear(self):
            pass
        def set(self):
            pass

    runtime._shutdown_requested = False
    runtime._lease_thread_stop = _StopAfterFirst()
    runtime._lease_heartbeat_loop()
    assert live.writes == 1
    assert removed == []  # both live and surviving IDA child refresh

    runtime._lease_thread_stop = threading.Event()
    runtime._cleanup_all_runtimes = lambda: None
    monkeypatch.setattr(runtime, "_cleanup_all_runtimes", lambda: None)
    runtime.shutdown()
    runtime.shutdown()
    assert runtime._shutdown is True
