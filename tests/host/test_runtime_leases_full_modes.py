"""Additional platform and lifecycle coverage for runtime leases."""

from __future__ import annotations

import builtins
import json
import os
import signal
import subprocess
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime_leases as leases_mod
from ida_pro_mcp.host.server.server_runtime_leases import ServerRuntimeLeasesMixin

SID = "A1B2C3D4"


class _Runtime(ServerRuntimeLeasesMixin):
    def __init__(self, tmp_path):
        self._runtime_lease_dir = str(tmp_path)
        self._runtime_lock = __import__("threading").RLock()
        self.session_runtimes = {}
        self.idat_exe = "/opt/ida/idat64"
        self._runtime_owner_id = "owner"

    @staticmethod
    def _ida_binary_names():
        return ["idat64", "ida64"]


class _Clock:
    def __init__(self, values):
        self.values = iter(values)

    def __call__(self):
        return next(self.values)


def _lease_path(tmp_path, sid=SID):
    return tmp_path / f"SID_{sid}.lease.json"


def test_lease_scalar_parsers_and_proc_stat_edges(monkeypatch):
    assert [leases_mod._lease_pid(v) for v in (True, False, 12, " 34 ", "", "-1", "１２")] == [0, 0, 12, 34, 0, 0, 0]
    assert leases_mod._lease_timestamp("bad") == 0.0
    assert leases_mod._lease_timestamp(float("nan")) == 0.0
    assert leases_mod._lease_timestamp(float("inf")) == 0.0
    assert leases_mod._lease_timestamp("2.5") == 2.5
    assert leases_mod.ServerRuntimeLeasesMixin._parse_proc_stat("bad") is None
    assert leases_mod.ServerRuntimeLeasesMixin._parse_proc_stat("1 (cmd) S 2") is None
    assert leases_mod.ServerRuntimeLeasesMixin._parse_proc_stat("1 (cmd with ) parens) S 2 3 4") == {
        "state": "S",
        "ppid": 2,
        "pgrp": 3,
        "session": 4,
    }

    monkeypatch.setattr(leases_mod.sys, "platform", "darwin")
    assert leases_mod._process_start_token(123) == ""
    assert leases_mod._process_start_token(0) == ""


def test_lease_write_remove_and_pid_compare_paths(tmp_path):
    runtime = _Runtime(tmp_path)
    runtime._write_runtime_lease_record(str(_lease_path(tmp_path)), {"pid": 11, "updated_at": 1})
    assert json.loads(_lease_path(tmp_path).read_text())["pid"] == 11
    runtime._remove_runtime_lease_if_pid_matches(SID, 12)
    assert _lease_path(tmp_path).exists()
    runtime._remove_runtime_lease_if_pid_matches(SID, 11)
    assert not _lease_path(tmp_path).exists()
    runtime._remove_runtime_lease_if_pid_matches(SID, 11)
    runtime._remove_runtime_lease(SID)
    runtime._write_runtime_lease(SID, {"process": None})
    runtime._write_runtime_lease(SID, {"process": SimpleNamespace(pid=44), "port": 5000})
    stored = json.loads(_lease_path(tmp_path).read_text())
    assert stored["session_id"] == SID and stored["pid"] == 44


@pytest.mark.parametrize(
    ("first", "expected"),
    [(ProcessLookupError(), True), (PermissionError(), False)],
)
def test_kill_stale_pid_first_probe_errors(monkeypatch, first, expected):
    runtime = _Runtime("/tmp")

    def kill(_pid, _sig):
        raise first

    monkeypatch.setattr(leases_mod.os, "kill", kill)
    assert runtime._kill_stale_pid(9) is expected
    assert runtime._kill_stale_pid(0) is False


def test_kill_stale_pid_escalates_and_confirms_exit(monkeypatch):
    runtime = _Runtime("/tmp")
    calls = []
    probes = iter([None, None, ProcessLookupError()])

    def kill(_pid, sig):
        calls.append(sig)
        if sig == 0:
            value = next(probes)
            if isinstance(value, BaseException):
                raise value
        elif sig == signal.SIGKILL:
            return None

    monkeypatch.setattr(leases_mod.os, "kill", kill)
    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(leases_mod.time, "time", _Clock([0.0, 0.0, 2.0, 2.0]))
    assert runtime._kill_stale_pid(9) is True
    assert calls == [0, signal.SIGTERM, 0, signal.SIGKILL, 0]


def test_linux_process_identity_uses_exe_then_cmdline(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    runtime.idat_exe = ""
    monkeypatch.setattr(leases_mod.sys, "platform", "linux")
    monkeypatch.setattr(leases_mod.os.path, "realpath", lambda path: "/opt/ida/idat64" if str(path).endswith("/exe") else str(path))
    assert runtime._is_expected_ida_process(9, {"idat_exe": ""}) is True

    monkeypatch.setattr(leases_mod.os.path, "realpath", lambda path: "/usr/bin/other" if str(path).endswith("/exe") else str(path))
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path).endswith("/cmdline"):
            return __import__("io").BytesIO(b"/opt/ida/ida64\x00--headless\x00")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert runtime._is_expected_ida_process(9, {"idat_exe": ""}) is True
    monkeypatch.setattr(builtins, "open", lambda *a, **k: (_ for _ in ()).throw(OSError("gone")))
    assert runtime._is_expected_ida_process(9, {"idat_exe": ""}) is False


def test_process_group_identity_and_live_member_scans(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.os, "listdir", lambda _path: ["x", "10", "11"])
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path).endswith("/10/stat"):
            return __import__("io").BytesIO(b"10 (other) S 1 99 1")
        if str(path).endswith("/11/stat"):
            return __import__("io").BytesIO(b"11 (ida) Z 1 99 1")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(runtime, "_proc_is_ida_named", lambda pid: pid == 10)
    assert runtime._proc_group_has_ida_member(99) is True
    assert runtime._proc_group_has_ida_member(100) is False
    assert runtime._proc_group_has_live_member(99) is True
    monkeypatch.setattr(leases_mod.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("proc")))
    assert runtime._proc_group_has_live_member(99) is True


def test_windows_process_map_and_descendant_walk(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.sys, "platform", "win32")
    runtime._ida_binary_names = lambda: ["idat64.exe", "ida64.exe"]
    output = """Name=launcher.exe
ParentProcessId=1
ProcessId=10

Name=IDA64.EXE
ParentProcessId=10
ProcessId=11

garbage
Name=child.exe
ParentProcessId=11
ProcessId=12
"""
    monkeypatch.setattr(leases_mod.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=output))
    children, names = runtime._win32_process_map()
    assert children[10] == [11] and names[11] == "ida64.exe"
    assert runtime._win32_ida_descendant_alive(10) is True
    assert runtime._win32_ida_descendant_alive(0) is False
    assert runtime._collect_descendant_pids(10, max_depth=2) == [11, 12]

    monkeypatch.setattr(leases_mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("wmic")))
    assert runtime._win32_process_map() == ({}, {})


def test_collect_descendants_macos_and_linux_fallbacks(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.sys, "platform", "darwin")
    calls = []

    def pgrep(command, *_args, **_kwargs):
        calls.append(command[-1])
        return SimpleNamespace(stdout="20 bad\n21") if len(calls) == 1 else SimpleNamespace(stdout="")

    monkeypatch.setattr(leases_mod.subprocess, "run", pgrep)
    assert runtime._collect_descendant_pids(10, max_depth=2) == [20, 21]
    assert runtime._collect_descendant_pids(0) == []

    monkeypatch.setattr(leases_mod.sys, "platform", "linux")
    monkeypatch.setattr(leases_mod.os, "listdir", lambda _path: ["20", "21"])
    monkeypatch.setattr(runtime, "_parse_proc_stat", lambda data: {"ppid": 10, "pgrp": 1, "state": "S", "session": 1} if "20" in data else None)
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda path, *a, **k: __import__("io").BytesIO(str(path).encode()) if "/stat" in str(path) else real_open(path, *a, **k))
    assert runtime._collect_descendant_pids(10) == [20]


def test_runtime_tree_and_process_tree_kill_modes(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.sys, "platform", "linux")
    monkeypatch.setattr(leases_mod.os, "killpg", lambda pid, sig: None if sig == 0 else None)
    monkeypatch.setattr(runtime, "_proc_group_has_ida_member", lambda pid: True)
    assert runtime._runtime_tree_still_alive(10) is True
    monkeypatch.setattr(leases_mod.os, "killpg", lambda *_a: (_ for _ in ()).throw(ProcessLookupError()))
    assert runtime._runtime_tree_still_alive(10) is False
    monkeypatch.setattr(leases_mod.os, "getpgid", lambda _pid: 10)
    monkeypatch.setattr(runtime, "_kill_stale_process_group", lambda pid: pid == 10)
    assert runtime._kill_stale_process_tree(10) is True

    monkeypatch.setattr(leases_mod.os, "getpgid", lambda _pid: 99)
    monkeypatch.setattr(runtime, "_collect_descendant_pids", lambda _pid: [11, 12])
    killed = []
    monkeypatch.setattr(leases_mod.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(runtime, "_kill_stale_pid", lambda _pid: True)
    assert runtime._kill_stale_process_tree(10) is True
    assert killed == [(11, signal.SIGKILL), (12, signal.SIGKILL)]

    monkeypatch.setattr(leases_mod.sys, "platform", "win32")
    executed = []
    monkeypatch.setattr(leases_mod.subprocess, "run", lambda *args, **kwargs: executed.append(args[0]) or SimpleNamespace(stdout=""))
    assert runtime._kill_stale_process_tree(10) is True
    assert executed[0][:3] == ["taskkill", "/T", "/F"]


def test_group_kill_escalation_and_ownership_guards(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    calls = []
    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(leases_mod.time, "time", _Clock([0.0, 0.0, 2.0, 2.0]))
    monkeypatch.setattr(leases_mod.os, "killpg", lambda pgid, sig: calls.append(sig) or None)
    monkeypatch.setattr(runtime, "_proc_group_has_live_member", lambda _pgid: True)
    assert runtime._kill_stale_process_group(10) is False
    assert calls == [signal.SIGTERM, 0, signal.SIGKILL, 0]
    assert runtime._kill_stale_process_group(0) is False

    monkeypatch.setattr(leases_mod.os, "kill", lambda *_a: (_ for _ in ()).throw(PermissionError()))
    assert runtime._lease_has_live_foreign_owner({"owner_pid": 999}) is True
    monkeypatch.setattr(leases_mod.os, "kill", lambda *_a: (_ for _ in ()).throw(ProcessLookupError()))
    assert runtime._lease_has_live_foreign_owner({"owner_pid": 999}) is False
    assert runtime._lease_has_live_foreign_owner({"owner_pid": os.getpid()}) is False
    assert runtime._lease_has_live_foreign_owner({"owner_pid": "bad"}) is False


def test_rewrite_lease_and_cleanup_malformed_entries(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    path = _lease_path(tmp_path)
    path.write_text("{bad", encoding="utf-8")
    assert runtime._rewrite_lease_if_unchanged(str(path), {"updated_at": 1}, 1) is False
    path.write_text(json.dumps({"updated_at": "bad"}), encoding="utf-8")
    assert runtime._rewrite_lease_if_unchanged(str(path), {"updated_at": 1}, 1) is False
    path.write_text(json.dumps({"updated_at": 1}), encoding="utf-8")
    assert runtime._rewrite_lease_if_unchanged(str(path), {"updated_at": 1, "last_error": "x"}, 1) is True
    assert json.loads(path.read_text())["last_error"] == "x"

    (tmp_path / "SID_BADBADBA.lease.json").write_text("{bad", encoding="utf-8")
    (tmp_path / "SID_A1B2C3D5.lease.json").write_text(json.dumps({"session_id": "WRONG", "pid": 0}), encoding="utf-8")
    runtime._cleanup_stale_runtime_leases()
    assert not (tmp_path / "SID_BADBADBA.lease.json").exists()
    assert not (tmp_path / "SID_A1B2C3D5.lease.json").exists()


def test_shutdown_closes_all_optional_resources_once(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    runtime._shutdown = False
    runtime._shutdown_requested = False
    runtime._lease_thread_stop = __import__("threading").Event()
    runtime._lease_thread = None
    runtime._cleanup_all_runtimes = lambda: setattr(runtime, "cleaned", True)
    runtime.assembler = SimpleNamespace(stop=lambda: setattr(runtime.assembler, "stopped", True))
    runtime._usage_intel = SimpleNamespace(stop=lambda: setattr(runtime._usage_intel, "stopped", True))
    index = SimpleNamespace(save=lambda: setattr(index, "saved", True))
    runtime._insight_indexes = {"default": index}
    runtime._global_facts = SimpleNamespace(close=lambda: setattr(runtime._global_facts, "closed", True))
    runtime.audit = SimpleNamespace(close=lambda: setattr(runtime.audit, "closed", True))
    runtime._stop_analysis_completion_watchers = lambda: setattr(runtime, "watchers_stopped", True)
    runtime.shutdown()
    runtime.shutdown()
    assert runtime.cleaned and runtime.assembler.stopped and runtime._usage_intel.stopped
    assert index.saved and runtime._global_facts.closed and runtime.audit.closed
    assert runtime.watchers_stopped
