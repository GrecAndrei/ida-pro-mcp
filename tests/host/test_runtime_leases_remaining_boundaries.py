"""Exercise the remaining stale-lease and shutdown failure modes."""

from __future__ import annotations

import builtins
import io
import json
import signal
import threading
from types import SimpleNamespace

from ida_pro_mcp.host.server import server_runtime_leases as leases_mod
from tests.host.test_runtime_leases_full_modes import _Runtime


def test_stale_pid_handles_signal_races_and_unverifiable_probes(monkeypatch):
    runtime = _Runtime("/tmp")
    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.0)

    def term_race(_pid, sig):
        if sig == signal.SIGTERM:
            raise ProcessLookupError()

    monkeypatch.setattr(leases_mod.os, "kill", term_race)
    assert runtime._kill_stale_pid(9) is True

    def term_denied(_pid, sig):
        if sig == signal.SIGTERM:
            raise PermissionError()

    monkeypatch.setattr(leases_mod.os, "kill", term_denied)
    assert runtime._kill_stale_pid(9) is False

    probes = iter([None, None, OSError("probe")])

    def probe_denied(_pid, sig):
        if sig == 0:
            event = next(probes)
            if isinstance(event, BaseException):
                raise event

    monkeypatch.setattr(leases_mod.os, "kill", probe_denied)
    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 1.0)
    assert runtime._kill_stale_pid(9) is False

    for final_error, expected in ((ProcessLookupError(), True), (PermissionError(), False)):
        probes = iter([None, final_error])

        def kill_after_escalation(_pid, sig, probes=probes):
            if sig == 0:
                event = next(probes)
                if isinstance(event, BaseException):
                    raise event

        monkeypatch.setattr(leases_mod.os, "kill", kill_after_escalation)
        monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.0)
        assert runtime._kill_stale_pid(9) is expected


def test_stale_process_group_handles_probe_and_escalation_failures(monkeypatch):
    runtime = _Runtime("/tmp")
    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(
        leases_mod.os,
        "killpg",
        lambda _pgid, sig: (_ for _ in ()).throw(PermissionError())
        if sig == signal.SIGTERM
        else None,
    )
    assert runtime._kill_stale_process_group(9) is False

    monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(leases_mod.time, "time", lambda: 0.0)
    monkeypatch.setattr(
        leases_mod.os,
        "killpg",
        lambda _pgid, sig: (_ for _ in ()).throw(OSError("probe")) if sig == 0 else None,
    )
    assert runtime._kill_stale_process_group(9) is True

    for escalation_error, expected in ((ProcessLookupError(), True), (PermissionError(), False)):
        calls = []

        def killpg(_pgid, sig, calls=calls, escalation_error=escalation_error):
            calls.append(sig)
            if sig == signal.SIGKILL:
                raise escalation_error

        monkeypatch.setattr(leases_mod.os, "killpg", killpg)
        monkeypatch.setattr(leases_mod, "PROCESS_TERMINATION_TIMEOUT_SECONDS", 0.0)
        assert runtime._kill_stale_process_group(9) is expected

    calls = []

    def final_probe(_pgid, sig):
        calls.append(sig)
        if sig == 0 and len(calls) > 2:
            raise PermissionError()

    monkeypatch.setattr(leases_mod.os, "killpg", final_probe)
    assert runtime._kill_stale_process_group(9) is False


def test_process_tree_and_identity_helpers_fail_closed_on_platform_errors(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.sys, "platform", "darwin")
    monkeypatch.setattr(
        leases_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("pgrep")),
    )
    assert runtime._collect_descendant_pids(9) == []

    monkeypatch.setattr(leases_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        leases_mod.os,
        "listdir",
        lambda _path: (_ for _ in ()).throw(OSError("proc")),
    )
    assert runtime._collect_descendant_pids(9) == []
    assert runtime._proc_group_has_ida_member(9) is False

    real_open = builtins.open
    realpath = leases_mod.os.path.realpath
    monkeypatch.setattr(runtime, "_ida_binary_names", lambda: ["idat64"])
    monkeypatch.setattr(
        leases_mod.os.path,
        "realpath",
        lambda _path: (_ for _ in ()).throw(OSError("exe")),
    )

    def cmdline(path, *args, **kwargs):
        if str(path).endswith("/cmdline"):
            return io.BytesIO(b"/opt/ida/idat64\x00--headless\x00")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", cmdline)
    assert runtime._proc_is_ida_named(9) is True

    monkeypatch.setattr(leases_mod.os.path, "realpath", realpath)
    monkeypatch.setattr(
        leases_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=""),
    )
    monkeypatch.setattr(leases_mod.sys, "platform", "darwin")
    assert runtime._platform_pid_is_ida_process(9, {}) is False


def test_lease_record_and_foreign_owner_identity_edges(tmp_path, monkeypatch):
    runtime = _Runtime(tmp_path)
    path = tmp_path / "SID_A1B2C3D4.lease.json"
    path.write_text("[]", encoding="utf-8")
    runtime._remove_runtime_lease_if_pid_matches("A1B2C3D4", 9)
    assert path.exists()

    monkeypatch.setattr(leases_mod.os, "kill", lambda *_args: None)
    monkeypatch.setattr(leases_mod, "_process_start_token", lambda _pid: "")
    assert runtime._lease_has_live_foreign_owner({"owner_pid": 999, "owner_start_token": "old"}) is True
    monkeypatch.setattr(leases_mod, "_process_start_token", lambda _pid: "new")
    assert runtime._lease_has_live_foreign_owner({"owner_pid": 999, "owner_start_token": "old"}) is False


def test_heartbeat_and_shutdown_optional_failure_paths(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    runtime._lease_thread_stop = threading.Event()
    runtime._lease_thread = SimpleNamespace(is_alive=lambda: True)
    runtime._start_runtime_lease_heartbeat()

    class _Stop:
        def __init__(self):
            self.calls = 0

        def wait(self, _seconds):
            self.calls += 1
            return self.calls > 1

        def set(self):
            pass

        def clear(self):
            pass

    runtime._lease_thread_stop = _Stop()
    runtime._shutdown_requested = False
    item = {"process": SimpleNamespace(pid=3, poll=lambda: None)}
    runtime.session_runtimes = {"sid": item}

    def rewrite(_sid, _runtime):
        runtime.session_runtimes["sid"] = {}

    runtime._write_runtime_lease = rewrite
    runtime._lease_heartbeat_loop()

    runtime = _Runtime(tmp_path / "shutdown")
    runtime._shutdown = False
    runtime._shutdown_requested = False
    runtime._lease_thread_stop = threading.Event()
    runtime._lease_thread = None
    runtime._cleanup_all_runtimes = lambda: None
    runtime.assembler = SimpleNamespace(stop=lambda: (_ for _ in ()).throw(OSError("embedder")))
    runtime._insight_index = SimpleNamespace(save=lambda: (_ for _ in ()).throw(OSError("index")))
    runtime._global_facts = SimpleNamespace(close=lambda: (_ for _ in ()).throw(OSError("facts")))
    runtime.audit = SimpleNamespace(close=lambda: (_ for _ in ()).throw(OSError("audit")))
    runtime.shutdown()
    assert runtime._shutdown is True


def test_lifecycle_registration_survives_signal_registration_errors(monkeypatch, tmp_path):
    runtime = _Runtime(tmp_path)
    monkeypatch.setattr(leases_mod.atexit, "register", lambda _fn: None)
    monkeypatch.setattr(leases_mod.signal, "SIGINT", None)
    monkeypatch.setattr(
        leases_mod.signal,
        "signal",
        lambda *_args: (_ for _ in ()).throw(OSError("signal")),
    )
    runtime._register_lifecycle_handlers()
