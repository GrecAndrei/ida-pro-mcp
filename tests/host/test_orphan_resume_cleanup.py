"""Tests for session-resume orphan cleanup.

Bug class: resuming a session whose IDA runtime was killed abruptly (host
SIGKILL/crash) leaves the orphaned `idat` holding the unpacked IDB sidecars
(.id0/.id1/.nam). The next open fails with "Database initialization failed
with error 4". The old `_terminate_ida_processes_for_path` was a silent no-op
on Linux (psutil not installed, `wmic` fallback is Windows-only), and it was
only invoked for packed-IDB sessions anyway.
"""
from __future__ import annotations

import builtins
import os
import sys
from io import BytesIO

import pytest

from ida_pro_mcp.host.server import server_runtime
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _OrphanKillHarness(ServerRuntimeMixin):
    """Minimal ServerRuntimeMixin for orphan-kill tests."""

    _ida_dir = None

    def _ida_binary_names(self):
        return ["idat", "idat64", "ida", "ida64"]


def _psutil_module(fake_procs):
    """Build a fake psutil module exposing process_iter(attrs)."""
    mod = type(sys)("psutil")
    mod.process_iter = lambda *a, **k: fake_procs
    return mod


class _FakeProc:
    def __init__(self, info):
        self.info = info


# ---------------------------------------------------------------------------
# _terminate_ida_processes_for_path: /proc fallback (Linux, no psutil)
# ---------------------------------------------------------------------------


def test_proc_fallback_kills_only_ida_process_holding_target(monkeypatch, tmp_path):
    """The /proc fallback kills the orphan idat whose cmdline references the
    target IDB, and ignores a non-matching idat plus a non-IDA process that
    also mentions the path."""
    harness = _OrphanKillHarness()
    target = str(tmp_path / "SID_A1B2C3D4_sample.bin.i64")

    proc_files = {
        "/proc/1000/cmdline": f"/ida9/idat\x00-A\x00-Sx.py\x00{target}".encode(),
        "/proc/1001/cmdline": b"/ida9/idat\x00-A\x00/unrelated.i64",
        "/proc/2000/cmdline": f"/usr/bin/tail\x00{target}".encode(),
    }
    real_open = builtins.open

    def fake_open(path, mode="r", *args, **kwargs):
        if path in proc_files:
            return BytesIO(proc_files[path])
        return real_open(path, mode, *args, **kwargs)

    real_realpath = os.path.realpath

    def fake_realpath(path):
        if path == "/proc/1000/exe":
            return "/ida9/idat"
        if path == "/proc/2000/exe":
            return "/usr/bin/tail"
        return real_realpath(path)

    real_listdir = os.listdir

    def fake_listdir(path):
        if path == "/proc":
            return ["1000", "1001", "2000", "notapid"]
        return real_listdir(path)

    killed_groups = []
    monkeypatch.setattr(server_runtime.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "psutil", None)  # force `import psutil` to fail
    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(os.path, "realpath", fake_realpath)
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: killed_groups.append((pgid, sig)))

    killed = harness._terminate_ida_processes_for_path(target)

    assert killed == [1000]
    assert killed_groups == [(1000, server_runtime.signal.SIGTERM)]


def test_psutil_branch_used_when_available(monkeypatch, tmp_path):
    """With psutil importable the /proc fallback is bypassed entirely."""
    target = str(tmp_path / "X.i64")
    fake_procs = [
        _FakeProc({"pid": 4242, "name": "idat", "cmdline": ["/ida9/idat", "-A", target]}),
        _FakeProc({"pid": 4243, "name": "bash", "cmdline": ["/bin/bash", target]}),
    ]

    harness = _OrphanKillHarness()
    killed_groups = []
    monkeypatch.setitem(sys.modules, "psutil", _psutil_module(fake_procs))
    monkeypatch.setattr(server_runtime.sys, "platform", "linux")
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: killed_groups.append((pgid, sig)))

    killed = harness._terminate_ida_processes_for_path(target)

    assert killed == [4242]
    assert killed_groups == [(4242, server_runtime.signal.SIGTERM)]


def test_empty_target_is_noop():
    harness = _OrphanKillHarness()
    assert harness._terminate_ida_processes_for_path("") == []


# ---------------------------------------------------------------------------
# _is_orphan_locked_db_open_failure: precise error-4 detection
# ---------------------------------------------------------------------------


def test_orphan_lock_signature_detected():
    harness = _OrphanKillHarness()
    diag = (
        "IDA has found an unpacked version of database: X.i64 on the disk.\n"
        "It appears IDA did not close properly; ...\n"
        "/x/X.id0: Resource temporarily unavailable -> OK\n"
        "Database initialization failed with error 4"
    )
    assert harness._is_orphan_locked_db_open_failure(diag) is True


def test_orphan_lock_detector_rejects_other_failures():
    harness = _OrphanKillHarness()
    # Bare error 4 from a forced-processor mismatch on an existing IDB must NOT
    # route to this recovery (it cannot fix that cause).
    assert (
        harness._is_orphan_locked_db_open_failure(
            "Database initialization failed with error 4"
        )
        is False
    )
    # Library-init failures are handled by the other detector.
    assert harness._is_orphan_locked_db_open_failure("library init failed with error 2") is False
    assert harness._is_orphan_locked_db_open_failure("") is False
    assert harness._is_orphan_locked_db_open_failure(None) is False
    # Lock phrase without the database-init wording still matches.
    assert (
        harness._is_orphan_locked_db_open_failure(
            "Resource temporarily unavailable; IDA did not close properly"
        )
        is True
    )


# ---------------------------------------------------------------------------
# _start_server_inner wiring: orphan-kill on every existing-IDB reopen
# ---------------------------------------------------------------------------


class _ReachedBuildCommand(Exception):
    pass


def _boom(*a, **k):
    raise _ReachedBuildCommand()


def _make_session(tmp_path, sid: str, *, idb_exists: bool):
    from tests._isolated_repo_loader import load_repo_module

    mod = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
    binary = tmp_path / f"{sid}_sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
    idb = tmp_path / f"SID_{sid}_sample.bin.i64"
    if idb_exists:
        idb.write_bytes(b"\x00" * 64)
    return mod.Session(
        session_id=sid,
        binary_path=str(binary),
        idb_path=str(idb),
        analysis_options={},
    )


class _StartServerHarness(ServerRuntimeMixin):
    idat_exe = "/bin/true"
    ida_dir = None
    cache_dir = "."
    _runtime_owner_id = "testowner"
    session_runtimes = {}

    def _is_executable_file(self, path):
        return True

    def _runtime_alive(self, runtime):
        return False


def test_start_server_inner_kills_orphans_on_regular_existing_idb_reopen(monkeypatch, tmp_path):
    from tests._isolated_repo_loader import load_repo_module

    mod = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
    mgr = mod.SessionManager(str(tmp_path))
    h = _StartServerHarness()
    h.cache_dir = str(tmp_path)
    h.session_mgr = mgr

    session = _make_session(tmp_path, "AB12CDEF", idb_exists=True)
    calls = []
    monkeypatch.setattr(
        h, "_terminate_ida_processes_for_path", lambda target: (calls.append(str(target)) or [])
    )
    monkeypatch.setattr(h, "_build_ida_command", _boom)

    with pytest.raises(_ReachedBuildCommand):
        h._start_server_inner(session)

    # The orphan kill ran against the session idb path (a regular session, not
    # a packed IDB).
    assert calls == [session.idb_path]


def test_start_server_inner_skips_orphan_kill_when_creating_new_idb(monkeypatch, tmp_path):
    from tests._isolated_repo_loader import load_repo_module

    mod = load_repo_module("ida_mcp_stdio.py", module_name="ida_mcp_stdio")
    mgr = mod.SessionManager(str(tmp_path))
    h = _StartServerHarness()
    h.cache_dir = str(tmp_path)
    h.session_mgr = mgr

    session = _make_session(tmp_path, "XYZZY999", idb_exists=False)
    calls = []
    monkeypatch.setattr(
        h, "_terminate_ida_processes_for_path", lambda target: (calls.append(str(target)) or [])
    )
    monkeypatch.setattr(h, "_build_ida_command", _boom)

    with pytest.raises(_ReachedBuildCommand):
        h._start_server_inner(session)

    assert calls == []
