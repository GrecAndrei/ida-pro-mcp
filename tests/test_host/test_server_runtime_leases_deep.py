from __future__ import annotations

import json
import math
import os
import signal
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.server.server_runtime_leases import (
    ServerRuntimeLeasesMixin,
    _lease_pid,
    _lease_timestamp,
    _process_start_token,
    _resolve_stale_cleanup_budget,
    _runtime_lease_io_lock,
)


def test_lease_pid_parsing() -> None:
    assert _lease_pid(1234) == 1234
    assert _lease_pid("5678") == 5678
    assert _lease_pid(True) == 0
    assert _lease_pid(False) == 0
    assert _lease_pid("not_a_number") == 0
    assert _lease_pid(None) == 0


def test_lease_timestamp_parsing() -> None:
    now = time.time()
    assert _lease_timestamp(now) == now
    assert _lease_timestamp("12345.67") == 12345.67
    assert _lease_timestamp(float("nan")) == 0.0
    assert _lease_timestamp(float("inf")) == 0.0
    assert _lease_timestamp("invalid") == 0.0


def test_resolve_stale_cleanup_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", "15.5")
    assert _resolve_stale_cleanup_budget() == 15.5

    # Values below 1.0 are clamped to min_value=1.0
    monkeypatch.setenv("IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", "0.2")
    assert _resolve_stale_cleanup_budget() == 1.0


def test_runtime_lease_io_lock(tmp_path: Path) -> None:
    lease_file = str(tmp_path / "test.lease")
    with _runtime_lease_io_lock(lease_file):
        assert Path(lease_file + ".lock").exists()


def test_runtime_leases_mixin_write_record(tmp_path: Path) -> None:
    mixin = ServerRuntimeLeasesMixin()
    lease_path = str(tmp_path / "runtime.lease")
    now = time.time()
    payload = {
        "pid": 12345,
        "session_id": "sess-alpha",
        "created_at": now,
        "updated_at": now,
    }

    mixin._write_runtime_lease_record(lease_path, payload)
    assert Path(lease_path).is_file()
    data = json.loads(Path(lease_path).read_text(encoding="utf-8"))
    assert data["pid"] == 12345
    assert data["session_id"] == "sess-alpha"


class DummyLeasesHost(ServerRuntimeLeasesMixin):
    def __init__(self, tmp_path: Path):
        self._runtime_lease_dir = str(tmp_path / "leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self.session_runtimes: dict = {}
        self._runtime_lock = threading.RLock()
        self._lease_thread_stop = threading.Event()
        self._shutdown_requested = False
        self.idat_exe = ""

    def _ida_binary_names(self):
        return ["idat64", "idat", "ida64", "ida", "ida.exe", "idat.exe", "idat64.exe"]


def test_lease_pid_overflow_and_exceptions():
    # Large digit string triggers ValueError: Exceeds the limit for integer string conversion
    assert _lease_pid("9" * 5000) == 0


def test_kill_stale_pid_branches(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)
    # 217-218: SIGKILL raises ProcessLookupError -> returns True
    def fake_kill_1(pid, sig):
        if sig == signal.SIGKILL:
            raise ProcessLookupError()

    t = 100.0

    def fake_time():
        nonlocal t
        t += 5.0
        return t

    with patch("os.kill", side_effect=fake_kill_1), patch("time.time", side_effect=fake_time):
        assert host._kill_stale_pid(1234) is True

    # 219-220: SIGKILL raises generic Exception -> returns False
    def fake_kill_2(pid, sig):
        if sig == signal.SIGKILL:
            raise OSError("sigkill failed")

    t = 100.0
    with patch("os.kill", side_effect=fake_kill_2), patch("time.time", side_effect=fake_time):
        assert host._kill_stale_pid(1234) is False


def test_process_identity_and_descendants_boundaries(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)
    assert host._proc_is_ida_named(0) is False
    assert host._proc_group_has_ida_member(0) is False
    assert host._proc_group_has_live_member(0) is False
    assert host._runtime_tree_still_alive(0) is False
    assert host._kill_stale_process_tree(0) is False
    assert host._is_expected_ida_process(0, {}) is False

    # 350: win32 runtime tree still alive
    with patch("sys.platform", "win32"), patch.object(host, "_win32_ida_descendant_alive", return_value=True):
        assert host._runtime_tree_still_alive(100) is True

    # 428, 432: _win32_ida_descendant_alive with seen and unseen non-ida / ida
    with patch.object(host, "_win32_process_map", return_value=({100: [100, 200], 200: [300]}, {200: "notepad.exe", 300: "idat64.exe"})):
        assert host._win32_ida_descendant_alive(100) is True

    # 500-501: _collect_descendant_pids error on stat open
    with patch("os.listdir", return_value=["999"]), patch("builtins.open", side_effect=PermissionError):
        assert host._collect_descendant_pids(100) == []

    # 559: _kill_stale_process_group returns True on ProcessLookupError from killpg(0)
    calls = []

    def fake_killpg(pgid, sig):
        calls.append(sig)
        if sig == 0 and len(calls) > 2:
            raise ProcessLookupError()

    t = 100.0

    def fake_time_pg():
        nonlocal t
        t += 5.0
        return t

    with patch("os.killpg", side_effect=fake_killpg), patch("time.time", side_effect=fake_time_pg):
        assert host._kill_stale_process_group(100) is True


def test_is_expected_ida_process_edge_branches(tmp_path: Path):
    import io
    host = DummyLeasesHost(tmp_path)

    # 628-629: os.path.realpath raises
    with patch("sys.platform", "linux"), \
         patch("os.path.realpath", side_effect=OSError("bad link")), \
         patch("builtins.open", side_effect=FileNotFoundError):
        assert host._is_expected_ida_process(1234, {}) is False

    # 640-641, 646: os.path.samefile raises, actual_exe exists but differs from expected_path
    fake_expected = str(tmp_path / "ida1" / "idat64")
    fake_actual = str(tmp_path / "ida2" / "idat64")
    with patch("sys.platform", "linux"), \
         patch("os.path.realpath", side_effect=[fake_expected, fake_actual]), \
         patch("os.path.exists", return_value=True), \
         patch("os.path.samefile", side_effect=OSError("samefile failed")):
        assert host._is_expected_ida_process(1234, {"idat_exe": fake_expected}) is False

    # 656: cmdline is empty (parts = [])
    with patch("sys.platform", "linux"), \
         patch("os.path.realpath", return_value=""), \
         patch("builtins.open", MagicMock(return_value=io.BytesIO(b"\x00\x00"))):
        assert host._is_expected_ida_process(1234, {}) is False

    # 660: parts[0] is not ida, but parts[1] is
    with patch("sys.platform", "linux"), \
         patch("os.path.realpath", return_value=""), \
         patch("builtins.open", MagicMock(return_value=io.BytesIO(b"python3\x00idat64\x00"))):
        assert host._is_expected_ida_process(1234, {}) is True

    # 688: _platform_pid_is_ida_process on non-linux where tasklist returns empty output
    with patch("sys.platform", "win32"), \
         patch("subprocess.run", return_value=MagicMock(stdout="")):
        assert host._platform_pid_is_ida_process(1234, {}) is False


def test_lease_owner_and_modification_branches(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)

    # 726-727: _lease_has_live_foreign_owner generic Exception from os.kill
    with patch("os.kill", side_effect=OSError("unexpected kill error")):
        assert host._lease_has_live_foreign_owner({"owner_pid": 99999}) is False

    # 752-753: _remove_lease_if_unchanged load failure
    p = str(tmp_path / "corrupt.lease")
    Path(p).write_text("not json", encoding="utf-8")
    assert host._remove_lease_if_unchanged(p, 100.0) is False

    # 755: _remove_lease_if_unchanged not dict
    Path(p).write_text("[1, 2, 3]", encoding="utf-8")
    assert host._remove_lease_if_unchanged(p, 100.0) is False

    # 762: _remove_lease_if_unchanged os.remove OSError
    valid_lease = {"updated_at": 100.0}
    Path(p).write_text(json.dumps(valid_lease), encoding="utf-8")
    with patch("os.remove", side_effect=OSError("locked")):
        assert host._remove_lease_if_unchanged(p, 100.0) is False

    # 780: _rewrite_lease_if_unchanged current not dict
    Path(p).write_text('"a string"', encoding="utf-8")
    assert host._rewrite_lease_if_unchanged(p, {}, 100.0) is False


def test_cleanup_stale_runtime_leases_branches(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)

    # 790-791: os.listdir raises
    with patch("os.listdir", side_effect=OSError("no dir")):
        host._cleanup_stale_runtime_leases()

    lease_path = str(tmp_path / "leases" / "SID_ABCDEF12.lease.json")
    old_time = time.time() - 1000

    # 827: tracked is True -> continue
    host.session_runtimes["ABCDEF12"] = {"process": MagicMock()}
    Path(lease_path).write_text(json.dumps({"session_id": "ABCDEF12", "updated_at": old_time, "pid": 1234}), encoding="utf-8")
    host._cleanup_stale_runtime_leases()

    # 832: tracked is False, then tracked_after is True
    class TrackedAfterDict(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.checked = 0

        def __contains__(self, item):
            self.checked += 1
            return self.checked > 1

    host.session_runtimes = TrackedAfterDict()
    Path(lease_path).write_text(json.dumps({"session_id": "ABCDEF12", "updated_at": old_time, "pid": 1234}), encoding="utf-8")
    host._cleanup_stale_runtime_leases()

    # 842: pid <= 0 and _remove_lease_if_unchanged returns False
    host.session_runtimes = {}
    Path(lease_path).write_text(json.dumps({"session_id": "ABCDEF12", "updated_at": old_time, "pid": 0}), encoding="utf-8")
    with patch.object(host, "_remove_lease_if_unchanged", return_value=False):
        host._cleanup_stale_runtime_leases()

    # 853-854, 881: os.kill raises Exception -> alive is None -> skip_count += 1
    Path(lease_path).write_text(json.dumps({"session_id": "ABCDEF12", "updated_at": old_time, "pid": 1234}), encoding="utf-8")
    with patch("os.kill", side_effect=Exception("perm check failure")), \
         patch.object(host, "_is_expected_ida_process", return_value=False):
        host._cleanup_stale_runtime_leases()

    # 861: alive is False and _remove_lease_if_unchanged returns False
    with patch("os.kill", side_effect=ProcessLookupError), \
         patch.object(host, "_remove_lease_if_unchanged", return_value=False):
        host._cleanup_stale_runtime_leases()

    # 877: not _is_expected_ida_process, alive is True, remove returns False
    with patch("os.kill", return_value=None), \
         patch.object(host, "_is_expected_ida_process", return_value=False), \
         patch.object(host, "_remove_lease_if_unchanged", return_value=False):
        host._cleanup_stale_runtime_leases()


def test_lease_heartbeat_loop_shutdown_and_desync(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)

    # 923: _shutdown_requested before runtime loop
    host._shutdown_requested = True
    with patch.object(host._lease_thread_stop, "wait", side_effect=[False, True]):
        host._lease_heartbeat_loop()

    # 928: _shutdown_requested inside runtime loop
    # 932: session_runtimes.get(sid) is not runtime
    host._shutdown_requested = False
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 5555

    class DesyncDict(dict):
        def __init__(self, host_ref, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.host_ref = host_ref

        def get(self, key, default=None):
            if key == "s1":
                self.host_ref._shutdown_requested = True
            elif key == "s3":
                return {"different": "runtime"}
            return super().get(key, default)

    host.session_runtimes = DesyncDict(host, {"s1": {"process": proc}, "s2": {"process": proc}})
    with patch.object(host._lease_thread_stop, "wait", side_effect=[False, True]), \
         patch.object(host, "_write_runtime_lease"):
        host._lease_heartbeat_loop()

    # Test line 932 specifically
    host._shutdown_requested = False
    host.session_runtimes = DesyncDict(host, {"s3": {"process": proc}})
    with patch.object(host._lease_thread_stop, "wait", side_effect=[False, True]):
        host._lease_heartbeat_loop()


def test_leases_mixin_aliases_and_termination_signal(tmp_path: Path):
    host = DummyLeasesHost(tmp_path)
    with patch.object(host, "_cleanup_stale_runtime_leases") as mock_cleanup:
        host._adopt_or_cleanup_stale_runtime_leases()
        assert mock_cleanup.called

    host.shutdown = MagicMock()
    host._handle_termination_signal(signal.SIGTERM, None)
    assert host._shutdown_requested is True
    assert host._lease_thread_stop.is_set()
    assert host.shutdown.called
