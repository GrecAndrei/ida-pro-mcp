from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_runtime import (
    ServerRuntimeMixin,
    _lease_pid,
    _process_start_token,
)


class DummyRuntimeServer(ServerRuntimeMixin):
    def __init__(self, tmp_path=None):
        self._runtime_owner_id = "test_owner_1"
        self._owner_start_token = "tok_123"
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._session_activity = {}
        self._session_activity_events = {}
        self._session_startup_locks = {}
        self._session_teardown = set()
        self._activity_log = []
        self._activity_log_max = 500
        self._runtime_lock = threading.Lock()
        self._analysis_watchdog_lock = threading.Lock()
        self._analysis_watchdog_stop_events = {}
        self._analysis_watchdog_threads = {}
        self._analysis_checkpoint_lock = threading.Lock()
        self._analysis_checkpoint_stop_events = {}
        self._analysis_checkpoint_threads = {}
        self.tmp_path = tmp_path

        lease_dir = str(tmp_path / "leases") if tmp_path else "/tmp/leases"
        os.makedirs(lease_dir, exist_ok=True)
        self._runtime_lease_dir = lease_dir

        log_dir = str(tmp_path / "logs") if tmp_path else "/tmp/logs"
        os.makedirs(log_dir, exist_ok=True)
        art_dir = str(tmp_path / "artifacts") if tmp_path else "/tmp/artifacts"
        os.makedirs(art_dir, exist_ok=True)

        self.session_mgr = MagicMock()
        self.session_mgr.find_session_by_path.return_value = None
        self.session_mgr.get_session.return_value = None
        self.session_mgr.discover_sessions.return_value = []
        self.session_mgr.get_session_artifact_dir.return_value = art_dir
        self.session_mgr.get_session_log_dir.return_value = log_dir
        self.bookmark_mgr = MagicMock()
        self.bookmark_mgr.list.return_value = {"bookmarks": []}
        self.current_session = None
        self.ida_dir = "/fake/ida"
        self.idat_exe = "/fake/ida/idat64"
        self.cache_dir = str(tmp_path / "cache") if tmp_path else "/tmp/cache"

    def _runtime_owner_path(self, sid: str) -> str:
        if self.tmp_path:
            return str(self.tmp_path / f"{sid}.owner.json")
        return f"/tmp/{sid}.owner.json"

    def _live_runtime_pids(self) -> set[int]:
        return set()

    def _runtime_alive(self, runtime: Any) -> bool:
        if not runtime or not isinstance(runtime, dict):
            return False
        proc = runtime.get("process")
        return bool(proc and proc.poll() is None)

    def _runtime_record(self, sid: str) -> dict[str, Any] | None:
        return self.session_runtimes.get(sid)

    def _write_runtime_lease(self, sid: str, runtime: Any) -> None:
        pass

    def _remove_runtime_lease(self, sid: str) -> None:
        pass

    def _send_notification(self, notification: Any) -> None:
        pass

    def _persist_session_fields(self, session: Any, **fields: Any) -> None:
        pass

    def _is_executable_file(self, path: str) -> bool:
        return True


def test_runtime_lease_claim_file_not_found_and_reclaim(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    owner_file = tmp_path / "A1B2C3D4.owner.json"

    # Line 276: FileNotFoundError in read loop
    link_calls = 0

    def mock_link(src, dst):
        nonlocal link_calls
        link_calls += 1
        if link_calls == 1:
            raise FileExistsError()

    call_count = 0
    real_open = open

    def mock_open(file, *args, **kwargs):
        nonlocal call_count
        if str(file) == str(owner_file):
            call_count += 1
            if call_count == 1:
                raise FileNotFoundError()
        return real_open(file, *args, **kwargs)

    with patch("os.link", side_effect=mock_link), patch("builtins.open", side_effect=mock_open):
        res = server._claim_runtime_ownership("A1B2C3D4")
        assert res == str(owner_file)

    # Line 310: both attempts fail to claim lease
    with patch("os.link", side_effect=FileExistsError), patch("ida_pro_mcp.host.server.server_runtime._lease_pid", return_value=0):
        assert server._claim_runtime_ownership("A1B2C3D4") is None

    # Line 321: _release_runtime_ownership when owner data is not a dict
    owner_file.write_text("not json data", encoding="utf-8")
    server._release_runtime_ownership("A1B2C3D4")

    owner_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    server._release_runtime_ownership("A1B2C3D4")

    # Line 348: _is_executable_file on Windows
    with patch("os.name", "nt"), patch("os.path.isfile", return_value=True):
        assert ServerRuntimeMixin._is_executable_file(server, "/fake/path.exe") is True


def test_detect_ida_dir_and_find_idat_branches(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)

    # Line 415: candidate is not a directory
    with (
        patch.dict(os.environ, {"IDADIR": "", "IDA_DIR": ""}, clear=False),
        patch.object(server, "_ida_binary_names", return_value=["idat64"]),
        patch("glob.glob", return_value=["/fake/cand"]),
        patch("os.path.isdir", return_value=False),
        patch("shutil.which", return_value=None),
    ):
        # Line 424: nothing found returns ""
        assert server._detect_ida_dir() == ""

    # Line 443: _find_idat resolves via shutil.which
    server.ida_dir = ""
    with (
        patch.dict(os.environ, {"IDA_MCP_IDAT": ""}),
        patch.object(server, "_detect_ida_dir", return_value=""),
        patch.object(server, "_ida_binary_names", return_value=["idat64"]),
        patch("shutil.which", return_value="/usr/bin/idat64"),
        patch.object(server, "_is_executable_file", return_value=True),
    ):
        res = server._find_idat()
        assert res == "/usr/bin/idat64"


def test_process_stats_rusage_exception() -> None:
    server = DummyRuntimeServer()
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 12345
    runtime = {"process": proc}

    # Lines 541-542: resource.getrusage raises
    with patch("resource.getrusage", side_effect=RuntimeError("rusage boom")), patch("builtins.open", side_effect=FileNotFoundError):
        snap = server._collect_ida_state_snapshot(
            runtime=runtime,
            include_process_stats=True,
        )
        assert snap["process_alive"] is True
        assert "host_rusage_cpu_user_sec" not in snap


def test_send_rpc_raw_eof_in_header() -> None:
    server = DummyRuntimeServer()
    mock_sock = MagicMock()
    # Line 651: not c while reading 4-byte header
    mock_sock.recv.return_value = b""

    with patch("socket.socket", return_value=mock_sock), pytest.raises(EOFError):
        server._send_rpc_raw({"test": 1}, 9999, timeout=1.0)


def test_extract_library_init_failure_parse_error_and_flag() -> None:
    server = DummyRuntimeServer()

    # Lines 808-809: err code parse exception
    with patch("re.search") as mock_search:
        m = MagicMock()
        m.group.side_effect = OverflowError("too big")
        mock_search.return_value = m
        info = server._extract_library_init_failure("library init failed error: 999999999999999999999")
        assert info is not None
        assert info.get("error_code") is None

    # Line 891: _is_library_init_err2 with info['err2'] == True
    with patch.object(
        server,
        "_extract_library_init_failure",
        return_value={"detected": True, "error_code": 5, "err2": True},
    ):
        assert server._is_library_init_err2("some diag") is True


def test_record_tool_call_activity_branches() -> None:
    server = DummyRuntimeServer()

    # Line 1028: no sid and no current_session -> return
    server.current_session = None
    server._record_activity("calc", {}, {"ok": True})
    assert len(server._session_last_activity) == 0

    # Line 1050: auto_nudge.record_tool_call when _usage_intel is None
    # and line 1069: raw_addrs is string
    mock_nudge_mod = MagicMock()
    with patch.dict(sys.modules, {"ida_pro_mcp.host.server.auto_nudge": mock_nudge_mod}):
        server._record_activity(
            "calc",
            {"action": "eval", "addrs": "0x401000, 0x402000"},
            {"ok": True},
            session_id="A1B2C3D4",
        )
        assert mock_nudge_mod.record_tool_call.called
        assert "A1B2C3D4" in server._session_last_activity


def test_recent_workset_break_and_target_fallback() -> None:
    server = DummyRuntimeServer()
    server.bookmark_mgr.list.return_value = {
        "bookmarks": [
            {"timestamp": f"2026-09-07T00:00:0{i}Z", "addr": f"0x40{i}000", "name": f"bm{i}"}
            for i in range(10)
        ]
    }
    server._activity_log = [
        {
            "session_id": "A1B2C3D4",
            "ts": "2026-09-07T00:00:00Z",
            "tool": "decompile",
            "action": "decompile",
            "target": "target_func",
            # Line 1214: target without topic
        }
    ]

    # Line 1198: break when len(entries) >= n * 2
    res = server._build_recent_workset("A1B2C3D4", n=1, include_bookmarks=True, include_items=True)
    assert res.get("ok") is True
    assert "target_func" in res.get("workset", "")


def test_watchdog_worker_runtime_dead() -> None:
    server = DummyRuntimeServer()
    server.session_runtimes["A1B2C3D4"] = {"port": 1234}
    server._runtime_alive = MagicMock(return_value=False)
    server._update_session_indexing_metadata = MagicMock()
    server._analysis_watchdog_interval = 0.001

    captured_target = None

    def fake_thread_init(*args, **kwargs):
        nonlocal captured_target
        captured_target = kwargs.get("target")
        mock_t = MagicMock()
        mock_t.is_alive.return_value = True
        return mock_t

    with patch("threading.Thread", side_effect=fake_thread_init):
        server._start_analysis_watchdog("A1B2C3D4", 1234)

    assert captured_target is not None
    # Calling worker when runtime is dead returns immediately (line 1329)
    captured_target()


def test_session_teardown_flags_and_retire_dead_runtime() -> None:
    server = DummyRuntimeServer()
    server._runtime_lock = None  # Lines 1436, 1452, 1486

    # Line 1436: begin teardown with runtime_lock None
    server._begin_session_teardown("A1B2C3D4")
    assert server._session_teardown_active("A1B2C3D4") is True  # Line 1486

    # Line 1483: callable is_closing
    server._session_is_closing = lambda sid: sid == "A1B2C3D4"
    assert server._session_teardown_active("A1B2C3D4") is True
    del server._session_is_closing

    # Line 1452: end teardown with runtime_lock None
    server._end_session_teardown("A1B2C3D4")
    assert server._session_teardown_active("A1B2C3D4") is False

    # Lines 1508-1513: _retire_dead_runtime closes log handles and pops port/auth_token
    server._runtime_lock = threading.Lock()
    mock_fh = MagicMock()
    runtime = {
        "log_handles": [mock_fh],
        "port": 5000,
        "auth_token": "secret",
    }
    server.session_runtimes["A1B2C3D4"] = runtime
    server._retire_dead_runtime("A1B2C3D4")
    assert mock_fh.close.called
    assert runtime["log_handles"] == []
    assert "port" not in runtime
    assert "auth_token" not in runtime


def test_analysis_checkpoint_timer_lazy_init_and_join() -> None:
    server = DummyRuntimeServer()
    server._analysis_checkpoint_stop_events = None  # Lines 1598-1599
    server._analysis_checkpoint_threads = None  # Lines 1602-1603

    fake_thread = MagicMock()
    fake_thread.is_alive.return_value = True

    with patch("threading.Thread", return_value=fake_thread):
        server._start_analysis_checkpoint_timer("A1B2C3D4", 1234)
        assert isinstance(server._analysis_checkpoint_stop_events, dict)
        assert isinstance(server._analysis_checkpoint_threads, dict)

    # Lines 1625-1626: stop joins thread
    server._stop_analysis_checkpoint_timer("A1B2C3D4", join_timeout=0.1)
    assert fake_thread.join.called


def test_analysis_options_native_magic_exception_and_int_entry_point(tmp_path) -> None:
    server = DummyRuntimeServer()
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"DATA")

    session = SimpleNamespace(
        session_id="A1B2C3D4",
        binary_path=str(bin_file),
        idb_path=str(tmp_path / "test.i64"),
        analysis_options={"entry_point": 0x401000},  # Line 1872: int entry_point
        analysis_applied=False,
        ida_args=[],
    )

    # Lines 1824-1825: open raises
    with patch("builtins.open", side_effect=PermissionError("open fail")):
        args = server._preload_ida_args(session)
        assert "-i401000" in args  # Line 1872


def test_find_idalib_python_dir_success() -> None:
    server = DummyRuntimeServer()
    server.ida_dir = ""
    server.idat_exe = "/opt/ida/idat64"

    # Line 1947: isdir returns True for candidate/idapro under idat_exe
    def mock_isdir(p):
        return p == "/opt/ida/idalib/python/idapro"

    with patch("os.path.isdir", side_effect=mock_isdir):
        res = server._idalib_python_dir()
        assert res == "/opt/ida/idalib/python"


def test_cleanup_stale_idb_family_empty() -> None:
    server = DummyRuntimeServer()
    # Line 2014: empty idb_path returns None
    assert server._cleanup_stale_idb_family("") is None


def test_kill_orphans_locking_path_all_branches() -> None:
    server = DummyRuntimeServer()

    # Line 2089: empty normalized path
    with patch("os.path.realpath", return_value=""):
        assert server._terminate_ida_processes_for_path("/some/path") == []

    # Lines 2110-2111 & 2120-2121: psutil exception branches
    mock_ps = MagicMock()
    mock_proc = MagicMock()

    class MockProcInfo(dict):
        def get(self, key, default=None):
            if key == "cmdline":
                raise RuntimeError("cmdline fail")
            return super().get(key, default)

    mock_proc.info = MockProcInfo({"name": "idat64"})
    mock_ps.process_iter.return_value = [mock_proc]

    with patch.dict(sys.modules, {"psutil": mock_ps}):
        assert server._terminate_ida_processes_for_path("/some/path.i64") == []

    # Lines 2120-2121: process_iter raises
    mock_ps.process_iter.side_effect = RuntimeError("iter boom")
    with patch.dict(sys.modules, {"psutil": mock_ps}):
        assert server._terminate_ida_processes_for_path("/some/path.i64") == []

    # Lines 2143-2144, 2153-2155: Windows wmic parsing
    with patch.dict(sys.modules, {"psutil": None}), patch("sys.platform", "win32"):
        mock_run = MagicMock()
        mock_run.stdout = "ProcessId: 4321\nCommandLine: invalid \" quote\nOtherLine: xyz"
        with patch("subprocess.run", return_value=mock_run):
            assert server._terminate_ida_processes_for_path("/some/path.i64") == []
        # Lines 2154-2155: wmic run raises
        with patch("subprocess.run", side_effect=RuntimeError("wmic fail")):
            assert server._terminate_ida_processes_for_path("/some/path.i64") == []

    # Lines 2163-2164: POSIX listdir /proc raises
    with patch.dict(sys.modules, {"psutil": None}), patch("sys.platform", "linux"), patch("os.listdir", side_effect=PermissionError("proc access fail")):
        assert server._terminate_ida_processes_for_path("/some/path.i64") == []

    # Lines 2171-2172, 2180-2181, 2213-2214: POSIX /proc read error and kill error
    with patch.dict(sys.modules, {"psutil": None}), patch("sys.platform", "linux"):
        with patch("os.listdir", return_value=["9999"]), patch("builtins.open", side_effect=PermissionError("cannot read cmdline")):
            assert server._terminate_ida_processes_for_path("/some/path.i64") == []

        mock_fh = MagicMock()
        mock_fh.__enter__ = MagicMock(
            return_value=SimpleNamespace(read=lambda: b"/opt/ida/idat64\x00/target.i64\x00")
        )
        mock_fh.__exit__ = MagicMock(return_value=None)
        real_realpath = os.path.realpath

        def mock_realpath_proc_fail(p):
            if "/proc/" in str(p):
                raise RuntimeError("realpath fail")
            return real_realpath(p)

        with patch("os.listdir", return_value=["9999"]), patch("builtins.open", return_value=mock_fh), patch.object(server, "_argv_targets_path", return_value=True):
            # Line 2180-2181: realpath on /proc/*/exe raises
            with patch("os.path.realpath", side_effect=mock_realpath_proc_fail):
                assert server._terminate_ida_processes_for_path("/target.i64") == []

            # Line 2213-2214: os.kill raises
            with (
                patch("os.path.realpath", return_value="/opt/ida/idat64"),
                patch.object(server, "_ida_binary_names", return_value=["idat64"]),
                patch("os.kill", side_effect=PermissionError("kill fail")),
            ):
                assert server._terminate_ida_processes_for_path("/target.i64") == []


def test_nuclear_reset_size_check_exception(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    idb_file = tmp_path / "test.i64"
    idb_file.write_bytes(b"DATA")

    # Lines 2257-2258: os.getsize raises
    with patch("os.path.getsize", side_effect=OSError("getsize fail")):
        server._nuclear_reset(str(idb_file), aggressive=True)


def test_start_server_locks_and_guard_branches() -> None:
    server = DummyRuntimeServer()
    session = SimpleNamespace(session_id="A1B2C3D4", idb_path="/tmp/test.i64")

    # Line 2274: lazy init of _session_startup_locks
    if hasattr(server, "_session_startup_locks"):
        delattr(server, "_session_startup_locks")

    # Line 2286: _runtime_alive recheck returns _already_running
    server._runtime_alive = MagicMock(return_value=True)
    server.session_runtimes["A1B2C3D4"] = {"port": 1234}
    res = server._start_server(session)
    assert res.get("_already_running") is True

    # Line 2309: ownership claim fails
    server._runtime_alive = MagicMock(return_value=False)
    server._session_teardown_active = MagicMock(return_value=False)
    server._claim_runtime_ownership = MagicMock(return_value=None)
    res2 = server._start_server(session)
    assert res2.get("code") == MCPError.FILE_LOCKED

    # Line 2327: mark_pending callable, line 2333-2335: inner raises
    server._claim_runtime_ownership = MagicMock(return_value="/tmp/owner.json")
    server._mark_analysis_pending = MagicMock()
    server._start_server_inner = MagicMock(side_effect=RuntimeError("inner boom"))
    server._release_runtime_ownership = MagicMock()

    with pytest.raises(RuntimeError, match="inner boom"):
        server._start_server(session)

    assert server._mark_analysis_pending.called
    assert server._release_runtime_ownership.called


def test_start_server_inner_prelaunch_killed_log(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    session = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path=str(tmp_path / "test.i64"),
        binary_path=None,
        analysis_options={},
        analysis_applied=False,
        ida_args=[],
    )
    (tmp_path / "test.i64").write_bytes(b"IDB")

    # Line 2445: if killed: log_rpc(...)
    server._terminate_ida_processes_for_path = MagicMock(return_value=[1234, 5678])
    with patch.object(server, "_build_ida_command", side_effect=RuntimeError("stop early")), pytest.raises(RuntimeError):
        server._start_server_inner(session)


def test_start_server_inner_apply_options_exception_and_error(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    session = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path=str(tmp_path / "test.i64"),
        binary_path=None,
        analysis_options={"processor": "arm"},
        analysis_applied=False,
        ida_args=[],
    )
    (tmp_path / "test.i64").write_bytes(b"IDB")

    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.pid = None

    art_dir = server.session_mgr.get_session_artifact_dir(session.session_id)
    port_file = os.path.join(art_dir, f"ida_rpc_{session.session_id}_{server._runtime_owner_id[:12]}.port")

    def mock_popen(*args, **kwargs):
        with open(port_file, "w") as f:
            f.write("1234\n")
        return mock_proc

    server._cleanup_runtime = MagicMock()
    server._build_ida_command = MagicMock(return_value=["/fake/idat64"])
    server._send_rpc_raw = MagicMock(return_value={"pong": True, "port": 1234})
    server._apply_session_options = MagicMock(side_effect=RuntimeError("apply options boom"))

    # Lines 2552-2561: apply_options raises -> cleanup_runtime called, re-raised then caught by outer loop
    with (
        patch("subprocess.Popen", side_effect=mock_popen),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._resolve_startup_timeout", return_value=0.01),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
        patch("time.time", side_effect=[0, 0, 0, 0, 100, 100, 100, 100]),
    ):
        res = server._start_server_inner(session)
        assert res.get("code") == MCPError.IDA_TIMEOUT
        assert server._cleanup_runtime.called

    # Lines 2563-2564: _apply_session_options returns error result
    server._cleanup_runtime.reset_mock()
    server._apply_session_options = MagicMock(
        return_value={"ok": False, "error": True, "message": "apply error"}
    )
    with (
        patch("subprocess.Popen", side_effect=mock_popen),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
    ):
        res = server._start_server_inner(session)
        assert res.get("error") is True
        assert server._cleanup_runtime.called

    # Line 2587: crash with _is_library_init_err2 calls recovery
    mock_dead_proc = MagicMock()
    mock_dead_proc.poll.return_value = 1
    mock_dead_proc.pid = None
    server._is_library_init_err2 = MagicMock(return_value=True)
    server._attempt_session_recovery = MagicMock(return_value={"recovered": True})
    with (
        patch("subprocess.Popen", return_value=mock_dead_proc),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
    ):
        res_rec = server._start_server_inner(session)
        assert res_rec.get("recovered") is True

    # Line 2591: crash details include library_init
    server._is_library_init_err2 = MagicMock(return_value=False)
    server._is_orphan_locked_db_open_failure = MagicMock(return_value=False)
    server._extract_library_init_failure = MagicMock(return_value={"detected": True, "code": 1})
    with (
        patch("subprocess.Popen", return_value=mock_dead_proc),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
    ):
        res_crash = server._start_server_inner(session)
        assert "library_init" in res_crash.get("details", {})


def test_launch_and_wait_idalib_missing_and_branches(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    session = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path=str(tmp_path / "test.i64"),
        binary_path=str(tmp_path / "test.bin"),
        analysis_options={},
        analysis_applied=False,
        ida_args=[],
    )
    (tmp_path / "test.i64").write_bytes(b"IDB")

    # Line 2693: returns FILE_NOT_FOUND error
    server._is_idalib_runtime = MagicMock(return_value=True)
    server._idalib_python_dir = MagicMock(return_value="")

    res = server._launch_and_wait(session, 1234)
    assert res.get("code") == MCPError.FILE_NOT_FOUND

    # Lines 2751-2752 (actual_port <= 0), line 2768 (session teardown active), line 2794-2798 (timeout)
    server._is_idalib_runtime = MagicMock(return_value=False)
    server._build_ida_command = MagicMock(return_value=["/fake/idat64"])
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.pid = None

    art_dir = server.session_mgr.get_session_artifact_dir(session.session_id)
    port_file = os.path.join(art_dir, f"ida_rpc_A1B2C3D4_{server._runtime_owner_id[:12]}_normal.port")

    def mock_popen(*args, **kwargs):
        with open(port_file, "w") as f:
            f.write("1234\n")
        return mock_proc

    isfile_count = 0
    real_isfile = os.path.isfile
    def mock_isfile(p):
        nonlocal isfile_count
        if str(p) == port_file:
            isfile_count += 1
            if isfile_count == 1:
                return False
        return real_isfile(p)

    # Lines 2794-2796: first ping raises, second returns pong
    server._send_rpc_raw = MagicMock(side_effect=[RuntimeError("ping boom"), {"pong": True, "port": 1234}])
    server._session_teardown_active = MagicMock(return_value=True)

    with (
        patch("subprocess.Popen", side_effect=mock_popen),
        patch("os.path.isfile", side_effect=mock_isfile),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
    ):
        res_abort = server._launch_and_wait(session, 1234)
        assert res_abort.get("code") == MCPError.IDA_BUSY

    # Lines 2794-2798: timeout
    server._session_teardown_active = MagicMock(return_value=False)
    if os.path.exists(port_file):
        os.remove(port_file)
    with (
        patch("subprocess.Popen", return_value=mock_proc),
        patch("time.sleep", return_value=None),
        patch("ida_pro_mcp.host.server.server_runtime._resolve_startup_timeout", return_value=0.01),
        patch("time.time", side_effect=[0, 100, 100, 100]),
        patch("ida_pro_mcp.host.server.server_runtime._kill_process_tree"),
    ):
        res_to = server._launch_and_wait(session, 1234)
        assert res_to.get("code") == MCPError.IDA_TIMEOUT


def test_attempt_session_recovery_orphan_and_sidecar_exception(tmp_path) -> None:
    server = DummyRuntimeServer(tmp_path)
    idb_file = tmp_path / "target.i64"
    idb_file.write_bytes(b"DATA")
    bin_file = tmp_path / "target.bin"
    bin_file.write_bytes(b"BIN")

    session = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path=str(idb_file),
        binary_path=str(bin_file),
        packed_idb=True,
        analysis_options={},
        analysis_applied=False,
        ida_args=[],
    )

    # Line 2834: orphan locked db failure
    server._is_orphan_locked_db_open_failure = MagicMock(return_value=True)
    server._cleanup_runtime = MagicMock()
    server._claim_runtime_ownership = MagicMock(return_value="/tmp/owner.json")
    server._nuclear_reset = MagicMock()
    server._persist_session_fields = MagicMock()

    # Lines 2901-2902: sidecar removal exception
    sidecar = tmp_path / "target.id0"
    sidecar.write_bytes(b"SIDECAR")

    # Line 2924: sanitized retry succeeds
    server._launch_and_wait = MagicMock(
        side_effect=[
            {"error": True, "library_init": True},  # first fails with library_init
            {"ok": True},  # retry succeeds (line 2924)
        ]
    )

    # Line 2953: apply options error result
    server._runtime_record = MagicMock(return_value={"port": 1234})
    server._apply_session_options = MagicMock(
        return_value={"ok": False, "error": True, "message": "apply options fail"}
    )

    with patch("os.remove", side_effect=PermissionError("cannot remove sidecar")):
        res = server._attempt_session_recovery(session, "locked db error 4", 1234)
        assert res.get("error") is True
        assert res.get("message") == "apply options fail"

    # Lines 2962-2963: background services exception
    server._apply_session_options = MagicMock(return_value={"ok": True})
    server._start_session_background_services = MagicMock(side_effect=RuntimeError("bg fail"))
    server._launch_and_wait = MagicMock(return_value={"ok": True})
    res2 = server._attempt_session_recovery(session, "locked db error 4", 1234)
    assert res2.get("ok") is True

    # Line 2905: missing binary_path returns FILE_NOT_FOUND
    session.binary_path = "/nonexistent/binary.bin"
    res_no_bin = server._attempt_session_recovery(session, "locked db error 4", 1234)
    assert res_no_bin.get("code") == MCPError.FILE_NOT_FOUND


def test_apply_session_options_reanalyze_error_and_arch_branches() -> None:
    server = DummyRuntimeServer()
    session = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path="/tmp/test.i64",
        analysis_options={
            "baseaddr": "0x400000",  # Line 3032
            "start_ea": "0x401000",
            "min_ea": "0x400000",
            "max_ea": "0x500000",
            "reanalyze": True,
            "processor": "arm",
            "bitness": 32,
        },
        analysis_applied=False,
        ida_args=[],
    )
    runtime = {"port": 1234}

    # Lines 3090-3091: reanalyze returns error
    server._send_rpc_raw = MagicMock(
        side_effect=[
            {"ok": True},  # set_options
            {"ok": True},  # set_processor
            {"ok": False, "error": True, "message": "reanalyze failed"},  # reanalyze
        ]
    )
    res = server._apply_session_options(session, runtime)
    assert res.get("error") is True
    assert res.get("message") == "reanalyze failed"

    # Lines 3145-3146 & 3163-3164: architecture verification exception
    session.analysis_applied = False
    server._send_rpc_raw = MagicMock(
        side_effect=[
            {"ok": True},  # set_options
            {"ok": True},  # set_architecture
            {"ok": True},  # reanalyze
            {"ok": True},  # bootstrap_knowledge
            # get_options
            {"ok": True, "result": {"procname": "arm", "app_bitness": "not_an_int"}},
        ]
    )
    res2 = server._apply_session_options(session, runtime)
    assert res2.get("error") is True
    assert "bitness expected=32 got=not_an_int" in res2["details"]["mismatches"][0]

    # Lines 3163-3164: got.get raises inside verify_architecture
    class BrokenResult(dict):
        def get(self, k, default=None):
            if k == "procname":
                raise RuntimeError("broken procname")
            return super().get(k, default)

    session.analysis_applied = False
    server._send_rpc_raw = MagicMock(
        side_effect=[
            {"ok": True},  # set_options
            {"ok": True},  # set_architecture
            {"ok": True},  # reanalyze
            {"ok": True},  # bootstrap_knowledge
            {"ok": True, "result": BrokenResult()},  # get_options
        ]
    )
    res3 = server._apply_session_options(session, runtime)
    assert res3.get("ok") is True


def test_start_session_background_services_and_cleanup_runtime_branches() -> None:
    server = DummyRuntimeServer()

    # Line 3185: empty session_id returns early
    server._start_session_background_services(SimpleNamespace(session_id=""), 1234)

    # Lines 3188-3220: starts services
    server._update_session_indexing_metadata = MagicMock()
    server._start_analysis_watchdog = MagicMock()
    server._start_analysis_checkpoint_timer = MagicMock()
    server._seed_index_from_matching_binary = MagicMock(return_value={"reused": True})

    captured_reuse = None
    def fake_reuse_thread(*args, **kwargs):
        nonlocal captured_reuse
        if "semantic-reuse" in kwargs.get("name", ""):
            captured_reuse = kwargs.get("target")
        mock_t = MagicMock()
        return mock_t

    with patch("threading.Thread", side_effect=fake_reuse_thread):
        server._start_session_background_services(SimpleNamespace(session_id="A1B2C3D4"), 1234)
        assert server._start_analysis_watchdog.called
        assert server._start_analysis_checkpoint_timer.called

    assert captured_reuse is not None
    # Lines 3211-3216: normal reuse
    captured_reuse()
    # Lines 3217-3218: reuse scan raises
    server._seed_index_from_matching_binary.side_effect = RuntimeError("scan fail")
    captured_reuse()

    # Lines 3235-3236: lazy init of _session_startup_locks in _cleanup_runtime
    # and line 3252: callable stop_watcher
    server._session_startup_locks = None
    server._stop_analysis_watchdog = MagicMock()
    server._stop_analysis_checkpoint_timer = MagicMock()
    server._stop_analysis_watcher = MagicMock()

    server._cleanup_runtime("A1B2C3D4")
    assert isinstance(server._session_startup_locks, dict)
    assert server._stop_analysis_watcher.called


def test_resolve_session_from_idb_ref_empty_and_root() -> None:
    server = DummyRuntimeServer()

    # Line 3325: empty string
    assert server._resolve_session_from_idb_ref("   ") is None

    # Line 3347: "/" (empty basename)
    assert server._resolve_session_from_idb_ref("/") is None

    # Lines 3355-3365: ambiguous basename
    s1 = SimpleNamespace(session_id="11111111", idb_path="/tmp/a/target.i64")
    s2 = SimpleNamespace(session_id="22222222", idb_path="/tmp/b/target.i64")
    server.session_mgr.discover_sessions.return_value = [s1, s2]
    assert server._resolve_session_from_idb_ref("target.i64") is None
