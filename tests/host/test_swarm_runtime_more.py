"""Offline transport and recovery coverage for ``server_runtime``."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import (
    RpcPayloadTooLarge,
    RpcQueueTimeout,
    ServerRuntimeMixin,
)


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._runtime_lease_dir = str(tmp_path / "leases")
        self._runtime_owner_id = "owner-more"
        self.cache_dir = str(tmp_path)
        self.ida_dir = None
        self.idat_exe = str(tmp_path / "idat64")
        self._macro_path = str(tmp_path / "macros.json")
        self._session_macros = {}
        self._session_last_activity = {}
        self._activity_log = []
        self._activity_log_max = 20
        self.current_session = None
        os.makedirs(self._runtime_lease_dir, exist_ok=True)


def _read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def test_send_rpc_raw_uses_framing_auth_and_fragmented_response(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received = {}
    response = json.dumps({"ok": True, "value": "bridge"}).encode()

    def serve():
        conn, _address = listener.accept()
        with conn:
            size = int.from_bytes(_read_exact(conn, 4), "big")
            received["payload"] = json.loads(_read_exact(conn, size))
            conn.sendall(len(response).to_bytes(4, "big"))
            conn.sendall(response[:3])
            conn.sendall(response[3:])

    thread = threading.Thread(target=serve)
    thread.start()
    port = listener.getsockname()[1]
    host.session_runtimes["SID12345"] = {
        "port": port,
        "auth_token": "secret",
        "rpc_lock": None,
    }
    monkeypatch.setenv("IDA_MCP_RPC_TIMEOUT", "not-a-number")
    request = {"tool": "idb", "args": {"action": "state"}}
    result = host._send_rpc_raw(request, port, recv_timeout=None)
    thread.join(timeout=2)
    listener.close()
    assert result == {"ok": True, "value": "bridge"}
    assert received["payload"]["session_token"] == "secret"
    assert "session_token" not in request
    assert host.session_runtimes["SID12345"]["rpc_lock"].locked() is False


def test_send_rpc_raw_queue_timeout_and_payload_limit(tmp_path):
    host = _Host(tmp_path)
    lane = threading.Lock()
    lane.acquire()
    host.session_runtimes["SID12345"] = {"port": 99, "rpc_lock": lane}
    with pytest.raises(RpcQueueTimeout):
        host._send_rpc_raw({"x": 1}, 99, queue_timeout=0)
    lane.release()
    too_large = {"data": "x" * (runtime_mod.MAX_RPC_REQUEST_SIZE + 1)}
    with pytest.raises(RpcPayloadTooLarge):
        host._send_rpc_raw(too_large, 99)
    limited = host._send_rpc_with_retry(too_large, 99, max_retries=4)
    assert limited["code"] == MCPError.SIZE_LIMIT_EXCEEDED


def test_send_rpc_with_retry_only_retries_transient_failures(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    attempts = []

    def transient(*_args, **_kwargs):
        attempts.append(1)
        if len(attempts) < 3:
            raise ConnectionRefusedError("starting")
        return {"ok": True}

    monkeypatch.setattr(host, "_send_rpc_raw", transient)
    assert host._send_rpc_with_retry({}, 99, base_backoff=0, max_retries=2) == {"ok": True}
    assert len(attempts) == 3
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("busy")))
    with pytest.raises(TimeoutError):
        host._send_rpc_with_retry({}, 99, max_retries=5, base_backoff=0)


class _Proc:
    pid = 123

    def __init__(self, *, exited=False, timeout=False):
        self.exited = exited
        self.timeout = timeout
        self.returncode = 0 if exited else None
        self.calls = []

    def poll(self):
        return 0 if self.exited else None

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self.timeout and "kill" not in self.calls:
            raise subprocess.TimeoutExpired("idat", timeout)
        self.returncode = -9 if "kill" in self.calls else 0
        return self.returncode


def test_kill_ida_process_reports_exited_graceful_and_escalated_modes(tmp_path):
    host = _Host(tmp_path)
    exited = host._kill_ida_process({"process": _Proc(exited=True)})
    assert exited["terminated"] is True
    assert exited["signaled"] == "already_exited"
    graceful_proc = _Proc()
    graceful = host._kill_ida_process({"process": graceful_proc}, grace_sec=0)
    assert graceful["terminated"] is True
    assert graceful_proc.calls[0] == "terminate"
    escalated_proc = _Proc(timeout=True)
    escalated = host._kill_ida_process({"process": escalated_proc}, grace_sec=0)
    assert escalated["terminated"] is True
    assert escalated["signaled"] == "SIGKILL"
    assert host._kill_ida_process({})["error"] == "no_process_in_runtime"


@pytest.mark.parametrize(
    "message, expected",
    [
        ("library init failed: cannot open shared object file", "Missing shared runtime library"),
        ("library initialization failed: GLIBCXX_3.4 missing", "C++ runtime ABI"),
        ("error=2: Qt platform plugin xcb", "Qt platform/plugin"),
        ("library init failed: error 4: wrong ELF class", "architecture mismatch"),
        ("error 2: permission denied", "permission error"),
        ("library init failed: plugin failed during startup", "plugin failed"),
        ("library init failed: python module init failed", "Embedded Python"),
        ("library init failed: no space left on device", "Insufficient disk"),
        ("library init failed: opaque failure", "Generic library"),
    ],
)
def test_library_initialization_diagnostics_classify_causes(tmp_path, message, expected):
    host = _Host(tmp_path)
    result = host._extract_library_init_failure(message)
    assert result["detected"] is True
    assert any(expected in cause for cause in result["causes"])
    assert host._is_library_init_err2(message) is True
    assert host._extract_library_init_failure("") is None
    assert host._is_library_init_err2("normal startup") is False


def test_orphan_lock_detection_requires_database_context(tmp_path):
    host = _Host(tmp_path)
    assert host._is_orphan_locked_db_open_failure("resource temporarily unavailable") is False
    assert host._is_orphan_locked_db_open_failure(
        "resource temporarily unavailable: database did not close properly"
    ) is True
    assert host._is_orphan_locked_db_open_failure(
        "resource temporarily unavailable: database initialization failed"
    ) is True
    assert host._is_orphan_locked_db_open_failure("error 4") is False


def test_runtime_discovery_preload_and_idalib_paths_cover_fallbacks(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    (ida_dir / "idat64").write_text("", encoding="utf-8")
    (ida_dir / "idat64").chmod(0o755)
    host._ida_dir = str(ida_dir)
    names = host._ida_binary_names()
    assert names[0] == "idat64"
    assert host._is_executable_file(str(ida_dir / "idat64")) is True
    assert host._is_executable_file("") is False
    monkeypatch.setenv("IDADIR", str(ida_dir / "idat64"))
    assert host._detect_ida_dir() == str(ida_dir)
    monkeypatch.setenv("IDA_MCP_IDAT", str(ida_dir / "idat64"))
    host.ida_dir = None
    assert host._find_idat() == str(ida_dir / "idat64")
    host.ida_dir = str(ida_dir)

    python_dir = ida_dir / "idalib" / "python" / "idapro"
    python_dir.mkdir(parents=True)
    assert host._idalib_python_dir() == str(python_dir.parent)
    session = SimpleNamespace(
        binary_path=str(tmp_path / "raw.bin"),
        idb_path=str(tmp_path / "raw.i64"),
        ida_args=[],
        analysis_options={"processor": "arm", "loader": "bin", "baseaddr": "0x1000", "entry_point": "0x1010"},
    )
    Path(session.binary_path).write_bytes(b"RAW!")
    preload = host._preload_ida_args(session)
    assert preload == ["-parm", "-Tbin", "-b0x100", "-i0x1010"]
    session.analysis_options = {"processor_options": {}, "stack_size": 4, "memory_model": "flat"}
    assert host._preload_ida_args(session) == ["-Tbin"]


def test_json_rendering_and_backup_paths_cover_non_json_values(tmp_path):
    host = _Host(tmp_path)

    class BadKey:
        def __str__(self):
            raise RuntimeError("bad key")

    safe = host._json_safe_value({BadKey(): bytearray(b"ok"), "raw": b"\xff"})
    assert safe["<non_string_key>"] == "ok"
    assert safe["raw"] == {"_bytes_hex": "ff"}
    rendered = host._render_payload_text({"empty": {}, "list": ["```\na\nb", True]})
    assert "(empty)" in rendered
    assert "```text" in rendered
    assert "````" in rendered

    source = tmp_path / "database.i64"
    source.write_text("idb", encoding="utf-8")
    backup = host._backup_idb(str(source))
    assert backup and Path(backup).exists() and not source.exists()
    host._cleanup_stale_idb_family(backup)
    assert host._backup_idb(str(tmp_path / "missing.i64")) is None


def test_terminate_ida_processes_covers_psutil_and_live_pid_filtering(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    target = tmp_path / "sample.i64"
    target.write_bytes(b"idb")

    class Process:
        def __init__(self, info):
            self.info = info

    live = _Proc()
    live.pid = 111
    host.session_runtimes["LIVE1234"] = {"process": live}
    candidates = [
        Process({"pid": 111, "name": "idat64", "cmdline": ["idat64", str(target)]}),
        Process({"pid": 222, "name": "idat64", "cmdline": ["idat64", str(target)]}),
        Process({"pid": 333, "name": "unrelated", "cmdline": ["unrelated", str(target)]}),
        Process({"pid": "bad", "name": "ida64", "cmdline": ["ida64", str(target)]}),
    ]
    psutil = SimpleNamespace(process_iter=lambda _attrs: candidates)
    monkeypatch.setitem(sys.modules, "psutil", psutil)
    grouped = []
    killed = []
    monkeypatch.setattr(runtime_mod.os, "getpgid", lambda pid: pid if pid == 222 else 1)
    monkeypatch.setattr(runtime_mod.os, "killpg", lambda pid, sig: grouped.append((pid, sig)))
    monkeypatch.setattr(runtime_mod.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    assert host._terminate_ida_processes_for_path(str(target)) == [222]
    assert grouped == [(222, runtime_mod.signal.SIGTERM)]
    assert killed == []

    class BrokenProcess:
        @property
        def info(self):
            raise RuntimeError("process disappeared")

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(process_iter=lambda _attrs: [BrokenProcess()]))
    assert host._terminate_ida_processes_for_path(str(target)) == []


def test_terminate_ida_processes_uses_windows_wmic_fallback(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    target = tmp_path / "sample.i64"
    target.write_bytes(b"idb")
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        if command[0] == "wmic":
            return SimpleNamespace(
                stdout=(
                    "ProcessId: 321\n"
                    f"CommandLine: idat64.exe -o{target}\n"
                    "ProcessId: not-a-pid\n"
                    f"CommandLine: idat64.exe {target}\n"
                )
            )
        return SimpleNamespace(stdout="")

    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    monkeypatch.setattr(runtime_mod.subprocess, "run", run)
    assert host._terminate_ida_processes_for_path(str(target)) == [321]
    assert commands[0][0] == "wmic"
    assert commands[1][:4] == ["taskkill", "/T", "/F", "/PID"]


def test_terminate_ida_processes_uses_proc_fallback_and_skips_bad_entries(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    target = tmp_path / "sample.i64"
    target.write_bytes(b"idb")
    real_open = open
    real_realpath = runtime_mod.os.path.realpath

    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")
    monkeypatch.setattr(runtime_mod.os, "listdir", lambda path: ["not-a-pid", "444"])

    def proc_open(path, *args, **kwargs):
        if path == "/proc/444/cmdline":
            return __import__("io").BytesIO(f"idat64\x00{target}\x00".encode())
        return real_open(path, *args, **kwargs)

    def realpath(path):
        if path == "/proc/444/exe":
            return "/opt/ida/idat64"
        return real_realpath(path)

    monkeypatch.setattr("builtins.open", proc_open)
    monkeypatch.setattr(runtime_mod.os.path, "realpath", realpath)
    sent = []
    monkeypatch.setattr(runtime_mod.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    assert host._terminate_ida_processes_for_path(str(target)) == [444]
    assert sent == [(444, runtime_mod.signal.SIGTERM)]


def test_process_tree_failure_paths_are_best_effort(monkeypatch):
    class Proc:
        pid = 777

        def wait(self, **_kwargs):
            return None

    calls = []

    def killpg(pid, sig):
        calls.append((pid, sig))
        if sig == runtime_mod.signal.SIGTERM:
            raise RuntimeError("permission denied")
        if sig == runtime_mod.signal.SIGKILL:
            raise ProcessLookupError

    clock = iter((100.0, 100.01, 100.06))
    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")
    monkeypatch.setattr(runtime_mod.os, "killpg", killpg)
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(clock))
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda _seconds: None)
    runtime_mod._kill_process_tree(Proc(), grace_seconds=0.05)
    assert calls == [(777, runtime_mod.signal.SIGTERM), (777, 0), (777, runtime_mod.signal.SIGKILL)]
