"""Behavior coverage for runtime transport and observability helpers.

These tests exercise the same mixin methods used by the composed server while
keeping the process and socket boundaries deterministic.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import (
    RpcPayloadTooLarge,
    RpcQueueTimeout,
    ServerRuntimeMixin,
)

SID = "AB12CDEF"


class _Proc:
    def __init__(self, *, pid=123, poll_value=None, wait_values=()):
        self.pid = pid
        self.returncode = poll_value
        self._poll_value = poll_value
        self._wait_values = list(wait_values)
        self.calls = []

    def poll(self):
        return self._poll_value

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self._wait_values:
            value = self._wait_values.pop(0)
            if isinstance(value, BaseException):
                raise value
            self.returncode = value
        return self.returncode


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._activity_log = []
        self._activity_log_max = 3
        self.current_session = SimpleNamespace(session_id=SID)
        self.cache_dir = str(tmp_path)
        self.large_idb_shutdown_grace_seconds = 30.0
        self.session_mgr = SimpleNamespace(log_activity=lambda *a, **k: None)


class _FakeSocket:
    response = b""
    instances = []

    def __init__(self, *_args):
        self.sent = b""
        self.timeouts = []
        self.connected = None
        self.closed = False
        self._chunks = []
        self.__class__.instances.append(self)

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.connected = address

    def sendall(self, data):
        self.sent += data
        self._chunks = [self.response[:2], self.response[2:4], self.response[4:]]

    def recv(self, _size):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        self.closed = True


def test_rpc_transport_auth_framing_and_fragmented_response(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {"port": 7777, "auth_token": "secret"}
    response = json.dumps({"ok": True, "value": "done"}).encode()
    _FakeSocket.instances = []
    _FakeSocket.response = len(response).to_bytes(4, "big") + response
    monkeypatch.setattr(socket, "socket", _FakeSocket)

    request = {"tool": "code", "args": {"action": "status"}}
    result = host._send_rpc_raw(request, 7777, timeout=2, recv_timeout=9)

    assert result == {"ok": True, "value": "done"}
    assert request == {"tool": "code", "args": {"action": "status"}}
    sent = _FakeSocket.instances[0].sent
    frame_len = int.from_bytes(sent[:4], "big")
    payload = json.loads(sent[4:].decode())
    assert frame_len == len(sent) - 4
    assert payload["session_token"] == "secret"
    assert _FakeSocket.instances[0].timeouts == [2, 9]
    assert _FakeSocket.instances[0].connected == ("127.0.0.1", 7777)
    assert _FakeSocket.instances[0].closed


def test_rpc_transport_rejects_payloads_and_releases_busy_lane(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {"port": 7777, "rpc_lock": threading.Lock()}
    lock = host.session_runtimes[SID]["rpc_lock"]
    lock.acquire()
    try:
        with pytest.raises(RpcQueueTimeout):
            host._send_rpc_raw({"tool": "x"}, 7777, queue_timeout=0)
    finally:
        lock.release()

    monkeypatch.setattr(runtime_mod, "MAX_RPC_REQUEST_SIZE", 32)
    with pytest.raises(RpcPayloadTooLarge):
        host._send_rpc_raw({"large": "x" * 100}, 7777)
    assert not lock.locked()


def test_rpc_retry_distinguishes_transient_os_and_size_failures(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    calls = []

    def flaky(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionRefusedError("starting")
        return {"ok": True}

    monkeypatch.setattr(host, "_send_rpc_raw", flaky)
    assert host._send_rpc_with_retry({}, 7777, base_backoff=0, max_retries=2) == {"ok": True}
    assert len(calls) == 2

    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("busy")))
    with pytest.raises(TimeoutError):
        host._send_rpc_with_retry({}, 7777, max_retries=2)

    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda *_a, **_k: (_ for _ in ()).throw(RpcPayloadTooLarge("too big")),
    )
    result = host._send_rpc_with_retry({}, 7777)
    assert result["error"] is True
    assert result["code"] == "SIZE_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    ("proc", "expected"),
    [
        (None, {"attempted": False, "error": "no_process_in_runtime"}),
        (_Proc(poll_value=7), {"terminated": True, "signaled": "already_exited"}),
        (_Proc(wait_values=(0,)), {"terminated": True, "signaled": "SIGTERM"}),
        (
            _Proc(wait_values=(subprocess.TimeoutExpired("wait", 1), 9)),
            {"terminated": True, "signaled": "SIGKILL"},
        ),
    ],
)
def test_kill_ida_process_reports_each_process_lifecycle(tmp_path, proc, expected):
    host = _Host(tmp_path)
    result = host._kill_ida_process({"process": proc} if proc else {})
    for key, value in expected.items():
        assert result.get(key) == value
    if proc and proc.poll() is None:
        assert "terminate" in proc.calls


def test_kill_ida_process_surfaces_signal_and_final_wait_errors(tmp_path):
    host = _Host(tmp_path)

    class Broken(_Proc):
        def terminate(self):
            raise OSError("term denied")

        def kill(self):
            raise OSError("kill denied")

    result = host._kill_ida_process({"process": Broken(wait_values=(RuntimeError("wait"), RuntimeError("again")))})
    assert result["terminate_error"] == "term denied"
    assert result["kill_error"] == "kill denied"
    assert result["final_wait_error"] == "again"


def test_activity_extracts_all_address_shapes_and_persists_workset(tmp_path):
    host = _Host(tmp_path)
    logged = []
    host.session_mgr.log_activity = lambda *args, **kwargs: logged.append((args, kwargs))
    host._record_activity(
        "search",
        {
            "session_id": SID,
            "action": "find",
            "addr": 0x1000,
            "address": "at 0x2000 and 0x3000",
            "addrs": [0x4000, "0x5000 extra"],
        },
        {
            "ok": True,
            "resolved_topic": "network",
            "items": [{"address": "0x6000"}, {"address_ea": 0x7000}, "ignored"],
            "matches": "0x8000",
        },
    )
    row = host._activity_log[-1]
    assert row["addresses"] == ["0x1000", "0x2000", "0x3000", "0x4000", "0x5000", "0x6000", "0x7000", "0x8000"]
    assert logged and "network" in logged[0][1]["result"]

    host.bookmark_mgr = SimpleNamespace(
        list=lambda *_a, **_k: {"bookmarks": [{"timestamp": "now", "addr": "0x9000", "name": "entry", "category": "code", "tags": ["x"]}]}
    )
    workset = host._build_recent_workset(SID, 20, True, True)
    assert workset["count"] == 2
    assert "bookmark" in workset["workset"]
    assert workset["items"][-1]["kind"] == "bookmark"


def test_state_snapshot_covers_dead_process_and_unserializable_arguments(tmp_path):
    host = _Host(tmp_path)

    class BadProc:
        pid = 0

        def poll(self):
            raise RuntimeError("poll failed")

    snap = host._collect_ida_state_snapshot(
        runtime={"process": BadProc()},
        current_tool="code",
        current_args={"value": object()},
        call_started_at=0,
        include_process_stats=False,
    )
    assert snap["process_alive"] is None
    assert snap["process_error"] == "poll failed"
    assert snap["current_tool"] == "code"
    assert "current_args" in snap


def test_query_state_and_session_update_compatibility_paths(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {"process": _Proc(), "port": 7777, "auth_token": "tok"}

    def runtime_alive(runtime):
        return bool(runtime)

    monkeypatch.setattr(host, "_runtime_alive", runtime_alive, raising=False)
    sent = []
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *args, **kwargs: sent.append((args, kwargs)) or {"ok": True, "analysis": {}})
    state = host._query_ida_state(SID, timeout=4)
    assert state["ok"] is True
    assert sent[0][0][1] == 7777
    assert sent[0][1]["auth_token"] == "tok"
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_a, **_k: {"error": True})
    assert host._query_ida_state(SID) is None

    saved = []
    session = SimpleNamespace(session_id=SID, metadata={})

    def save_metadata(value):
        saved.append(value)

    host.session_mgr = SimpleNamespace(
        sessions={SID: session},
        _save_metadata=save_metadata,
    )
    host._update_session_indexing_metadata(SID, analysis_state="ready")
    assert session.metadata["analysis_state"] == "ready"
    host._persist_session_fields(session, runtime_pid=42)
    assert saved and session.runtime_pid == 42


def test_runtime_policy_helpers_cover_shutdown_and_checkpoint_bounds(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    host.checkpoint_save_seconds = "bad"
    assert host._checkpoint_save_interval() == 5.0
    assert host._shutdown_rpc_save_timeout(500) == 60.0
    assert host._shutdown_rpc_save_timeout("bad") == 1.0
    assert host._shutdown_grace_seconds(SID, {}) == 2.0

    idb = tmp_path / "large.i64"
    idb.write_bytes(b"x")
    monkeypatch.setattr(runtime_mod, "_LARGE_IDB_CHECKPOINT_THRESHOLD", 1)
    assert host._shutdown_grace_seconds(SID, {"idb_path": str(idb)}) == 30.0


def test_process_tree_kill_covers_platform_escalation_and_missing_pids(monkeypatch):
    """The host must contain only the child process tree on every platform."""
    runtime_mod._kill_process_tree(SimpleNamespace(pid=None))

    windows_proc = _Proc(wait_values=(0,))
    windows_calls = []
    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    monkeypatch.setattr(
        runtime_mod.subprocess,
        "run",
        lambda argv, **_kwargs: windows_calls.append(argv),
    )
    runtime_mod._kill_process_tree(windows_proc, grace_seconds=0.1)
    assert windows_calls == [["taskkill", "/T", "/F", "/PID", "123"]]

    # A failed taskkill and wait are deliberately swallowed: teardown must
    # still be best effort when Windows has already removed the process.
    monkeypatch.setattr(
        runtime_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("taskkill")),
    )
    broken_windows = _Proc(wait_values=(RuntimeError("gone"),))
    runtime_mod._kill_process_tree(broken_windows)

    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")
    posix_proc = _Proc(wait_values=(0,))
    signals = []
    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(runtime_mod.time, "time", lambda: next(clock))
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        runtime_mod.os,
        "killpg",
        lambda pid, sig: signals.append((pid, sig)),
    )
    runtime_mod._kill_process_tree(posix_proc, grace_seconds=1.0)
    assert signals == [(123, runtime_mod.signal.SIGTERM), (123, 0), (123, runtime_mod.signal.SIGKILL)]

    # A vanished group and an unprobeable group are both safe no-op exits.
    monkeypatch.setattr(
        runtime_mod.os,
        "killpg",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    runtime_mod._kill_process_tree(_Proc())
    monkeypatch.setattr(runtime_mod.time, "time", lambda: 0.0)
    monkeypatch.setattr(
        runtime_mod.os,
        "killpg",
        lambda _pid, sig: (
            (_ for _ in ()).throw(OSError("permission denied"))
            if sig == 0
            else None
        ),
    )
    runtime_mod._kill_process_tree(_Proc())


def test_runtime_ownership_reclaims_dead_and_damaged_owner_records(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    host._runtime_lease_dir = str(tmp_path)
    host._runtime_owner_id = "owner-a"
    sid = "DEAD1234"
    owner_path = Path(host._runtime_owner_path(sid))

    owner_path.write_text(
        json.dumps({"owner_id": "other", "owner_pid": 99999999}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        runtime_mod.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    assert host._claim_runtime_ownership(sid) == str(owner_path)
    assert json.loads(owner_path.read_text())["owner_id"] == host._runtime_owner_id

    damaged_sid = "BAD12345"
    damaged_path = Path(host._runtime_owner_path(damaged_sid))
    damaged_path.write_text("not-json", encoding="utf-8")
    assert host._claim_runtime_ownership(damaged_sid) == str(damaged_path)

    foreign_sid = "PERM1234"
    foreign_path = Path(host._runtime_owner_path(foreign_sid))
    foreign_path.write_text(
        json.dumps({"owner_id": "other", "owner_pid": 77}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        runtime_mod.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(PermissionError()),
    )
    assert host._claim_runtime_ownership(foreign_sid) is None


def test_rpc_transport_handles_eof_response_cap_and_connect_cleanup(monkeypatch, tmp_path):
    host = _Host(tmp_path)

    class EofSocket(_FakeSocket):
        def recv(self, _size):
            if self._chunks:
                return self._chunks.pop(0)
            return b""

    EofSocket.instances = []
    EofSocket.response = b"\x00\x00\x00\x05ab"
    monkeypatch.setattr(socket, "socket", EofSocket)
    with pytest.raises(EOFError):
        host._send_rpc_raw({"tool": "x"}, 3333)
    assert EofSocket.instances[0].closed

    EofSocket.instances = []
    EofSocket.response = (33).to_bytes(4, "big")
    monkeypatch.setattr(runtime_mod, "MAX_RPC_REQUEST_SIZE", 32)
    with pytest.raises(RpcPayloadTooLarge):
        host._send_rpc_raw({"tool": "x"}, 3333)
    assert EofSocket.instances[0].closed

    lane = threading.Lock()
    host.session_runtimes[SID] = {"port": 3333, "rpc_lock": lane}

    class ConnectFailure:
        def __init__(self, *_args):
            self.closed = False

        def settimeout(self, _value):
            return None

        def connect(self, _address):
            raise OSError("offline")

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "socket", ConnectFailure)
    with pytest.raises(OSError):
        host._send_rpc_raw({"tool": "x"}, 3333)
    assert not lane.locked()


def test_rpc_retry_exhaustion_and_non_retryable_errors(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    attempts = []

    def always_transient(*_args, **_kwargs):
        attempts.append(True)
        raise ConnectionAbortedError("starting")

    monkeypatch.setattr(host, "_send_rpc_raw", always_transient)
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda _seconds: None)
    with pytest.raises(ConnectionAbortedError):
        host._send_rpc_with_retry({}, 7, max_retries=2)
    assert len(attempts) == 3

    attempts.clear()
    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("bad socket")),
    )
    with pytest.raises(OSError):
        host._send_rpc_with_retry({}, 7, max_retries=4)
    assert not attempts

    monkeypatch.setenv("IDA_MCP_RPC_MAX_RETRIES", "not-an-int")
    monkeypatch.setattr(host, "_send_rpc_raw", lambda *_args, **_kwargs: {"ok": True})
    assert host._send_rpc_with_retry({}, 7) == {"ok": True}


def test_runtime_discovery_cross_platform_and_preload_loader_matrix(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    host._ida_dir = None
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.delenv("IDA_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_IDAT", raising=False)
    monkeypatch.setattr(runtime_mod.os.path, "realpath", str)
    monkeypatch.setattr(runtime_mod.shutil, "which", lambda _name: None)

    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    monkeypatch.setattr(runtime_mod.os.path, "isdir", lambda value: str(value).startswith("C:"))
    monkeypatch.setattr(host, "_is_executable_file", lambda value: str(value).endswith("idat.exe"))
    assert host._detect_ida_dir().startswith("C:")
    assert host._ida_binary_names()[0].endswith(".exe")

    monkeypatch.setattr(runtime_mod.sys, "platform", "darwin")
    monkeypatch.setattr(runtime_mod.os.path, "isdir", lambda value: str(value).startswith("/Applications"))
    monkeypatch.setattr(host, "_is_executable_file", lambda value: str(value).endswith("idat"))
    assert host._detect_ida_dir().startswith("/Applications")

    elf = tmp_path / "program"
    elf.write_bytes(b"\x7fELF\x02\x01")
    session = SimpleNamespace(
        binary_path=str(elf),
        idb_path=str(tmp_path / "program.i64"),
        analysis_options={"processor": "metapc", "input_format": "elf", "rebase_to": "0x2000"},
        ida_args=["-pold"],
    )
    args = host._preload_ida_args(session)
    assert "-pmetapc" not in args and "-Telf" in args
    assert "-b0x200" in args

    raw = tmp_path / "raw"
    raw.write_bytes(b"raw")
    session.binary_path = str(raw)
    session.ida_args = ["-c"]
    session.analysis_options = {
        "baseaddr": "0x123",
        "entry_point": "bad",
        "rebase_to": "0x1234",
        "skip_analysis": True,
        "no_analysis": True,
        "processor_options": {"x": 1},
        "stack_size": 8,
        "memory_model": "flat",
    }
    args = host._preload_ida_args(session)
    assert "-Tbin" in args and "-b0x123" in args and "-c" not in args
    assert "-ibad" in args


def test_runtime_idalib_paths_activity_filters_and_session_fallback(tmp_path):
    host = _Host(tmp_path)
    host.ida_dir = str(tmp_path / "ida")
    idalib_python = Path(host.ida_dir) / "idalib" / "python"
    (idalib_python / "idapro").mkdir(parents=True)
    assert host._idalib_python_dir() == str(idalib_python)

    host.ida_dir = str(tmp_path / "dev")
    dev_python = Path(host.ida_dir) / "idalib" / "python"
    dev_python.mkdir(parents=True)
    assert host._idalib_python_dir() == str(dev_python)

    host.current_session = SimpleNamespace(session_id=SID)
    host._usage_intel = object()
    host.session_mgr.log_activity = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("store"))
    host._record_activity("code", {"action": 4, "address": "0x1000"}, {"ok": True})
    assert host._session_last_activity[SID]
    assert host._activity_log[-1]["action"] == ""
    before = list(host._activity_log)
    host._record_activity("code", {"session_id": SID}, {"error": True})
    host._record_activity("code", "not-a-dict", {"ok": True})
    assert host._activity_log == before

    host.bookmark_mgr = SimpleNamespace(list=lambda *_args, **_kwargs: {"bookmarks": ["bad", {}]})
    workset = host._build_recent_workset(SID, 0, True, False)
    assert workset["count"] == 1 and "items" not in workset
