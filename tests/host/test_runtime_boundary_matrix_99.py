"""Additional runtime boundary coverage across discovery, RPC, and cleanup."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as runtime_mod
from ida_pro_mcp.host.server.server_runtime import (
    RpcPayloadTooLarge,
    RpcQueueTimeout,
    ServerRuntimeMixin,
)


class _Host(ServerRuntimeMixin):
    def __init__(self, tmp_path):
        self.cache_dir = str(tmp_path)
        self._runtime_lease_dir = str(tmp_path / "leases")
        Path(self._runtime_lease_dir).mkdir(parents=True)
        self._runtime_owner_id = "owner-99"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_last_activity = {}
        self._activity_log = []
        self._activity_log_max = 50
        self.session_mgr = SimpleNamespace(sessions={})
        self.current_session = None
        self.ida_dir = ""
        self.idat_exe = ""


def test_runtime_lease_corruption_and_discovery_fallbacks(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    sid = "ABC12345"
    path = Path(host._runtime_owner_path(sid))
    path.write_text("[]", encoding="utf-8")
    assert host._claim_runtime_ownership(sid) is not None
    host._release_runtime_ownership(sid)
    path.write_text(json.dumps({"owner_id": "someone-else"}), encoding="utf-8")
    host._release_runtime_ownership(sid)
    assert path.exists()

    monkeypatch.setattr(runtime_mod.sys, "platform", "win32")
    assert host._ida_binary_names()[0].endswith(".exe")
    monkeypatch.setattr(runtime_mod.sys, "platform", "linux")
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    idat = ida_dir / "idat"
    idat.write_text("", encoding="utf-8")
    idat.chmod(0o755)
    monkeypatch.setenv("IDADIR", "")
    monkeypatch.setenv("IDA_DIR", "")
    monkeypatch.setenv("IDA_MCP_IDAT", str(idat))
    assert host._detect_ida_dir() == str(ida_dir)

    host.ida_dir = ""
    monkeypatch.setenv("IDA_MCP_IDAT", str(tmp_path / "missing"))
    monkeypatch.setattr(runtime_mod.shutil, "which", lambda _name: None)
    host._detect_ida_dir = lambda: ""
    assert host._find_idat() == ""
    assert host._detect_ida_dir() == ""


class _FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""
        self.timeouts = []
        self.connected = None
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.connected = address

    def sendall(self, data):
        self.sent += data

    def recv(self, _size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)

    def close(self):
        self.closed = True


def test_rpc_protocol_fragmentation_caps_and_queue_release(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    lock = threading.Lock()
    host.session_runtimes["sid"] = {
        "port": 4321,
        "auth_token": "secret",
        "rpc_lock": lock,
    }
    payload = json.dumps({"ok": True, "value": "done"}).encode()
    response = len(payload).to_bytes(4, "big") + payload
    fake = _FakeSocket([response[:1], response[1:3], response[3:4], response[4:7], response[7:]])
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)
    monkeypatch.setenv("IDA_MCP_RPC_TIMEOUT", "bad")
    result = host._send_rpc_raw({"tool": "ping"}, 4321)
    assert result["ok"] is True
    sent_len = int.from_bytes(fake.sent[:4], "big")
    sent_request = json.loads(fake.sent[4:])
    assert sent_len == len(fake.sent[4:])
    assert sent_request["session_token"] == "secret"
    assert fake.connected == ("127.0.0.1", 4321)
    assert fake.closed is True
    assert lock.acquire(blocking=False) is True
    lock.release()

    monkeypatch.setattr(runtime_mod, "MAX_RPC_REQUEST_SIZE", 4)
    with pytest.raises(RpcPayloadTooLarge):
        host._send_rpc_raw({"large": "request"}, 4321)
    assert lock.acquire(blocking=False) is True
    lock.release()

    # A missing runtime lane still uses the socket path, while a zero queue
    # budget rejects a held lane without touching the network.
    host.session_runtimes = {"sid": {"port": 4321, "rpc_lock": lock}}
    lock.acquire()
    try:
        with pytest.raises(RpcQueueTimeout):
            host._send_rpc_raw({"x": 1}, 4321, queue_timeout=0)
    finally:
        lock.release()


def test_rpc_retry_classification_and_process_kill_escalation(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    attempts = {"count": 0}

    def flaky(*_args, **_kwargs):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise ConnectionRefusedError("starting")
        return {"pong": True}

    host._send_rpc_raw = flaky
    assert host._send_rpc_with_retry({}, 1, max_retries=2, base_backoff=0) == {"pong": True}
    assert attempts["count"] == 3
    host._send_rpc_raw = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("busy"))
    with pytest.raises(TimeoutError):
        host._send_rpc_with_retry({}, 1, max_retries=2, base_backoff=0)

    class Exited:
        pid = 7
        returncode = 3

        def poll(self):
            return 3

    assert host._kill_ida_process({"process": Exited()})["signaled"] == "already_exited"
    assert host._kill_ida_process({})["error"] == "no_process_in_runtime"

    class Graceful:
        pid = 8
        returncode = 0

        def __init__(self):
            self.events = []

        def poll(self):
            return None

        def terminate(self):
            self.events.append("term")

        def wait(self, timeout=None):
            self.events.append(("wait", timeout))

        def kill(self):
            self.events.append("kill")

    proc = Graceful()
    result = host._kill_ida_process({"process": proc}, grace_sec=0)
    assert result["terminated"] is True and proc.events == ["term", ("wait", 0)]

    class Escalating(Graceful):
        def wait(self, timeout=None):
            self.events.append(("wait", timeout))
            if len([x for x in self.events if isinstance(x, tuple)]) == 1:
                raise subprocess.TimeoutExpired("idat", timeout)

    proc = Escalating()
    result = host._kill_ida_process({"process": proc}, grace_sec=0)
    assert result["signaled"] == "SIGKILL" and "kill" in proc.events


def test_runtime_activity_workset_and_state_fallbacks(tmp_path):
    host = _Host(tmp_path)
    logged = []
    host.current_session = SimpleNamespace(session_id="SID12345")
    host.session_mgr.log_activity = lambda sid, **kwargs: logged.append((sid, kwargs))
    host._usage_intel = object()
    host._record_activity(
        "search",
        {
            "action": "find",
            "addr": "0x1000 and 0x1004",
            "addrs": [0x1008, "0x100c"],
            "query": "needle",
        },
        {
            "items": [{"address": "0x1010"}, {"address_ea": 0x1014}],
            "matches": "0x1018 0x1018",
            "topic": "strings",
        },
    )
    assert len(host._activity_log) == 1
    assert len(logged) == 1
    host._activity_log.append(host._activity_log[0].copy())
    host.bookmark_mgr = SimpleNamespace(
        list=lambda _sid, _args: {
            "bookmarks": [
                {"timestamp": "now", "addr": "0x2000", "name": "mark"},
                "malformed",
            ]
        }
    )
    workset = host._build_recent_workset("SID12345", 4, True, True)
    assert workset["count"] == 2
    assert "bookmark" in workset["workset"]
    assert host._build_recent_workset("other", 1, False, False)["count"] == 0

    session = SimpleNamespace(session_id="SID12345", metadata={"same": 1})
    host.session_mgr.sessions["SID12345"] = session
    host.session_mgr._save_metadata = lambda value: setattr(host, "saved", value)
    host._update_session_indexing_metadata("SID12345", same=1)
    host._update_session_indexing_metadata("SID12345", changed=2)
    assert session.metadata["changed"] == 2
    host._update_session_indexing_metadata("missing", changed=4)


def test_runtime_process_inventory_and_render_variants(monkeypatch, tmp_path):
    host = _Host(tmp_path)
    live = SimpleNamespace(info={"pid": 11, "name": "idat64", "cmdline": ["idat64", "/db.i64"]})
    stale = SimpleNamespace(info={"pid": 12, "name": "ida64", "cmdline": ["ida64", "/db.i64"]})
    unrelated = SimpleNamespace(info={"pid": 13, "name": "python", "cmdline": ["python", "/db.i64"]})
    psutil = types.ModuleType("psutil")
    psutil.process_iter = lambda _fields: iter([live, stale, unrelated])
    monkeypatch.setitem(sys.modules, "psutil", psutil)
    host.session_runtimes["live"] = {"process": SimpleNamespace(pid=11, poll=lambda: None)}
    killed = []
    monkeypatch.setattr(runtime_mod.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(runtime_mod.os, "killpg", lambda pid, sig: killed.append(("pg", pid, sig)))
    monkeypatch.setattr(runtime_mod.os, "kill", lambda pid, sig: killed.append(("p", pid, sig)))
    result = host._terminate_ida_processes_for_path("/db.i64")
    assert result == [12]
    assert killed == [("pg", 12, runtime_mod.signal.SIGTERM)]
    assert not host._terminate_ida_processes_for_path("")

    assert "````text" in host._render_payload_text({"empty": {}, "code": "line\nx```y"})
    assert host._json_safe_value((b"x", {b"y"}))


def test_runtime_preload_native_detection_idalib_args_and_session_resolution(tmp_path):
    host = _Host(tmp_path)
    native = tmp_path / "sample.elf"
    native.write_bytes(b"\x7fELF\0\0")
    session = SimpleNamespace(
        binary_path=str(native),
        idb_path=str(tmp_path / "sample.i64"),
        analysis_options={"baseaddr": 8, "entry_point": 0, "rebase_to": 0, "no_analysis": True},
        ida_args=["-Tother", "-b0x1000", "-i0x20", "-c"],
    )
    assert host._preload_ida_args(session) == []
    cmd, spec, root = host._build_idalib_command(session, "server.py", False, log_file="log")
    assert cmd[-1] == "ida_pro_mcp.idalib_worker"
    assert spec["existing"] is False
    assert "-o" + session.idb_path in spec["args"]
    assert root

    session_mgr = SimpleNamespace(
        get_session=lambda sid: SimpleNamespace(session_id=sid) if sid == "ABC12345" else None,
        find_session_by_path=lambda path: SimpleNamespace(idb_path=path),
        discover_sessions=list,
    )
    host.session_mgr = session_mgr
    assert host._resolve_session_from_idb_ref("ABC12345").session_id == "ABC12345"
    assert host._resolve_session_from_idb_ref("/tmp/file.i64").idb_path == "/tmp/file.i64"
    assert host._resolve_session_from_idb_ref(4) is None
