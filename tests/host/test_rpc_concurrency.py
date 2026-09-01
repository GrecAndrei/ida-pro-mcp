"""idat RPC concurrency: per-session lanes, parallelism across sessions.

IDA's bridge executes one SDK request at a time, so the host serializes
requests per session (rpc_lock) and parallelizes across sessions. A bounded
queue timeout turns a stuck in-flight request into a clear IDA_BUSY error
instead of an unbounded pile-up of waiting threads.
"""

from __future__ import annotations

import threading

import pytest

from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _RpcHarness(ServerRuntimeMixin):
    """Minimal mixin instance with fake runtimes on distinct ports."""

    def __init__(self):
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._runtime_lease_dir = "/tmp/nonexistent-lease-dir"
        self._runtime_owner_id = "test"


def _fake_proc(alive=True):
    class _Proc:
        # Above pid_max: killpg is a harmless no-op.
        pid = 2147483647

        def poll(self):
            return None if alive else 1

        def wait(self, timeout=None):
            return 1

    return _Proc()


def _register_runtime(harness, sid: str, port: int) -> threading.Lock:
    lock = threading.Lock()
    harness.session_runtimes[sid] = {
        "process": _fake_proc(),
        "port": port,
        "rpc_lock": lock,
        "auth_token": "tok",
    }
    return lock


def _local_echo_server(port: int = 0, concurrency_counter=None, hold_event=None):
    """A minimal TCP server that replies with a canned JSON payload.

    If concurrency_counter is given, it records concurrent entry so tests can
    assert serialization/parallelism. The server must be closed by the caller.
    ``port`` defaults to 0 (ephemeral) so parallel/leftover runs never collide
    on a fixed port; the caller reads the allocated port from the returned
    ``(srv, stop, port)`` triple.
    """
    import json
    import socket

    if concurrency_counter is None:
        concurrency_counter = {"active": 0, "max": 0, "lock": threading.Lock()}

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    port = srv.getsockname()[1]
    srv.listen(16)
    srv.settimeout(5.0)
    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return

            def _handle(c):
                with c:
                    with concurrency_counter["lock"]:
                        concurrency_counter["active"] += 1
                        concurrency_counter["max"] = max(
                            concurrency_counter["max"], concurrency_counter["active"]
                        )
                        ready_count = int(concurrency_counter.get("ready_count", 0) or 0)
                        ready_event = concurrency_counter.get("ready_event")
                        if ready_count and ready_event is not None and (
                            concurrency_counter["active"] >= ready_count
                        ):
                            ready_event.set()
                    try:
                        header = c.recv(4)
                        if len(header) != 4:
                            return
                        length = int.from_bytes(header, "big")
                        data = b""
                        while len(data) < length:
                            chunk = c.recv(length - len(data))
                            if not chunk:
                                return
                            data += chunk
                        if hold_event is not None:
                            hold_event.wait(timeout=5)
                        payload = json.dumps({"ok": True}).encode("utf-8")
                        c.sendall(len(payload).to_bytes(4, "big") + payload)
                    finally:
                        with concurrency_counter["lock"]:
                            concurrency_counter["active"] -= 1

            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return srv, stop, port


@pytest.fixture
def harness():
    return _RpcHarness()


def test_same_session_rpc_lane_serializes(harness):
    """Two concurrent RPCs to one session must never overlap on the bridge."""
    release = threading.Event()
    counter = {
        "active": 0,
        "max": 0,
        "lock": threading.Lock(),
        "ready_count": 1,
        "ready_event": threading.Event(),
    }
    srv, stop, port = _local_echo_server(
        0, concurrency_counter=counter, hold_event=release
    )
    _register_runtime(harness, "AAAA1111", port)
    try:
        results = {}

        def _call(tag):
            results[tag] = harness._send_rpc_raw(
                {"tool": "funcs", "args": {"action": "list"}},
                port,
                timeout=5,
                recv_timeout=10,
            )

        threads = [
            threading.Thread(target=_call, args=("a",)),
            threading.Thread(target=_call, args=("b",)),
        ]
        for t in threads:
            t.start()
        assert counter["ready_event"].wait(timeout=2)
        release.set()
        for t in threads:
            t.join(timeout=10)
        assert results["a"] == {"ok": True}
        assert results["b"] == {"ok": True}
        # Never more than one request in flight on the same lane.
        assert counter["max"] == 1
    finally:
        stop.set()
        srv.close()


def test_different_session_lanes_run_in_parallel(harness):
    """RPCs to different sessions must overlap on their separate lanes."""
    release = threading.Event()
    counter = {
        "active": 0,
        "max": 0,
        "lock": threading.Lock(),
        "ready_count": 2,
        "ready_event": threading.Event(),
    }
    srv_a, stop_a, port_a = _local_echo_server(
        0, concurrency_counter=counter, hold_event=release
    )
    srv_b, stop_b, port_b = _local_echo_server(
        0, concurrency_counter=counter, hold_event=release
    )
    _register_runtime(harness, "AAAA1111", port_a)
    _register_runtime(harness, "BBBB2222", port_b)
    try:
        results = {}

        def _call(tag, port):
            results[tag] = harness._send_rpc_raw(
                {"tool": "funcs", "args": {"action": "list"}},
                port,
                timeout=5,
                recv_timeout=10,
            )

        threads = [
            threading.Thread(target=_call, args=("a", port_a)),
            threading.Thread(target=_call, args=("b", port_b)),
        ]
        for t in threads:
            t.start()
        assert counter["ready_event"].wait(timeout=2)
        release.set()
        for t in threads:
            t.join(timeout=10)
        assert results["a"] == {"ok": True}
        assert results["b"] == {"ok": True}
        # Both sessions were serviced at the same time.
        assert counter["max"] == 2
    finally:
        stop_a.set()
        stop_b.set()
        srv_a.close()
        srv_b.close()


def test_queue_timeout_raises_when_lane_busy(harness):
    """A bounded queue wait must fail fast instead of queueing forever."""
    lock = _register_runtime(harness, "AAAA1111", 19024)
    lock.acquire()
    try:
        with pytest.raises(TimeoutError):
            harness._send_rpc_raw(
                {"tool": "funcs", "args": {"action": "list"}},
                19024,
                timeout=5,
                recv_timeout=10,
                queue_timeout=0.1,
            )
    finally:
        lock.release()


def test_retry_path_propagates_queue_timeout(harness):
    """The tool-call path (_send_rpc_with_retry) must surface TimeoutError."""
    lock = _register_runtime(harness, "AAAA1111", 19026)
    lock.acquire()
    try:
        with pytest.raises(TimeoutError):
            harness._send_rpc_with_retry(
                {"tool": "funcs", "args": {"action": "list"}},
                19026,
                timeout=5,
                recv_timeout=10,
                queue_timeout=0.05,
            )
    finally:
        lock.release()


def test_call_tool_maps_queue_timeout_to_ida_busy():
    """A lane that stays busy past the queue bound must report IDA_BUSY —
    not IDA_TIMEOUT (which means the socket recv deadline passed) and not
    IDA_CRASHED (the process is alive)."""
    from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
    from ida_pro_mcp.host.server.server_runtime import RpcQueueTimeout
    from ida_pro_mcp.services import MCPError, Session

    class _BusyDispatch(ServerDispatchMixin):
        def __init__(self):
            self.default_truncate_tokens = 4096
            self.session_runtimes = {
                "A1B2C3D4": {
                    "process": _fake_proc(),
                    "port": 9999,
                    "stdout_log": "",
                    "stderr_log": "",
                }
            }
            self._client_request_state().owned_session_ids.add("A1B2C3D4")

        def _resolve_session_from_idb_ref(self, idb_path):
            return Session(
                session_id="A1B2C3D4",
                idb_path="/tmp/a.i64",
                binary_path="/tmp/a.bin",
            )

        @staticmethod
        def _runtime_alive(runtime):
            return runtime is not None

        def _send_rpc_with_retry(self, *args, **kwargs):
            raise RpcQueueTimeout("busy")

        def _get_ida_diagnostics(self, *args, **kwargs):
            return ""

    res = _BusyDispatch().call_tool("code.decompile", "any.i64")
    assert res.get("error") is True
    assert res["code"] == MCPError.IDA_BUSY
    assert res.get("recoverable") is True
    assert "IDA_MCP_RPC_QUEUE_TIMEOUT" in str(res.get("hint") or "")


def test_health_reports_rpc_queue_depth(tmp_path, monkeypatch):
    """ida_session_health must report per-session RPC queue depth."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server.IDAMCPServer._detect_ida_dir",
        lambda self: "",
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server.IDAMCPServer._find_idat",
        lambda self: "",
    )
    from ida_pro_mcp.host.server.server import IDAMCPServer

    server = IDAMCPServer()
    try:
        server._session_inflight_calls["AAAA1111"] = 2
        server._session_inflight_calls["BBBB2222"] = 1
        server.session_runtimes["AAAA1111"] = {
            "process": _fake_proc(),
            "port": 19027,
        }
        server.session_runtimes["BBBB2222"] = {
            "process": _fake_proc(),
            "port": 19028,
        }

        health = server._handle_session_health({"verbose": True})
        assert health["sessions"]["rpc_queued_calls"] == 3
        by_sid = {r["session_id"]: r for r in health["sessions"]["runtimes"]}
        assert by_sid["AAAA1111"]["rpc_queued"] == 2
        assert by_sid["BBBB2222"]["rpc_queued"] == 1
    finally:
        server.shutdown()


def test_unbounded_queue_waits_for_lane(harness):
    """queue_timeout=None (legacy default) blocks until the lane frees."""
    srv, stop, port = _local_echo_server(0)
    acquire_seen = threading.Event()
    release = threading.Event()

    class _GateLock:
        def acquire(self, timeout=None):
            assert timeout is None
            acquire_seen.set()
            return release.wait(timeout=2)

        def release(self):
            release.set()

    _register_runtime(harness, "AAAA1111", port)
    harness.session_runtimes["AAAA1111"]["rpc_lock"] = _GateLock()
    result_box = {}

    def _call():
        result_box["result"] = harness._send_rpc_raw(
            {"tool": "funcs", "args": {"action": "list"}},
            port,
            timeout=5,
            recv_timeout=10,
        )

    caller = threading.Thread(target=_call)
    caller.start()
    try:
        assert acquire_seen.wait(timeout=2)
        assert caller.is_alive()
        release.set()
        caller.join(timeout=2)
        assert not caller.is_alive()
        assert result_box["result"] == {"ok": True}
    finally:
        release.set()
        caller.join(timeout=2)
        stop.set()
        srv.close()
