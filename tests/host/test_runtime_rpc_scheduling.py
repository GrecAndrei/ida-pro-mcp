"""Behavior tests for per-runtime RPC scheduling."""

from __future__ import annotations

import json
import threading

from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin


class _RuntimeHarness(ServerRuntimeMixin):
    def __init__(self):
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}


class _FakeSocket:
    def __init__(self, tracker):
        self.tracker = tracker
        self.port = None
        self.response = b""
        self.offset = 0

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.port = address[1]
        self.tracker.on_connect(self.port)

    def sendall(self, data):
        payload = json.dumps({"ok": True, "port": self.port}).encode()
        self.response = len(payload).to_bytes(4, "big") + payload
        self.tracker.wait_until_released(self.port)

    def recv(self, size):
        chunk = self.response[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self):
        if self.port is not None:
            self.tracker.on_close(self.port)


class _Tracker:
    def __init__(self, expected_parallel=1):
        self.expected_parallel = expected_parallel
        self.lock = threading.Lock()
        self.connected = threading.Event()
        self.release = threading.Event()
        self.active = 0
        self.max_active = 0

    def on_connect(self, port):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            if self.active >= self.expected_parallel:
                self.connected.set()

    def wait_until_released(self, port):
        assert self.release.wait(timeout=5)

    def on_close(self, port):
        with self.lock:
            self.active -= 1


def _run_calls(server, calls):
    results = []

    def invoke(port):
        results.append(server._send_rpc_raw({"type": "ping"}, port))

    threads = [threading.Thread(target=invoke, args=(port,)) for port in calls]
    for thread in threads:
        thread.start()
    return threads, results


def test_calls_to_one_ida_runtime_are_serialized(monkeypatch):
    server = _RuntimeHarness()
    server.session_runtimes = {"A": {"port": 41001, "auth_token": "a"}}
    tracker = _Tracker(expected_parallel=1)
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: _FakeSocket(tracker))

    threads, results = _run_calls(server, [41001, 41001])
    assert tracker.connected.wait(timeout=5)
    # The second call is queued before opening a competing socket.
    assert tracker.max_active == 1
    tracker.release.set()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(results) == 2
    assert tracker.max_active == 1


def test_calls_to_different_ida_runtimes_run_in_parallel(monkeypatch):
    server = _RuntimeHarness()
    server.session_runtimes = {
        "A": {"port": 41001, "auth_token": "a"},
        "B": {"port": 41002, "auth_token": "b"},
    }
    tracker = _Tracker(expected_parallel=2)
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: _FakeSocket(tracker))

    threads, results = _run_calls(server, [41001, 41002])
    assert tracker.connected.wait(timeout=5)
    assert tracker.max_active == 2
    tracker.release.set()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(results) == 2
