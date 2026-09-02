"""Exercise the local embedder lifecycle through its HTTP/process boundaries."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.intelligence import core


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        if isinstance(self.payload, bytes):
            return self.payload
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Process:
    pid = 321

    def __init__(self, *, exited=False):
        self.returncode = 1 if exited else None
        self.terminated = False
        self.killed = False
        self.wait_calls = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if timeout == 5 and not self.terminated:
            raise TimeoutError("still running")
        return self.returncode


def _embedder(tmp_path, *, ready=False, use_llama=False):
    obj = object.__new__(core.BgeCodeEmbedder)
    obj._gemini = None
    obj._model_path = str(tmp_path / "model.gguf")
    obj._server_bin = str(tmp_path / "llama-server")
    obj._profile = core.BGE_CODE_V1
    obj._dimension = 2
    obj._use_llama = use_llama
    obj._ready = ready
    obj._owns_proc = False
    obj._proc = None
    obj._port = 18100
    obj._batch_size = 1
    obj._max_batch_size = 4
    obj._batch_lock = threading.Lock()
    obj._consecutive_rpc_failures = 0
    obj._max_rpc_failures = 2
    obj._last_batch_timeout = False
    obj._last_recycle_reason = ""
    obj._server_started_at = 0.0
    obj._identity_cache = None
    obj._start_lock = threading.Lock()
    obj._stop_registered = True
    obj._idle_lock = threading.Lock()
    obj._idle_timer = None
    obj._idle_generation = 0
    obj._embedding_cache = {}
    obj._embedding_cache_lock = threading.Lock()
    obj._embedding_inflight = {}
    obj._embedding_cache_generation = 0
    return obj


def test_start_server_attach_spawn_gpu_and_failure_modes(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, use_llama=False)
    model = tmp_path / "model.gguf"
    server = tmp_path / "llama-server"
    model.write_bytes(b"model")
    server.write_bytes(b"server")
    server.chmod(0o755)
    obj._read_lease = dict
    monkeypatch.setattr(core, "_find_llama_server", lambda: str(server))
    monkeypatch.setattr(core, "_find_model", lambda: str(model))
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(obj, "_pick_port", lambda: 19090)
    monkeypatch.setattr(core, "_process_start_token", lambda _pid: "token")
    monkeypatch.setattr(core, "_process_rss_bytes", lambda _pid: 42)
    published = []

    def write_lease(value):
        published.append(value)

    monkeypatch.setattr(obj, "_write_lease", write_lease)
    proc = _Process()
    commands = []

    def start_process(command, **_kwargs):
        commands.append(command)
        return proc

    monkeypatch.setattr(core.subprocess, "Popen", start_process)
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(b'{"status":"ok"}'))
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(core.time, "time", lambda: 1.0)
    assert obj._start_server_locked() is True
    assert obj._use_llama and obj._ready and obj._owns_proc
    assert obj._port == 19090
    assert commands and commands[0][-2:] == ["--device", "none"]

    attached = _embedder(tmp_path, ready=False, use_llama=False)
    attached._read_lease = lambda: {"port": 19100}
    attached._lease_matches = lambda _lease: True
    assert attached._start_server_locked() is True
    assert attached._port == 19100 and attached._owns_proc is False

    failed = _embedder(tmp_path, use_llama=True)
    monkeypatch.setattr(core.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no binary")))
    assert failed._start_server_locked() is False
    assert failed._ready is False

    exited = _embedder(tmp_path, use_llama=True)
    exited_proc = _Process(exited=True)
    monkeypatch.setattr(core.subprocess, "Popen", lambda *_args, **_kwargs: exited_proc)
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("not ready")))
    monkeypatch.setattr(core.time, "time", iter([0.0, 61.0]).__next__)
    assert exited._start_server_locked() is False


def test_start_lock_and_stop_paths_are_fail_closed(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    assert obj._start_server_locked() is True

    class BusyLock:
        def __enter__(self):
            raise core.EmbeddingQueueTimeout("busy")

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(core, "_InterProcessLock", lambda *_args: BusyLock())
    assert obj._start_server() is False

    proc = _Process()
    obj._proc = proc
    obj._owns_proc = True
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(tmp_path / "lease.json"))
    (tmp_path / "lease.json").write_text(json.dumps({"pid": 321, "owner_pid": 999}), encoding="utf-8")
    obj.stop()
    assert proc.terminated and obj._proc is None and not obj._owns_proc

    hanging = _Process()
    obj._proc = hanging
    obj._owns_proc = True
    monkeypatch.setattr(hanging, "terminate", lambda: None)
    obj.stop()
    assert hanging.killed

    obj._proc = None
    obj._owns_proc = False
    (tmp_path / "lease.json").write_text(
        json.dumps({"pid": 321, "owner_pid": __import__("os").getpid()}),
        encoding="utf-8",
    )
    kills = []

    def fake_kill(pid, signal):
        kills.append((pid, signal))
        if signal == 0:
            raise OSError("gone")

    monkeypatch.setattr(core.os, "kill", fake_kill)
    obj.stop()
    assert (321, 15) in kills


@pytest.mark.parametrize(
    "payload",
    [
        {"data": []},
        [{"embedding": [1]}],
        [{"index": 0, "embedding": [1, 2]}, {"index": 0, "embedding": [3, 4]}],
        [{"embedding": [float("nan"), float("inf")]}],
        [{"embedding": [1, 2, 3]}],
    ],
)
def test_request_embeddings_validation_and_failure_modes(monkeypatch, tmp_path, payload):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._server_has_active_slots = lambda: False
    obj._cancel_idle_shutdown = lambda: None
    obj._schedule_idle_shutdown = lambda *_args, **_kwargs: None
    obj._record_success_and_maybe_recycle = lambda: None
    obj._retire_lease_process = lambda *_args: None
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(payload))
    assert obj._request_embeddings(["query"], purpose="query", timeout=0.1) is None

    obj._ready = False
    assert obj._request_embeddings(["query"], purpose="query", timeout=0.1) is None


def test_request_embeddings_timeout_active_slot_and_batch_recycling(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._server_has_active_slots = lambda: False
    obj._cancel_idle_shutdown = lambda: None
    obj._schedule_idle_shutdown = lambda *_args, **_kwargs: None
    obj._retire_lease_process = lambda *_args: setattr(obj, "retired", True)
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("slow")))
    assert obj._request_embeddings(["query"], purpose="query", timeout=0.01) is None
    assert obj._last_batch_timeout and obj.retired

    active = _embedder(tmp_path, ready=True, use_llama=True)
    active._server_has_active_slots = lambda: True
    active._retire_lease_process = lambda *_args: setattr(active, "retired", True)
    assert active._request_embeddings(["query"], purpose="query", timeout=0.1) is None
    assert active.retired

    batch = _embedder(tmp_path, ready=True, use_llama=True)
    batch._llama_embed_batch = lambda _texts, **_kwargs: None
    batch._last_batch_timeout = True
    rows = batch.embed_batch(["one", "two"])
    assert len(rows) == 2 and all(not row.ok for row in rows)
    batch._ready = False
    batch._last_recycle_reason = "recycled"
    rows = batch.embed_batch(["one", "two", "three"])
    assert len(rows) == 3 and all(not row.ok for row in rows)


def test_success_recycle_and_cache_state_modes(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease = {"schema": 2, "pid": 7, "request_count": 0, "rss": 10}
    obj._read_lease = lambda: dict(lease)
    obj._lease_matches = lambda _value: True
    monkeypatch.setattr(core, "_process_rss_bytes", lambda _pid: 20)
    saved = []

    def save_lease(value):
        saved.append(value)

    obj._write_lease = save_lease
    monkeypatch.setattr(core, "EMBED_MAX_REQUESTS", 0)
    monkeypatch.setattr(core, "EMBED_MAX_RSS_GROWTH_MB", 1)
    obj._record_success_and_maybe_recycle()
    assert saved[0]["request_count"] == 1

    obj._retire_lease_process = lambda _lease, reason: setattr(obj, "reason", reason)
    lease["rss"] = 1
    monkeypatch.setattr(core, "_process_rss_bytes", lambda _pid: 3 * 1024 * 1024)
    obj._record_success_and_maybe_recycle()
    assert "RSS grew" in obj.reason

    monkeypatch.setattr(core, "EMBED_MAX_REQUESTS", 1)
    obj._record_success_and_maybe_recycle()
    assert "request limit" in obj.reason

    bare = object.__new__(core.BgeCodeEmbedder)
    bare._embedding_cache = None
    bare._embedding_cache_lock = None
    bare._embedding_inflight = None
    bare._embedding_cache_generation = None
    cache, lock, inflight = bare._embedding_cache_state()
    assert isinstance(cache, dict) and lock.acquire and isinstance(inflight, dict)
    bare._embedding_cache["old"] = [1]
    bare._invalidate_embedding_cache()
    assert bare._embedding_cache == {}
