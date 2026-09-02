"""Cross-mode tests for the shared intelligence core.

These tests deliberately exercise discovery, lifecycle, HTTP, and classifier
paths together.  All external boundaries are replaced with small deterministic
doubles; no model, server, or IDA installation is required.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace

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


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"binary")
    path.chmod(0o755)
    return path


def test_state_loading_fingerprint_errors_and_windows_config(monkeypatch, tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path / "install"))
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path / "cache"))
    (tmp_path / "install").mkdir()
    (tmp_path / "install" / "embedder.json").write_text("not json", encoding="utf-8")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "embedder.json").write_text("[]", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    config_file = tmp_path / "config" / "ida-pro-mcp" / "embedder.json"
    config_file.parent.mkdir(parents=True)
    config_file.write_text(json.dumps({"model_path": str(model)}), encoding="utf-8")
    state = core._read_embedder_state()
    assert state["model_path"] == str(model)
    assert state["_source"] == str(config_file)

    config_file.write_text(json.dumps(["not-a-dict"]), encoding="utf-8")
    assert core._read_embedder_state() == {}
    assert core._select_state_path(["$MISSING", str(model)]) == str(model)

    monkeypatch.setattr(core.sys, "platform", "win32")
    appdata = tmp_path / "appdata" / "ida-pro-mcp" / "embedder.json"
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    appdata.parent.mkdir(parents=True)
    appdata.write_text(json.dumps({"server_bin": "server.exe"}), encoding="utf-8")
    assert core._read_embedder_state()["server_bin"] == "server.exe"

    broken = tmp_path / "broken"
    broken.write_bytes(b"x")
    monkeypatch.setattr(core, "hash_file", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("busy")))
    assert core.model_fingerprint(str(broken), deep_hash=True)["sha256_head_16mb"] == ""
    assert core.model_fingerprint(str(broken), deep_hash=True)["sha256_full"] == ""


def test_server_and_model_discovery_cover_platform_roots_path_and_quants(monkeypatch, tmp_path):
    project = tmp_path / "project"
    install = tmp_path / "install"
    home = tmp_path / "home"
    project.mkdir()
    install.mkdir()
    monkeypatch.setattr(core, "_PROJECT_ROOT", str(project))
    monkeypatch.setattr(core, "_install_root", lambda: str(install))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN", raising=False)
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "shutil", SimpleNamespace(which=lambda _name: None))

    monkeypatch.setattr(core.sys, "platform", "darwin")
    mac_server = _make_executable(home / ".local" / "bin" / "llama-server")
    assert core._find_llama_server() == str(mac_server)

    monkeypatch.setattr(core.sys, "platform", "win32")
    win_server = _make_executable(tmp_path / "programs" / "llama.cpp" / "bin" / "llama-server.exe")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "programs"))
    assert core._find_llama_server() == str(win_server)

    win_server.unlink()
    path_server = _make_executable(tmp_path / "path" / "llama-server.cmd")
    monkeypatch.setattr(core.shutil, "which", lambda name: str(path_server) if name == "llama-server.exe" else None)
    assert core._find_llama_server() == str(path_server)

    path_server.unlink()
    mac_server.unlink()
    project_server = _make_executable(project / "bin" / "llama-server")
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core.shutil, "which", lambda _name: None)
    assert core._find_llama_server() == str(project_server)

    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "qwen3-embedding-0.6b")
    q4 = project / "qwen3-embedding-0.6b-Q4_K_M.gguf"
    q8 = install / "models" / "qwen3-embedding-0.6b-Q8_0.gguf"
    q4.write_bytes(b"q4")
    q8.parent.mkdir()
    q8.write_bytes(b"q8")
    monkeypatch.setenv("IDA_MCP_Q4", "1")
    assert core._find_model() == str(q4)
    monkeypatch.setenv("IDA_MCP_Q4", "0")
    assert core._find_model() == str(q8)

    q4.unlink()
    q8.unlink()
    legacy = install / "bge-code-v1-Q4_K_M.gguf"
    legacy.write_bytes(b"legacy")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    assert core._find_model() == str(legacy)


def test_model_manual_env_and_hf_discovery_cache_invalidation(monkeypatch, tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(core, "_PROJECT_ROOT", str(tmp_path / "project"))
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path / "install"))
    monkeypatch.setattr(core, "_read_embedder_state", lambda: {"model_path": str(model), "profile": "bge-code-v1"})
    monkeypatch.setattr(core, "_select_state_path", lambda value: value if value and os.path.isfile(value) else "")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "qwen3-embedding-0.6b")
    assert core._find_model() == ""
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", f"{tmp_path / 'missing'};{model}")
    assert core._find_model() == str(model)

    monkeypatch.delenv("IDA_MCP_EMBED_MODEL")
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    hf = tmp_path / "home" / ".cache" / "huggingface" / "hub" / "models--x" / "snapshots" / "rev" / "Qwen3-Embedding-0.6B.gguf"
    hf.parent.mkdir(parents=True)
    hf.write_bytes(b"hf")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    assert core._find_model() == str(hf)

    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", "")
    assert core._prefer_q4() is True
    monkeypatch.setenv("IDA_MCP_Q4", "off")
    assert core._prefer_q4() is False
    monkeypatch.setenv("IDA_MCP_EMBED_THREADS", "bad")
    assert core._safe_int_env("IDA_MCP_EMBED_THREADS", "3") == 3
    monkeypatch.setenv("IDA_MCP_FLOAT", "inf")
    assert core._safe_float_env("IDA_MCP_FLOAT", "2.5") == 2.5


def test_process_and_lock_helpers_cover_fallbacks_and_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(core.os, "sched_getaffinity", lambda _pid: set())
    monkeypatch.setattr(core.os, "cpu_count", lambda: 3)
    assert core._available_cpu_count() == 3
    monkeypatch.setattr(core.os, "sched_getaffinity", lambda _pid: (_ for _ in ()).throw(OSError("no affinity")))
    assert core._available_cpu_count() == 3
    monkeypatch.setattr(core.sys, "platform", "win32")
    assert core._process_command(1) == ""
    assert core._process_start_token(1) == ""
    assert core._process_rss_bytes(1) == 0

    lock_path = str(tmp_path / "locks" / "request.lock")
    monkeypatch.setattr(core.sys, "platform", "linux")
    with core._InterProcessLock(lock_path, 1):
        assert Path(lock_path).is_file()

    lock = core._InterProcessLock(lock_path, 0)
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(core, "time", SimpleNamespace(monotonic=lambda: 100.0, sleep=lambda _x: None))
    # A deterministic lock contention path without a second process.
    import fcntl

    original_flock = fcntl.flock
    monkeypatch.setattr(fcntl, "flock", lambda *_args: (_ for _ in ()).throw(BlockingIOError()))
    with pytest.raises(core.EmbeddingQueueTimeout):
        lock.__enter__()
    monkeypatch.setattr(fcntl, "flock", original_flock)


def test_embedder_status_request_shapes_and_activation_grace(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=False)
    obj._start_server = lambda: False
    assert obj.status(probe=True)["ready"] is False
    obj._port = 18101
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(b'{"status":"ok"}'))
    assert obj.status(probe=True)["ready"] is True
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")))
    status = obj.status(probe=True)
    assert status["ready"] is False and status["probe_error"] == "offline"

    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._server_has_active_slots = lambda: False
    obj._cancel_idle_shutdown = lambda: None
    obj._schedule_idle_shutdown = lambda *_args, **_kwargs: None
    obj._record_success_and_maybe_recycle = lambda: None
    for payload in ("bad", {"data": [{"embedding": [1, 1]}], "extra": True}):
        monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, payload=payload, **_kwargs: _Response(payload))
        if payload == "bad":
            assert obj._request_embeddings(["x"], purpose="query", timeout=1) is None
        else:
            assert obj._request_embeddings(["x"], purpose="query", timeout=1) == [[pytest.approx(1 / 2**0.5), pytest.approx(1 / 2**0.5)]]

    obj._server_started_at = 10.0
    monkeypatch.setattr(core.time, "monotonic", lambda: 10.1)
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("cold")))
    retired = []
    obj._retire_lease_process = lambda *_args: retired.append(True)
    monkeypatch.setattr(core, "EMBED_ACTIVATION_GRACE_TIMEOUT", 60.0)
    assert obj._request_embeddings(["x"], purpose="query", timeout=0.01) is None
    assert not retired and obj._ready is True


def test_embedder_cache_batch_growth_and_stop_cleanup(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    monkeypatch.setattr(core, "EMBED_CACHE_MAX", 1)
    calls = []
    obj._request_embeddings = lambda texts, **_kwargs: calls.append(texts) or [[1.0, 0.0]]
    assert obj._llama_embed("a") == [1.0, 0.0]
    assert obj._llama_embed("a") == [1.0, 0.0]
    assert len(calls) == 1
    assert obj._llama_embed("b") == [1.0, 0.0]
    assert len(calls) == 2

    obj._llama_embed_batch = lambda texts, **_kwargs: [[1.0, 0.0] for _ in texts]
    assert all(result.ok for result in obj.embed_batch(["one"]))
    assert obj._batch_size == 2
    obj._gemini = SimpleNamespace(stop=lambda: setattr(obj, "gemini_stopped", True))
    obj.stop()
    assert obj.gemini_stopped is True


def test_classifier_cache_failure_explanation_and_anchor_report(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr("ida_pro_mcp.host.config.CACHE_DIR", str(tmp_path))

    class Embedder:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")
        embedding_format = "format"

        def embed(self, text):
            if text == "fail":
                return SimpleNamespace(ok=False, vector=None, backend="offline")
            return core._EmbedResult([1.0, 0.0], "offline", True)

        def embed_query(self, text):
            return self.embed(text)

    classifier = core.BehaviorClassifier(Embedder())
    classifier._save_anchor("network_raw", [1.0, 0.0])
    cache_path = Path(classifier._cache_path())
    assert cache_path.is_file()
    cache_path.write_text(
        json.dumps({"version": 1, "anchors": {"network_raw": ["bad"], "file_operations": [1, 2]}}),
        encoding="utf-8",
    )
    other = core.BehaviorClassifier(Embedder())
    assert "network_raw" not in other._anchor_embs
    assert other._anchor_explain("send(sock, req); close_socket(sock)", "send socket")
    assert other.classify("fail") == []

    other._anchor_embs = {"network_raw": [1.0, 0.0]}
    rows = other.classify_vec([1.0, 0.0], threshold=None, top_k=1, block=False)
    assert rows and rows[0]["behavior"] == "network_raw"
    monkeypatch.setitem(sys.modules, "idautils", ModuleType("idautils"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ModuleType("ida_hexrays"))
    sys.modules["idautils"].Functions = lambda: [1, 2, 3]
    sys.modules["ida_hexrays"].decompile = lambda ea: "send(sock, req)" if ea == 1 else None
    other._get_anchor = lambda _label: [1.0, 0.0]
    report = other.anchor_coverage_report(min_similarity=0.5, max_funcs=2)
    assert report["function_count"] == 1
    assert report["anchors"] and report["anchors"][0]["top_example"] == "0x1"
