"""Cross-platform and backend-boundary coverage for the intelligence core."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.intelligence import core


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
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
    obj._batch_size = 2
    obj._max_batch_size = 4
    obj._batch_lock = __import__("threading").Lock()
    obj._consecutive_rpc_failures = 0
    obj._max_rpc_failures = 2
    obj._last_batch_timeout = False
    obj._last_recycle_reason = ""
    obj._server_started_at = 0.0
    obj._identity_cache = None
    obj._idle_lock = __import__("threading").Lock()
    obj._idle_timer = None
    obj._idle_generation = 0
    return obj


def test_filesystem_discovery_and_platform_branches(monkeypatch, tmp_path):
    model = tmp_path / "model.gguf"
    server = tmp_path / "llama-server.exe"
    model.write_bytes(b"abcdef")
    server.write_bytes(b"binary")
    server.chmod(0o755)

    assert core.hash_file(str(model), max_bytes=2) == core.hash_file(str(model)[:0] or str(model), max_bytes=2)
    assert core._select_state_path(123) == ""
    assert core._select_state_path([None, str(model)]) == str(model)
    assert core._select_state_path("$MISSING_MODEL") == ""
    with pytest.raises(ValueError):
        core.write_embedder_state(tmp_path / "bad", profile="unknown-profile")
    with pytest.raises(ValueError):
        core.write_embedder_state(tmp_path / "bad", backend="wat")

    monkeypatch.setattr(core.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    assert core._install_root() == str(tmp_path.resolve())
    assert core._llama_server_binary_names()[0].endswith(".exe")
    assert core._is_executable(str(server)) is True
    assert core._is_executable(str(tmp_path / "model.gguf")) is False
    monkeypatch.setattr(core.os, "pathsep", ";")
    assert core._split_env_paths("C:\\one;D:\\two") == ["C:\\one", "D:\\two"]
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(tmp_path))
    assert core._find_llama_server() == str(server)

    monkeypatch.setattr(core, "_is_executable", lambda path: path == str(server))
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout="Vulkan0: GPU\n"))
    assert core._detect_gpu_device(str(server)) == "Vulkan0"
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("probe")))
    assert core._detect_gpu_device(str(server)) == ""
    monkeypatch.setattr(core, "_is_executable", lambda _path: False)
    assert core._detect_gpu_device(str(server)) == ""


def test_model_discovery_cache_profiles_and_process_helpers(monkeypatch, tmp_path):
    model = tmp_path / "qwen3-embedding-0.6b-q8_0.gguf"
    legacy = tmp_path / "bge-code-v1-q4_k_m.gguf"
    model.write_bytes(b"model")
    legacy.write_bytes(b"legacy")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(model))
    assert core._find_model() == str(model)
    monkeypatch.delenv("IDA_MCP_EMBED_MODEL")
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "custom")
    monkeypatch.setattr(core, "glob", SimpleNamespace(glob=lambda pattern: [str(legacy)] if "bge" in pattern else []))
    assert core._find_model() == str(legacy)
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", ("same", str(model)))
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "qwen3-embedding-0.6b")
    assert core._find_model() == str(model) or core._find_model() == str(legacy)

    monkeypatch.setattr(core.sys, "platform", "linux")
    assert core._process_command(os.getpid())
    assert core._process_start_token(os.getpid())
    assert core._process_rss_bytes(os.getpid()) >= 0
    assert core._llama_context_layout(128, 99, max_total_ctx=1024) == (512, 2, 1024)
    assert core._identifier_terms("HTTPServerWorker") == ["HTTP", "Server", "Worker"]
    signature = core._extract_signature("int doWork(int value) { memcpy(dst, src, value); return 0; }")
    assert "Work" in signature


def test_embedder_status_leases_and_idle_modes(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=True)
    obj._start_server = lambda: True
    status = obj.status(probe=True)
    assert status["ready"] is True
    assert status["profile"] == core.BGE_CODE_V1.key
    assert obj._pick_port() > 0
    monkeypatch.setenv("IDA_MCP_EMBED_PORT", "19001")
    assert obj._pick_port() == 19001
    identity = obj._lease_identity()
    assert identity["profile"] == core.BGE_CODE_V1.key
    assert obj._lease_identity() == identity

    monkeypatch.setattr(core, "_pid_alive", lambda pid: pid == 7)
    monkeypatch.setattr(core, "_process_start_token", lambda _pid: "token")
    obj._server_json = lambda _port, endpoint: {"status": "ok"} if endpoint == "health" else {"model_path": obj._model_path}
    lease = {
        "schema": 2,
        "pid": 7,
        "owner_pid": 7,
        "port": 1234,
        "process_start_token": "token",
        "owner_start_token": "token",
        **identity,
    }
    assert obj._lease_matches(lease) is True
    lease["recycle_requested"] = True
    assert obj._lease_matches(lease) is False
    monkeypatch.setattr(
        core,
        "_process_command",
        lambda _pid: f"{obj._server_bin} --embedding --model {obj._model_path}",
    )
    assert obj._pid_is_expected_server(7, {"schema": 2}) is True
    assert obj._server_has_active_slots() is False
    obj._port = None
    assert obj._server_has_active_slots() is False
    monkeypatch.setattr(core, "EMBED_MAX_RSS_MB", 1)
    assert obj._rss_limit_bytes() == 1024 * 1024
    monkeypatch.setattr(core, "EMBED_MAX_RSS_MB", 0)
    assert obj._rss_limit_bytes() >= 3 * 1024**3

    class _Timer:
        def __init__(self):
            self.cancelled = False
            self.started = False

        def cancel(self):
            self.cancelled = True

        def start(self):
            self.started = True

    timer = _Timer()
    monkeypatch.setattr(core.threading, "Timer", lambda *args, **kwargs: timer)
    obj._schedule_idle_shutdown(timeout=1)
    assert timer.started is True
    obj._cancel_idle_shutdown()
    assert timer.cancelled is True
    obj._shutdown_if_idle(999)
    obj._idle_generation = 2
    obj._server_has_active_slots = lambda: False
    obj.stop = lambda: setattr(obj, "stopped", True)
    obj._shutdown_if_idle(2)
    assert obj.stopped is True


def test_embedding_http_shapes_cache_and_batch_adaptation(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    monkeypatch.setattr(obj, "_server_has_active_slots", lambda: False)
    monkeypatch.setattr(obj, "_cancel_idle_shutdown", lambda: None)
    monkeypatch.setattr(obj, "_schedule_idle_shutdown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(obj, "_record_success_and_maybe_recycle", lambda: None)
    responses = iter([
        {"data": [{"index": 1, "embedding": [0, 2]}, {"index": 0, "embedding": [2, 0]}]},
        [{"embedding": [1, 1]}, {"embedding": [[1, 0]]}],
    ])
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(next(responses)))
    rows = obj._request_embeddings(["a", "b"], purpose="document", timeout=1)
    assert rows == [[1.0, 0.0], [0.0, 1.0]]
    rows = obj._request_embeddings(["a", "b"], purpose="document", timeout=1)
    assert rows[0] == pytest.approx([0.70710678, 0.70710678])
    assert rows[1] == [1.0, 0.0]
    assert obj._request_embeddings([], purpose="query", timeout=1) == []

    obj._request_embeddings = lambda texts, **_kwargs: [[1.0, 0.0] for _ in texts]
    obj._model_path = str(tmp_path / "model.gguf")
    assert obj._llama_embed("same") == obj._llama_embed("same")
    assert obj._llama_embed_batch(["a", "b"]) == [[1.0, 0.0], [1.0, 0.0]]
    assert obj.embed("x").ok is True
    obj._use_llama = False
    assert obj.embed("x").ok is False
    assert obj.embed_batch(["a", "b"])[0].ok is False
    assert obj.embed_batch([]) == []
    assert obj.embed_vector("x") is None
    assert obj.embedding_format.startswith("profile-v1:")
    assert obj.decomp_document_chars > 0


def test_embedding_failure_and_classifier_generation_modes(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._server_has_active_slots = lambda: False
    obj._cancel_idle_shutdown = lambda: None
    obj._schedule_idle_shutdown = lambda *_args, **_kwargs: None
    obj._retire_lease_process = lambda *_args: None
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("slow")))
    assert obj._request_embeddings(["x"], purpose="query", timeout=0.01) is None
    assert obj._last_batch_timeout is True
    obj._last_batch_timeout = True
    obj._llama_embed_batch = lambda _texts, **_kwargs: None
    obj._batch_size = 4
    failures = obj.embed_batch(["a", "b"])
    assert len(failures) == 2 and all(not row.ok for row in failures)

    class Embedder:
        backend = "fake"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")

        def embed(self, _text):
            return [1.0, 0.0]

    classifier = core.BehaviorClassifier(Embedder())
    classifier._save_anchor = lambda *_args: None
    assert classifier._get_anchor("network_raw") == [1.0, 0.0]
    assert classifier._get_anchor("not-an-anchor") is None
    classifier.clear_cache()
    classifier._anchor_generation += 1
    assert classifier.classify_vec([1.0, 0.0], threshold=0.0, top_k=1, block=False) == []
    assert classifier.classify(" ") == []
    monkeypatch.setattr(Embedder, "embed", lambda self, _text: SimpleNamespace(ok=False, vector=None, backend="fake"))
    assert classifier.classify("memcpy(buffer, input)") == []
