"""Offline coverage for local, cloud, and shared-process intelligence modes."""

from __future__ import annotations

import json
import os
import types

import pytest

from ida_pro_mcp.host.intelligence import core
from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder
from tests.host.intelligence.test_core_runtime_modes import _embedder, _Response


def test_discovery_state_and_fingerprints_are_portable(monkeypatch, tmp_path):
    model = tmp_path / "model-q4_k_m.gguf"
    server = tmp_path / "llama-server"
    model.write_bytes(b"model")
    server.write_bytes(b"#!/bin/sh\n")
    server.chmod(0o755)
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path / "cache"))
    assert len(core.hash_file(str(model))) == 64
    assert core.model_fingerprint(str(model), deep_hash=True)["sha256_full"]
    assert core.model_fingerprint(str(tmp_path / "missing"))["exists"] is False
    assert core._split_env_paths("a;b;c") == ["a", "b", "c"]
    assert core._split_env_paths("") == []
    assert core._is_executable(str(server))
    assert not core._is_executable(str(tmp_path / "missing"))

    state_path = core.write_embedder_state(
        tmp_path,
        model_path=str(model),
        server_bin=str(server),
        profile="bge-code-v1",
        backend="cloud",
        gemini_model="gemini-embedding-001",
        gemini_dimension=99999,
        gemini_vertex_project="project",
        gemini_vertex_location="europe-west4",
        disabled=False,
        rerank={"model_path": str(model), "enabled": True, "empty": ""},
    )
    with open(state_path, encoding="utf-8") as state_file:
        payload = json.load(state_file)
    assert payload["backend"] == "gemini"
    assert payload["gemini_dimension"] == core.GEMINI_MAX_DIM
    assert payload["rerank"] == {"model_path": str(model), "enabled": True}
    monkeypatch.setattr(core, "_read_embedder_state", lambda: payload)
    assert core._select_state_path([str(tmp_path / "missing"), str(model)]) == str(model)
    assert core._select_state_path(False) == ""
    assert core._model_quant_rank("x-q4_k_m.gguf") < core._model_quant_rank("x-q8_0.gguf")
    monkeypatch.setenv("IDA_MCP_Q4", "0")
    assert core._model_quant_rank("x-q8_0.gguf") < core._model_quant_rank("x-q4_k_m.gguf")
    assert core._find_llama_server() == str(server)
    assert core._find_model() == str(model)


def test_process_and_lease_helpers_cover_valid_invalid_and_mismatch_states(monkeypatch, tmp_path):
    assert core._safe_int_env("NOT_SET", "7") == 7
    monkeypatch.setenv("NOT_SET", "bad")
    assert core._safe_int_env("NOT_SET", "7") == 7
    monkeypatch.setenv("NOT_SET", "nan")
    assert core._safe_float_env("NOT_SET", "1.5") == 1.5
    assert core._pid_alive(-1) is False
    assert core._process_command(-1) == ""
    assert core._process_start_token(-1) == ""
    assert core._process_rss_bytes(-1) == 0

    lease_path = tmp_path / "lease.json"
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_path))
    BgeCodeEmbedder._write_lease({"schema": 2, "port": 123})
    assert BgeCodeEmbedder._read_lease()["port"] == 123
    lease_path.write_text("not-json", encoding="utf-8")
    assert BgeCodeEmbedder._read_lease() == {}

    obj = object.__new__(BgeCodeEmbedder)
    obj._model_path = ""
    obj._server_bin = ""
    obj._gemini = None
    obj._profile = core.BGE_CODE_V1
    obj._dimension = 768
    obj._use_llama = False
    obj._ready = False
    obj._owns_proc = False
    obj._proc = None
    obj._port = None
    obj._consecutive_rpc_failures = 0
    obj._last_recycle_reason = ""
    obj._batch_size = 1
    obj._max_batch_size = 1
    assert obj._lease_matches({}) is False
    assert obj._pid_is_expected_server(-1) is False
    assert obj._extract_embedding({"embedding": [[1, 2]]}) == [1.0, 2.0]
    assert obj._extract_embedding({"embedding": []}) is None
    assert obj._extract_embedding(None) is None
    obj._invalidate_embedding_cache()
    assert obj.embed_documents([]) == []
    assert obj.embed_batch(["a"])[0].ok is False


def test_behavior_classifier_cold_warm_cloud_and_budget_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr("ida_pro_mcp.host.config.CACHE_DIR", str(tmp_path))

    class Embedder:
        backend = "offline"
        dim = 2
        embedding_format = "test-format"
        _model_path = str(tmp_path / "model.gguf")

        def __init__(self):
            self.calls = []

        def embed(self, text):
            self.calls.append(text)
            return core._EmbedResult([1.0, 0.0], "offline", True)

        def embed_query(self, text):
            return self.embed(text)

    classifier = BehaviorClassifier(Embedder())
    assert classifier.classify("   ") == []
    assert classifier.classify_vec([1.0, 0.0], block=False) == []
    rows = classifier.classify_vec([1.0, 0.0], threshold=0.0, top_k=2, block=True, embed_budget_sec=10)
    assert len(rows) == 2
    classifier.clear_cache()
    assert classifier._anchor_embs == {}
    classifier.refresh_anchors(["network_raw"])
    assert "network_raw" in classifier._anchor_embs

    cached = {"version": 1, "anchors": {"network_raw": [1, 0], "bad": [1, 2, 3]}}
    (tmp_path / f"anchor_cache_{classifier._cache_key()}.json").write_text(json.dumps(cached), encoding="utf-8")
    other = BehaviorClassifier(Embedder())
    assert other._anchor_embs.get("network_raw") == [1.0, 0.0]
    report = other.anchor_coverage_report()
    assert report["function_count"] == 0

    monkeypatch.setattr(core.BgeCodeEmbedder, "cosine", staticmethod(lambda a, b: 0.9))
    assert other.classify("recv(socket, buf)", threshold=0.2, top_k=1, block=False)[0]["backend"] == "offline"


def test_discovery_probe_and_platform_executable_modes(monkeypatch, tmp_path):
    server = tmp_path / "llama-server"
    server.write_bytes(b"server")
    server.chmod(0o755)
    assert core._detect_gpu_device("") == ""

    real_is_executable = core._is_executable
    monkeypatch.setattr(core, "_is_executable", lambda path: path == str(server))
    monkeypatch.setattr(
        core.subprocess,
        "run",
        lambda *_args, **_kwargs: types.SimpleNamespace(
            stdout="CPU: host\nVulkan0: integrated\nVulkan1: discrete\n"
        ),
    )
    assert core._detect_gpu_device(str(server)) == "Vulkan0"
    monkeypatch.setattr(core.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("probe")))
    assert core._detect_gpu_device(str(server)) == ""
    monkeypatch.setattr(core.subprocess, "run", lambda *_args, **_kwargs: types.SimpleNamespace(stdout="CPU: host\n"))
    assert core._detect_gpu_device(str(server)) == ""

    monkeypatch.setattr(core, "_is_executable", real_is_executable)
    monkeypatch.setattr(core.sys, "platform", "win32")
    assert core._llama_server_binary_names() == ("llama-server.exe", "llama-server")
    assert core._is_executable(str(server)) is False
    windows_server = tmp_path / "llama-server.cmd"
    windows_server.write_bytes(b"server")
    assert core._is_executable(str(windows_server)) is True
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert core._install_root().endswith(os.path.join("local", "ida-pro-mcp"))
    monkeypatch.setenv("IDA_PRO_MCP_HOME", "~/custom-ida-mcp")
    assert core._install_root() == os.path.realpath(os.path.expanduser("~/custom-ida-mcp"))


def test_server_discovery_accepts_directory_and_state_fallbacks(monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    server = bin_dir / "llama-server"
    server.write_bytes(b"server")
    server.chmod(0o755)
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(bin_dir))
    assert core._find_llama_server() == str(server)

    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", f"{tmp_path / 'missing'}:{bin_dir}")
    assert core._find_llama_server() == str(server)
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(tmp_path / "missing"))
    monkeypatch.setattr(core, "_read_embedder_state", lambda: {"server_bin": str(server)})
    assert core._find_llama_server() == str(server)


def test_embedder_status_discovers_shared_lease_and_server_json(monkeypatch, tmp_path):
    lease_path = tmp_path / "embed-lease.json"
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_path))
    lease_path.write_text(json.dumps({"port": 19001}), encoding="utf-8")
    obj = _embedder(tmp_path, ready=False, use_llama=False)
    obj._port = None
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(b'{"status":"ok"}'))
    status = obj.status(probe=True)
    assert status["ready"] is True
    assert status["port"] == 19001
    assert status["use_llama"] is True
    assert status["owns_process"] is False
    assert status["probe_error"] == ""

    lease_path.write_text(json.dumps({"port": "bad"}), encoding="utf-8")
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("health unavailable")))
    cold = _embedder(tmp_path, ready=False, use_llama=False)
    assert cold.status(probe=True)["ready"] is False

    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response({"ok": True}))
    assert BgeCodeEmbedder._server_json(19001, "/props") == {"ok": True}


def test_embedder_idle_timer_and_active_slot_branches(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    assert obj._schedule_idle_shutdown(timeout=0) is None
    assert obj._cancel_idle_shutdown() is None

    timers = []

    class Timer:
        def __init__(self, delay, callback, args):
            self.delay = delay
            self.callback = callback
            self.args = args
            self.daemon = False
            self.cancelled = False
            timers.append(self)

        def start(self):
            return None

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(core.threading, "Timer", Timer)
    obj._schedule_idle_shutdown(timeout=1)
    obj._schedule_idle_shutdown(timeout=2)
    assert timers[0].cancelled is True
    obj._cancel_idle_shutdown()
    assert timers[1].cancelled is True

    stopped = []
    obj.stop = lambda: stopped.append(True)
    obj._shutdown_if_idle(0)  # stale generation
    assert not stopped
    obj._idle_generation = 10
    obj._server_has_active_slots = lambda: True
    obj._schedule_idle_shutdown = lambda: stopped.append("rescheduled")
    obj._shutdown_if_idle(10)
    assert stopped == ["rescheduled"]
    obj._server_has_active_slots = lambda: False
    obj._shutdown_if_idle(10)
    assert stopped[-1] is True


def test_behavior_classifier_anchor_result_and_generation_edges(monkeypatch, tmp_path):
    class Embedder:
        dim = 2
        backend = "offline"
        _model_path = str(tmp_path / "model.gguf")

        def __init__(self, result):
            self.result = result

        def embed(self, _text):
            return self.result(_text) if callable(self.result) else self.result

    classifier = BehaviorClassifier(Embedder(object()))
    classifier._save_anchor = lambda *_args: None
    assert classifier._get_anchor("network_raw", generation=0) is None

    classifier._embedder = Embedder([1.0, 0.0])
    assert classifier._get_anchor("network_raw", generation=0) == [1.0, 0.0]
    classifier.clear_cache()
    classifier._embedder = Embedder(types.SimpleNamespace(ok=False, vector=None))
    assert classifier._get_anchor("network_raw") is None

    classifier._embedder = Embedder([1.0, 0.0])
    classifier._anchor_generation = 3

    def invalidate_during_embed(_text):
        classifier._anchor_generation += 1
        return [0.0, 1.0]

    classifier._embedder = Embedder(invalidate_during_embed)
    # A generation mismatch never publishes the result computed for an older
    # cache snapshot.
    assert classifier._get_anchor("network_raw", generation=3) is None


def test_behavior_classifier_classify_fallback_and_backend_edges(monkeypatch, tmp_path):
    class Embedder:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")

        def embed(self, text):
            return core._EmbedResult([1.0, 0.0], "offline", text != "bad")

    classifier = BehaviorClassifier(Embedder())
    classifier.classify_vec = lambda _vec, **kwargs: (
        [{"behavior": "network", "confidence": 0.8}] if kwargs["block"] else []
    )
    assert classifier.classify("recv(socket)", block=False)[0]["backend"] == "offline"
    assert classifier.classify("bad") == []
    classifier._embedder = types.SimpleNamespace(embed=lambda _text: object())
    with pytest.raises(AttributeError):
        classifier.classify("recv(socket)")
