"""Offline coverage for local, cloud, and shared-process intelligence modes."""

from __future__ import annotations

import json
import os
import types

from ida_pro_mcp.host.intelligence import core
from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder


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
