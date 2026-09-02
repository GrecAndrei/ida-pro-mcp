"""Cover embedder discovery and lease ownership at their real boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence import core
from tests.host.intelligence.test_core_runtime_modes import _embedder


def test_embedder_state_precedence_and_write_validation(tmp_path, monkeypatch):
    install = tmp_path / "install"
    cache = tmp_path / "cache"
    install.mkdir()
    cache.mkdir()
    monkeypatch.setattr(core, "_install_root", lambda: str(install))
    monkeypatch.setattr(core, "CACHE_DIR", str(cache))
    (install / "embedder.json").write_text("not-json", encoding="utf-8")
    (cache / "embedder.json").write_text(json.dumps({"model_path": "~/model.gguf"}), encoding="utf-8")
    assert core._read_embedder_state()["model_path"] == "~/model.gguf"
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    (cache / "embedder.json").write_text(json.dumps({"model_path": str(model)}), encoding="utf-8")
    state = core._read_embedder_state()
    assert state["model_path"] == str(model)
    assert state["_source"] == str(cache / "embedder.json")

    written = core.write_embedder_state(
        install,
        model_path=str(model),
        server_bin=str(tmp_path / "llama-server"),
        profile="custom",
        backend="cloud",
        gemini_model="gemini-test",
        gemini_dimension=1,
        gemini_vertex_project="project",
        gemini_vertex_location="europe-west1",
        disabled=True,
        rerank={"model_path": str(model), "enabled": True, "empty": ""},
    )
    payload = json.loads(Path(written).read_text(encoding="utf-8"))
    assert payload["backend"] == "gemini"
    assert payload["gemini_dimension"] == core.GEMINI_MIN_DIM
    assert payload["rerank"] == {"model_path": str(model), "enabled": True}
    with pytest.raises(ValueError, match="unknown embedding backend"):
        core.write_embedder_state(install, backend="remote")
    with pytest.raises(ValueError, match="unknown embedding model profile"):
        core.write_embedder_state(install, profile="missing")


def test_server_and_model_discovery_honor_explicit_and_quantized_paths(tmp_path, monkeypatch):
    server = tmp_path / "llama-server"
    server.write_bytes(b"server")
    server.chmod(0o755)
    model_q8 = tmp_path / "qwen3-embedding-0.6b-q8_0.gguf"
    model_q4 = tmp_path / "qwen3-embedding-0.6b-q4_k_m.gguf"
    model_q8.write_bytes(b"q8")
    model_q4.write_bytes(b"q4")
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(server))
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    assert core._find_llama_server() == str(server)
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", f"{tmp_path / 'missing'};{model_q8}")
    core._MODEL_PATH_CACHE = None
    assert core._find_model() == str(model_q8)

    monkeypatch.delenv("IDA_MCP_EMBED_MODEL")
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path / "install"))
    monkeypatch.setattr(core, "_PROJECT_ROOT", str(tmp_path / "project"))
    monkeypatch.setattr(core, "glob", __import__("glob"))
    core._MODEL_PATH_CACHE = None
    assert core._model_quant_rank(str(model_q4)) < core._model_quant_rank(str(model_q8))
    monkeypatch.setenv("IDA_MCP_Q4", "0")
    assert core._model_quant_rank(str(model_q8)) < core._model_quant_rank(str(model_q4))


def test_lease_validation_and_retirement_fail_closed(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._lease_identity = lambda: {"model_path": str(tmp_path / "model.gguf"), "server_path": str(tmp_path / "server")}
    obj._server_json = lambda _port, endpoint: {"status": "ok"} if endpoint == "health" else {"model_path": str(tmp_path / "model.gguf")}
    monkeypatch.setattr(core, "_pid_alive", lambda pid: pid > 0)
    monkeypatch.setattr(core, "_process_start_token", lambda _pid: "start")
    valid = {"schema": 2, "pid": 11, "owner_pid": 12, "port": 18000, "process_start_token": "start", "owner_start_token": "start", **obj._lease_identity()}
    assert obj._lease_matches(valid) is True
    assert obj._lease_matches({**valid, "schema": 1}) is False
    assert obj._lease_matches({**valid, "recycle_requested": True}) is False
    obj._server_json = lambda *_args: {"status": "bad"}
    assert obj._lease_matches(valid) is False

    lease_file = tmp_path / "lease.json"
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    obj._read_lease = lambda: valid
    obj._pid_is_expected_server = lambda _pid, _lease: True
    alive = iter([True, False])
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: next(alive, False))
    killed = []
    monkeypatch.setattr(core.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(core.time, "monotonic", lambda: 4.0)
    monkeypatch.setattr(obj, "_invalidate_embedding_cache", lambda: None)
    obj._retire_lease_process(valid, "test recycle")
    assert (11, 15) in killed
    assert obj._last_recycle_reason == "test recycle"


def test_interprocess_lock_and_process_helpers_cover_timeout(tmp_path, monkeypatch):
    lock_path = str(tmp_path / "request.lock")
    first = core._InterProcessLock(lock_path, timeout=0)
    second = core._InterProcessLock(lock_path, timeout=0)
    with first, pytest.raises(core.EmbeddingQueueTimeout):
        second.__enter__()
    assert second.handle is None
    assert core._pid_alive(0) is False
    monkeypatch.setattr(core, "sys", type("Sys", (), {"platform": "plan9"})())
    assert core._process_command(1) == ""
    assert core._process_start_token(1) == ""
    assert core._process_rss_bytes(1) == 0
