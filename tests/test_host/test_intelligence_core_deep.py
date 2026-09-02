from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.core import (
    BgeCodeEmbedder,
    _find_llama_server,
    _find_model,
    _read_embedder_state,
    hash_file,
    write_embedder_state,
)


def test_hash_file(tmp_path: Path) -> None:
    sample = tmp_path / "model.bin"
    sample.write_bytes(b"GGUF_MODEL_DATA_12345")
    h = hash_file(str(sample))
    assert len(h) == 64

    # Bounded hash
    h_bounded = hash_file(str(sample), max_bytes=4)
    assert len(h_bounded) == 64
    assert h != h_bounded


def test_embedder_state_read_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    write_embedder_state(
        tmp_path,
        model_path="/path/to/model.gguf",
        server_bin="/path/to/llama-server",
        profile="qwen3-embedding-0.6b",
    )

    read_back = _read_embedder_state()
    assert read_back.get("model_path") == "/path/to/model.gguf"
    assert read_back.get("profile") == "qwen3-embedding-0.6b"


def test_find_llama_server_and_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_server = tmp_path / "llama-server"
    fake_server.write_bytes(b"")
    fake_server.chmod(0o755)

    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(fake_server))
    found_server = _find_llama_server()
    assert found_server == str(fake_server)

    fake_model = tmp_path / "model.gguf"
    fake_model.write_bytes(b"GGUF")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(fake_model))
    found_model = _find_model()
    assert found_model == str(fake_model)


def test_bge_code_embedder_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.EMBED_DISABLED", True)
    monkeypatch.setattr(BgeCodeEmbedder, "_instance", None)
    monkeypatch.setenv("IDA_MCP_EMBED_DISABLED", "1")
    embedder = BgeCodeEmbedder()
    status = embedder.status()
    assert status.get("ready") is False
    assert status.get("disabled_by_env") is True
    assert status.get("use_llama") is False
