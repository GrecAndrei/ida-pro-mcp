from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.native import (
    NativeEmbedder,
    NativeReranker,
    _backend_requested,
    _find_native_lib,
    _rerank_cache_key,
    native_embedder_available,
    native_reranker_available,
    prefer_native_embed,
    prefer_native_rerank,
)


def test_rerank_cache_key_collision_resistance() -> None:
    # Delimiter injection test: query='a\0b', doc='c' vs query='a', doc='b\0c'
    k1 = _rerank_cache_key("a\0b", ["c"])
    k2 = _rerank_cache_key("a", ["b\0c"])
    assert k1 != k2

    k3 = _rerank_cache_key("find main", ["doc1", "doc2"])
    k4 = _rerank_cache_key("find main", ["doc1", "doc2"])
    assert k3 == k4


def test_backend_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_BACKEND", "native")
    assert _backend_requested() == "native"

    monkeypatch.setenv("IDA_MCP_BACKEND", "http")
    assert _backend_requested() == "http"

    monkeypatch.delenv("IDA_MCP_BACKEND", raising=False)
    assert _backend_requested() == ""


def test_find_native_lib_and_availability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_lib = tmp_path / "libmcp_llama.so"
    fake_lib.write_bytes(b"\x7fELF")

    monkeypatch.setenv("IDA_MCP_NATIVE_LIB", str(fake_lib))
    assert _find_native_lib() == str(fake_lib)


def test_prefer_native_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_ENABLE_NATIVE_EMBED", "0")
    assert prefer_native_embed() is False

    monkeypatch.setenv("IDA_MCP_ENABLE_NATIVE_RERANK", "0")
    assert prefer_native_rerank() is False


def test_native_embedder_and_reranker_lifecycle() -> None:
    embedder = NativeEmbedder()
    status = embedder.status()
    assert isinstance(status, dict)

    reranker = NativeReranker()
    r_status = reranker.status()
    assert isinstance(r_status, dict)
