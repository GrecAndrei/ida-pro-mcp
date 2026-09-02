from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.intelligence.gemini import (
    GEMINI_DEFAULT_DIM,
    GEMINI_DEFAULT_MODEL,
    GeminiEmbedBackend,
    _env_bool,
    _float_env,
    _int_env,
)


def test_gemini_env_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_INT", "42")
    assert _int_env("TEST_INT", 10) == 42
    assert _int_env("INVALID_INT", 10) == 10

    monkeypatch.setenv("TEST_FLOAT", "3.14")
    assert _float_env("TEST_FLOAT", 1.0) == 3.14
    assert _float_env("INVALID_FLOAT", 1.0) == 1.0

    monkeypatch.setenv("TEST_BOOL", "true")
    assert _env_bool("TEST_BOOL", False) is True
    assert _env_bool("INVALID_BOOL", True) is True


def test_gemini_backend_initialization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("VERTEX_AI_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("IDA_MCP_GEMINI_MODEL", "gemini-embedding-2")
    monkeypatch.setenv("IDA_MCP_GEMINI_DIM", "768")

    backend = GeminiEmbedBackend()
    assert backend.backend == "gemini"
    assert backend.dim == 768

    status = backend.status()
    assert isinstance(status, dict)
    assert status["backend"] == "gemini"
    assert status["dim"] == 768


def test_gemini_embed_mocked_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "fake_key_12345")
    backend = GeminiEmbedBackend()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"embedding": {"values": [0.1] * 768}}

    with patch.object(backend, "_post_retry", return_value={"embedding": {"values": [0.1] * 768}}):
        res = backend.embed("void func_main() { return; }")
        assert res.ok is True
        assert len(res.vector) == 768


def test_gemini_batch_chunking(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "fake_key_12345")
    backend = GeminiEmbedBackend()

    texts = [f"func_{i}" for i in range(10)]

    with patch.object(
        backend,
        "_post_retry",
        return_value={"embeddings": [{"values": [0.1] * 768} for _ in range(10)]},
    ):
        results = backend.embed_batch(texts)
        assert len(results) == 10
        assert all(r.ok for r in results)
