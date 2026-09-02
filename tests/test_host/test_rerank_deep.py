from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.core import write_embedder_state
from ida_pro_mcp.host.intelligence.rerank import (
    Reranker,
    _find_rerank_model,
    _read_rerank_state,
)


def test_rerank_state_read_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    write_embedder_state(
        tmp_path,
        rerank={
            "model_path": "/path/to/rerank.gguf",
            "profile": "qwen3-reranker-0.6b",
        },
    )

    read_back = _read_rerank_state()
    assert read_back.get("model_path") == "/path/to/rerank.gguf"
    assert read_back.get("profile") == "qwen3-reranker-0.6b"


def test_find_rerank_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_model = tmp_path / "rerank_qwen.gguf"
    fake_model.write_bytes(b"GGUF")

    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", str(fake_model))
    found = _find_rerank_model()
    assert found == str(fake_model)


def test_reranker_disabled_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_RERANK_DISABLED", "1")
    reranker = Reranker()
    status = reranker.status()
    assert status.get("ready") is False

    # Calling rerank on disabled backend returns un-reranked items or None
    res = reranker.rerank("find main", ["doc A", "doc B"])
    assert res is None or res == []
