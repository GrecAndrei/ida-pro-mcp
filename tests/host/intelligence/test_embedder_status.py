from __future__ import annotations

import contextlib
import urllib.error
from pathlib import Path
from unittest import mock

from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder


def _reset_singleton():
    old = BgeCodeEmbedder._instance
    BgeCodeEmbedder._instance = None
    return old


def _restore_singleton(old):
    inst = BgeCodeEmbedder._instance
    if inst is not None:
        with contextlib.suppress(Exception):
            inst.stop()
    BgeCodeEmbedder._instance = old


def test_embedder_unavailable_without_model_or_server(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        assert emb.backend == "unavailable"
        out = emb.embed("unsafe memcpy sample -> buffer_overflow top hit")
        assert out.ok is False
        assert out.vector is None
        assert out.backend == "unavailable"
    finally:
        _restore_singleton(old)


def test_embedder_respects_env_disable(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.EMBED_DISABLED", True)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "/bin/echo")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "/tmp/model.gguf")
    try:
        emb = BgeCodeEmbedder()
        assert emb.backend == "unavailable"
        assert emb.status()["disabled_by_env"] is True
    finally:
        _restore_singleton(old)


def test_embedder_repeated_text_is_deterministic(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        a = emb.embed("same text same vector")
        b = emb.embed("same text same vector")
        # Both should be unavailable (no model) and structurally equal
        assert a.ok == b.ok
        assert a.vector == b.vector
    finally:
        _restore_singleton(old)


def test_embed_batch_empty_returns_empty(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        assert emb.embed_batch([]) == []
    finally:
        _restore_singleton(old)


def test_embed_batch_rpc_failure_returns_unavailable_results(monkeypatch):
    """When the RPC server is unreachable, embed_batch returns results with
    ok=False for each item rather than silently degrading to a weaker backend."""
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "/bin/echo")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "/tmp/model.gguf")
    try:
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._port = 9
        emb._max_rpc_failures = 1
        with mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            out = emb.embed_batch(["a", "b", "c", "d"])
        assert len(out) == 4
        assert all(r.ok is False for r in out)
        assert all(r.vector is None for r in out)
    finally:
        _restore_singleton(old)


def test_embed_vector_returns_none_when_unavailable(monkeypatch):
    """embed_vector() is the convenience wrapper: returns the vector or None."""
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        assert emb.embed_vector("any text") is None
    finally:
        _restore_singleton(old)


def test_status_does_not_start_server_by_default(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "/bin/echo")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "/tmp/model.gguf")
    try:
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        with mock.patch.object(emb, "_start_server", side_effect=AssertionError("should not start")):
            st = emb.status(probe=False)
        assert st["ready"] is False
        assert st["use_llama"] is True
    finally:
        _restore_singleton(old)


def test_status_has_fingerprints(monkeypatch, tmp_path: Path):
    old = _reset_singleton()
    server = tmp_path / "llama-server"
    server.write_bytes(b"#!/bin/sh\necho ok\n")
    server.chmod(0o755)
    model = tmp_path / "bge-code-v1-q8_0.gguf"
    model.write_bytes(b"tiny-model")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: str(server))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: str(model))
    try:
        emb = BgeCodeEmbedder()
        st = emb.status(deep_hash=True)
        assert st["server_bin_exists"] is True
        assert st["model_exists"] is True
        assert st["fingerprints"]["model"]["sha256_head_16mb"]
        assert st["fingerprints"]["model"]["sha256_full"]
        assert st["fingerprints"]["server"]["sha256_head_16mb"]
    finally:
        _restore_singleton(old)
