from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import urllib.error
from pathlib import Path
from unittest import mock

from ida_pro_mcp.host.intelligence import core
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


def test_embedder_float_env_rejects_non_finite_values():
    """Bad numeric overrides must not create unbounded embedder timeouts."""
    code = (
        "from ida_pro_mcp.host.intelligence import core; "
        "print(core.EMBED_REQUEST_TIMEOUT, core.EMBED_CHARS_PER_TOKEN, "
        "core.DECOMP_DOCUMENT_FRACTION, core.ANCHOR_EMBED_BUDGET_SEC)"
    )
    for raw in ("nan", "inf", "-inf"):
        env = dict(
            os.environ,
            IDA_MCP_EMBED_REQUEST_TIMEOUT=raw,
            IDA_MCP_EMBED_CHARS_PER_TOKEN=raw,
            IDA_MCP_DECOMP_DOCUMENT_FRACTION=raw,
            IDA_MCP_ANCHOR_EMBED_BUDGET_SEC=raw,
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0, proc.stderr
        assert [float(value) for value in proc.stdout.split()] == [15.0, 3.0, 0.2, 20.0]


def test_available_cpu_count_respects_process_affinity(monkeypatch):
    monkeypatch.setattr(core.os, "sched_getaffinity", lambda _pid: {2, 4, 6}, raising=False)
    assert core._available_cpu_count() == 3


def test_llama_context_layout_preserves_slots_and_caps_total_context():
    assert core._llama_context_layout(2048, 3) == (2048, 3, 6144)
    assert core._llama_context_layout(4096, 16) == (4096, 8, 32768)
    assert core._llama_context_layout(0, 0) == (512, 1, 512)
    assert core._llama_context_layout(4096, 4, max_total_ctx=2048) == (2048, 1, 2048)


def test_decomp_document_budget_adapts_to_model_context(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr(core, "EMBED_CTX", 4096)
    monkeypatch.setattr(core, "EMBED_CHARS_PER_TOKEN", 3.0)
    monkeypatch.setattr(core, "DECOMP_DOCUMENT_FRACTION", 0.2)
    monkeypatch.setattr(core, "DECOMP_DOCUMENT_CHARS", 0)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        assert emb.max_input_chars == 11904
        assert emb.decomp_document_chars == 2380
    finally:
        _restore_singleton(old)


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


def test_http_embedder_caches_exact_single_query(monkeypatch):
    old = _reset_singleton()
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: "")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: "")
    try:
        emb = BgeCodeEmbedder()
        emb._use_llama = True
        emb._ready = True
        emb._dimension = 2
        emb._model_path = "cache-test-model.gguf"
        calls = 0

        def fake_request(texts, *, purpose, timeout):
            nonlocal calls
            calls += 1
            return [[0.6, 0.8]] if emb.dim == 2 else [[1.0, 0.0, 0.0]]

        monkeypatch.setattr(emb, "_request_embeddings", fake_request)
        assert emb.embed_vector("repeat me") == [0.6, 0.8]
        assert emb.embed_vector("repeat me") == [0.6, 0.8]
        assert calls == 1

        emb._dimension = 3
        assert emb.embed_vector("repeat me") == [1.0, 0.0, 0.0]
        assert calls == 2

        emb._dimension = 2
        assert emb.embed_vector("repeat me") == [0.6, 0.8]
        assert calls == 2

        emb._invalidate_embedding_cache()
        assert emb.embed_vector("repeat me") == [0.6, 0.8]
        assert calls == 3
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


def test_server_uses_batch_threads_without_raising_query_threads(monkeypatch, tmp_path: Path):
    """Indexing throughput can use more cores without slowing single queries."""
    old = _reset_singleton()
    server = tmp_path / "llama-server"
    server.write_bytes(b"#!/bin/sh\n")
    server.chmod(0o755)
    model = tmp_path / "bge-code-v1-q8_0.gguf"
    model.write_bytes(b"tiny-model")
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_llama_server", lambda: str(server))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._find_model", lambda: str(model))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._EMBED_LEASE_FILE", str(tmp_path / "lease.json"))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.EMBED_THREADS", 4)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.EMBED_BATCH_THREADS", 8)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.EMBED_PARALLEL", 3)
    try:
        emb = BgeCodeEmbedder()
        emb._max_batch_size = 3
        proc = mock.MagicMock()
        proc.pid = 1234
        proc.poll.return_value = None
        health = mock.MagicMock()
        health.read.return_value = b'{"status":"ok"}'
        with mock.patch.object(emb, "_pick_port", return_value=43123), mock.patch(
            "ida_pro_mcp.host.intelligence.core.subprocess.Popen", return_value=proc
        ) as popen, mock.patch(
            "ida_pro_mcp.host.intelligence.core.urllib.request.urlopen", return_value=health
        ), mock.patch("ida_pro_mcp.host.intelligence.core.time.sleep"):
            assert emb._start_server() is True
        command = popen.call_args.args[0]
        assert command[command.index("--threads") + 1] == "4"
        assert command[command.index("--threads-batch") + 1] == "8"
        assert command[command.index("--parallel") + 1] == "3"
        assert command[command.index("--ctx-size") + 1] == "6144"
        assert command[command.index("--batch-size") + 1] == "2048"
        assert command[command.index("--ubatch-size") + 1] == "2048"
    finally:
        _restore_singleton(old)
