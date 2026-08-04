"""Unit tests for the in-process native llama.cpp backend (native.py).

These run without the real libmcp_llama.so — they exercise the ctypes
binding against a fake library and the graceful-degradation paths.  The live
library is exercised by benchmarks/native_bench.py and the integration check.

The fake library implements the same C ABI the driver exposes:
  mcp_embed_new/free/dim/encode, mcp_rerank_new/free/score.
"""

from __future__ import annotations

import ctypes
import os

import pytest

from ida_pro_mcp.host.intelligence import native
from ida_pro_mcp.host.intelligence.native import (
    NativeEmbedder,
    NativeReranker,
    prefer_native_embed,
    prefer_native_rerank,
)


class _FakeMissingLib:
    """Fake loader for the "library absent" path."""

    path = ""
    error = "not found"
    lib = None


class _FakeLib:
    """ctypes-shaped fake of libmcp_llama.so."""

    path = "/fake/libmcp_llama.so"
    error = ""
    # The real _NativeLib sets .lib to the CDLL handle; a truthy sentinel keeps
    # `native_embedder_available()`/`status()` happy.  The C functions below
    # are defined directly on the class, matching the loader's __getattr__.
    lib = object()

    def mcp_llama_version(self) -> bytes:
        return b"fake 1"

    def mcp_err_message(self, code: int) -> bytes:
        return b"fake error"

    def mcp_embed_new(self, model: bytes, threads: int, ctx: int) -> int:
        return 1  # opaque handle

    def mcp_embed_free(self, handle: int) -> None:
        return None

    def mcp_embed_dim(self, handle: int) -> int:
        return 4  # tiny dim for tests

    def mcp_embed_encode(self, handle: int, texts, n: int, out) -> int:
        # Fake deterministic vectors that depend on the input text (content
        # affects value) and the row index (rows stay distinct).
        dim = 4
        for i in range(n):
            raw = getattr(texts[i], "value", None)
            if raw is None:
                raw = texts[i]
            if not isinstance(raw, bytes):
                raw = bytes(str(raw), "utf-8")
            base = sum(raw)  # content-dependent, rows stay distinct
            for j in range(dim):
                out[i * dim + j] = ((base % 97) + i + j + 1) / 100.0
        return 0

    def mcp_rerank_new(self, model: bytes, threads: int, ctx: int) -> int:
        return 2

    def mcp_rerank_free(self, handle: int) -> None:
        return None

    def mcp_rerank_score(self, handle: int, query: bytes, docs, n: int, out) -> int:
        # Distinct descending-by-doc-position scores so "sorted" is observable.
        for i in range(n):
            out[i] = float(n - i)
        return 0


@pytest.fixture(autouse=True)
def _isolate_singletons_and_lib(monkeypatch, tmp_path):
    """Reset the process-wide singletons and point the loader at the fake lib.

    ``_open`` guards on ``os.path.isfile(model_path)``, so the fake model
    paths must be real files.
    """
    embed_model = tmp_path / "model.gguf"
    embed_model.write_bytes(b"fake")
    rerank_model = tmp_path / "rerank.gguf"
    rerank_model.write_bytes(b"fake")
    # Reset the real loader's singleton so a stale instance from another test
    # can't leak through (it caches .lib=None when the real lib is absent).
    if hasattr(native, "_NativeLib"):
        native._NativeLib._instance = None
    monkeypatch.setattr(native, "_NativeLib", _FakeLib)
    NativeEmbedder._instance = None
    NativeReranker._instance = None
    NativeEmbedder._lock = __import__("threading").Lock()
    NativeReranker._lock = __import__("threading").Lock()
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_native_lib", lambda: "/fake/libmcp_llama.so"
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_model", lambda: str(embed_model)
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_rerank_model", lambda: str(rerank_model)
    )
    yield
    NativeEmbedder._instance = None
    NativeReranker._instance = None
    # bootstrap_native_backend() sets this in the REAL process env (by
    # design — the host needs it to propagate to idat children).  Under
    # pytest that leaks into later tests and makes BgeCodeEmbedder() route
    # to native; scrub it so the routing stays inert outside the host.
    os.environ.pop("IDA_MCP_NATIVE", None)
    os.environ.pop("IDA_MCP_BACKEND", None)


def test_lib_found_and_version():
    lib = native._NativeLib()
    assert lib.lib is not None
    assert lib.mcp_llama_version() == b"fake 1"


def test_embedder_reports_native_backend_and_dim(monkeypatch):
    emb = NativeEmbedder()
    assert emb.ensure_ready()
    assert emb.backend == "native-llama"
    assert emb.dim == 4
    st = emb.status()
    assert st["backend"] == "native-llama"
    assert st["native_lib_exists"] is True
    assert st["model_path"].endswith("model.gguf")


def test_embed_vector_shape_and_determinism(monkeypatch):
    emb = NativeEmbedder()
    assert emb.ensure_ready()
    vec = emb.embed_vector("hello")
    assert vec is not None and len(vec) == 4
    assert emb.embed_vector("hello") == vec  # deterministic for same input
    assert emb.embed_vector("world") != vec  # different input, different vec


def test_embed_batch_returns_per_item_results(monkeypatch):
    emb = NativeEmbedder()
    results = emb.embed_batch(["a", "b", "c"])
    assert len(results) == 3
    assert all(r.ok and r.vector and len(r.vector) == 4 for r in results)
    assert results[0].backend == "native-llama"


def test_embed_unavailable_when_lib_missing(monkeypatch):
    monkeypatch.setattr(native, "_NativeLib", _FakeMissingLib)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_native_lib", lambda: ""
    )
    emb = NativeEmbedder()
    assert not emb.ensure_ready()
    result = emb.embed("anything")
    assert not result.ok
    assert result.vector is None


def test_query_prefix_applied_via_profile(monkeypatch):
    """The native path must apply the profile prefix, like the HTTP path does."""
    from ida_pro_mcp.host.intelligence import model_profiles

    class _FakeProfile:
        key = "fake-embed"
        display_name = "Fake"
        license = ""
        query_prefix = "Instruct: query\n"
        document_prefix = ""
        suffix = ""
        pooling = "last"

        def format_text(self, text: str, purpose: str = "document") -> str:
            prefix = self.query_prefix if purpose == "query" else self.document_prefix
            return f"{prefix}{text}{self.suffix}"

    monkeypatch.setattr(
        native, "profile_from_model", lambda path, requested: _FakeProfile()
    )
    emb = NativeEmbedder()
    assert emb._format("search me", purpose="query") == "Instruct: query\nsearch me"
    assert emb._format("search me", purpose="document") == "search me"


def test_embedding_format_identifies_native_executor(monkeypatch):
    from ida_pro_mcp.host.intelligence import model_profiles

    class _FakeProfile:
        key = "fake-embed"
        display_name = "Fake"
        license = ""
        query_prefix = "q>"
        document_prefix = ""
        suffix = ""
        pooling = "last"

        def format_text(self, text: str, purpose: str = "document") -> str:
            return text

    monkeypatch.setattr(
        native, "profile_from_model", lambda path, requested: _FakeProfile()
    )
    emb = NativeEmbedder()
    assert emb.embedding_format.startswith("native-v1:fake-embed:")
    # Deterministic.
    assert emb.embedding_format == emb.embedding_format


def test_rerank_scores_sorted_and_indexed(monkeypatch):
    rr = NativeReranker()
    assert rr.ensure_ready()
    scored = rr.rerank("query", ["a", "b", "c", "d"])
    assert scored is not None
    scores = [s["score"] for s in scored]
    assert scores == sorted(scores, reverse=True)
    assert {s["index"] for s in scored} == {0, 1, 2, 3}
    assert scored[0]["score"] == 4.0  # fake returns n - i for position i


def test_rerank_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(native, "_NativeLib", _FakeMissingLib)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_native_lib", lambda: ""
    )
    rr = NativeReranker()
    assert rr.rerank("q", ["a"]) is None


def test_prefer_native_honors_env_pin(monkeypatch):
    monkeypatch.setenv("IDA_MCP_BACKEND", "http")
    monkeypatch.delenv("IDA_MCP_NATIVE", raising=False)
    assert prefer_native_embed() is False
    assert prefer_native_rerank() is False

    monkeypatch.setenv("IDA_MCP_BACKEND", "native")
    assert prefer_native_embed() is True
    assert prefer_native_rerank() is True


def test_prefer_native_rerank_honors_rerank_disabled(monkeypatch):
    monkeypatch.setenv("IDA_MCP_BACKEND", "")
    monkeypatch.setenv("IDA_MCP_NATIVE", "1")
    # prefer_native_rerank imports _rerank_enabled from the rerank module at
    # call time, so patch that module's binding.
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank._rerank_enabled", lambda: False
    )
    assert prefer_native_rerank() is False


def test_bootstrap_enables_and_disables(monkeypatch):
    # Lib present, no pin → enabled and env flag set.
    monkeypatch.delenv("IDA_MCP_NATIVE", raising=False)
    monkeypatch.setenv("IDA_MCP_BACKEND", "")
    report = native.bootstrap_native_backend()
    assert report["enabled"] is True
    assert report["lib"] == "/fake/libmcp_llama.so"

    # Explicit pin → not enabled, env untouched.
    monkeypatch.setenv("IDA_MCP_BACKEND", "http")
    report = native.bootstrap_native_backend()
    assert report["enabled"] is False
    assert report["reason"].startswith("backend pinned")

    # Lib missing → not enabled.
    monkeypatch.setenv("IDA_MCP_BACKEND", "")
    monkeypatch.setattr(native, "_NativeLib", _FakeMissingLib)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.native._find_native_lib", lambda: ""
    )
    report = native.bootstrap_native_backend()
    assert report["enabled"] is False
