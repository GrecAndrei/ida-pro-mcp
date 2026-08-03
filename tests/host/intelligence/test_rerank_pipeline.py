"""Reranker pipeline tests: document_text persistence, profile discovery,
and the semantic-search rerank stage (mocked reranker so discriminating vs
non-discriminating behaviour is deterministic)."""

from __future__ import annotations

import sys
import types

import pytest

from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from ida_pro_mcp.host.intelligence.helpers import _EmbedResult
from ida_pro_mcp.host.intelligence.rerank_profiles import (
    BGE_RERANKER_V2_GEMMA,
    QWEN3_RERANKER_0_6B,
    QWEN3_RERANKER_4B,
    profile_from_rerank_model,
)


class _KeywordEmbedder:
    """Deterministic: 'alpha' -> [1,0], 'gamma' -> [-1,0], else [0,1]."""

    backend = "test"
    dim = 2

    def _vec(self, text: str) -> list[float]:
        if "alpha" in text:
            return [1.0, 0.0]
        if "gamma" in text:
            return [-1.0, 0.0]
        return [0.0, 1.0]

    def embed_vector(self, text: str):
        return self._vec(str(text or ""))

    def embed_query_vector(self, text: str):
        return self._vec(str(text or ""))

    def embed_documents(self, texts: list[str]):
        return [_EmbedResult(self._vec(t), self.backend, True) for t in texts]


# ---------------------------------------------------------------------------
# document_text persistence
# ---------------------------------------------------------------------------

def test_index_persists_document_text_and_row_docs_recovers_it(tmp_path):
    db = FunctionEmbeddingIndex(str(tmp_path / "s.embeddings.db"), _KeywordEmbedder())
    ok = db.index_many(
        [
            ("0x401000", "alpha_fn", "void alpha_fn(void) { alpha(); }", None),
            ("0x402000", "beta_fn", "void beta_fn(void) { beta(); }", None),
        ]
    )
    assert ok["indexed"] == 2

    docs = db._row_docs_for_eas(["0x401000", "0x402000", "0x999999"])
    assert docs["0x401000"] == "void alpha_fn(void) { alpha(); }"
    assert docs["0x402000"] == "void beta_fn(void) { beta(); }"
    assert "0x999999" not in docs


def test_document_text_migration_adds_column_on_legacy_db(tmp_path):
    """A DB created before document_text existed must migrate additively."""
    import sqlite3

    db_path = str(tmp_path / "legacy.embeddings.db")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE func_embeddings (
                ea TEXT PRIMARY KEY, name TEXT, dim INTEGER,
                vec_blob BLOB NOT NULL, pseudo_hash TEXT, indexed_at REAL
            )
            """
        )
        conn.execute(
            "INSERT INTO func_embeddings(ea,name,dim,vec_blob,pseudo_hash,indexed_at) VALUES(?,?,?,?,?,?)",
            ("0x401000", "old", 2, b"\x00\x01\x02\x03", "h", 1.0),
        )
    index = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    # Column now exists and legacy row is readable (absent from row_docs).
    assert index._row_docs_for_eas(["0x401000"]) == {}
    # Re-indexing the legacy row persists its document text.
    index.index("0x401000", "old", "void old(void) {}")
    assert index._row_docs_for_eas(["0x401000"])["0x401000"] == "void old(void) {}"


# ---------------------------------------------------------------------------
# profile discovery
# ---------------------------------------------------------------------------

def test_profile_from_rerank_model_filenames():
    assert profile_from_rerank_model("/x/qwen3-reranker-0.6b-q8_0.gguf").key == "qwen3-reranker-0.6b"
    assert profile_from_rerank_model("/x/Qwen3-Reranker-4B-Q4_K_M.gguf").key == "qwen3-reranker-4b"
    assert profile_from_rerank_model("/x/bge-reranker-v2-gemma.Q4_K_M.gguf").key == "bge-reranker-v2-gemma"
    assert profile_from_rerank_model("/x/bge-reranker-v2-m3-q8_0.gguf").key == "bge-reranker-v2-m3"


def test_profile_aliases():
    from ida_pro_mcp.host.intelligence.rerank_profiles import get_rerank_model_profile

    assert get_rerank_model_profile("qwen3") is QWEN3_RERANKER_0_6B
    assert get_rerank_model_profile("bge-gemma") is BGE_RERANKER_V2_GEMMA
    assert get_rerank_model_profile("qwen3-reranker-4b") is QWEN3_RERANKER_4B
    assert get_rerank_model_profile("nonsense") is None


# ---------------------------------------------------------------------------
# semantic rerank stage
# ---------------------------------------------------------------------------

class _FakeIndex:
    """Minimal FunctionEmbeddingIndex surface used by the rerank stage."""

    def __init__(self, results):
        self._results = results

    @property
    def size(self):
        return len(self._results)

    def search(self, query, top_k, threshold, address_ranges=None):
        return [dict(r) for r in self._results]

    def refresh_from_disk(self):
        pass

    def _row_docs_for_eas(self, eas):
        return {ea: f"doc for {ea}" for ea in eas}


class _ScriptedReranker:
    """Injected reranker class; behaviour is set per test via `scripted`.

    The pipeline constructs `Reranker()` internally, so we monkeypatch the
    rerank module's `Reranker` attribute to this class and control what its
    `rerank()` returns through the class attribute.
    """

    _use_llama = True
    scripted: dict | None = None

    def __init__(self):
        self._script = _ScriptedReranker.scripted or {"result": None, "profile": "Test"}

    def rerank(self, query, documents):
        return self._script["result"]

    def status(self):
        return {"profile_name": self._script.get("profile", "Test Reranker")}


def _install_ida_stubs():
    """Stub every IDA module `tools/_common.py` imports so the search tools
    import cleanly outside IDA.  Reuses the repo's own stub installer, plus
    `ida_fixup` which the tools import but the shared stub omits."""
    import os as _os
    from tests._isolated_repo_loader import install_common_stub

    # `tools/_common` re-exports os via `from _common import *`; the synthetic
    # stub must provide it too.
    install_common_stub(overrides={"os": _os})
    sys.modules.setdefault("ida_fixup", types.ModuleType("ida_fixup"))


def _run_search_nl(index, query, scripted):
    """Call semantic.search_nl with the fake index and scripted reranker."""
    import ida_pro_mcp.ida_mcp.tools.search.semantic as sem
    import ida_pro_mcp.host.intelligence.rerank as rerank_mod

    # Pin the backend so no real assembler/embedder is constructed.
    sem.get_backend = lambda: (index, _FakeClassifier(), "test.idb")
    if scripted is None:
        # Simulate "no reranker installed": the pipeline skips construction.
        _ScriptedReranker._use_llama = False
        _ScriptedReranker.scripted = None
    else:
        _ScriptedReranker._use_llama = True
        _ScriptedReranker.scripted = scripted
    _orig_reranker = rerank_mod.Reranker
    _orig_max = rerank_mod.RERANK_MAX_CANDIDATES
    rerank_mod.Reranker = _ScriptedReranker
    rerank_mod.RERANK_MAX_CANDIDATES = 8
    try:
        return sem.search_nl(
            query,
            limit=3,
            mode="quick",
            min_score=0.0,
        )
    finally:
        # The module object outlives this test (the conftest snapshot holds the
        # same reference), so leaving a patched class behind would corrupt every
        # later test that imports rerank_mod.
        rerank_mod.Reranker = _orig_reranker
        rerank_mod.RERANK_MAX_CANDIDATES = _orig_max


class _FakeClassifier:
    def classify(self, text, threshold, top_k, block):
        return []


@pytest.fixture(autouse=True)
def _isolate_modules():
    _install_ida_stubs()
    snapshot = dict(sys.modules)
    yield
    for name in list(sys.modules.keys()):
        if name not in snapshot:
            del sys.modules[name]


def _results_three():
    # Equal recall scores so the adaptive gate keeps all three; the rerank
    # stage is the only thing that can change their relative order.
    return [
        {"ea": "0x401000", "name": "aes", "similarity": 0.9, "score": 0.9, "signature": "aes"},
        {"ea": "0x402000", "name": "recv", "similarity": 0.9, "score": 0.9, "signature": "recv"},
        {"ea": "0x403000", "name": "sha", "similarity": 0.9, "score": 0.9, "signature": "sha"},
    ]


def test_rerank_applied_reorders_to_rerank_scores():
    index = _FakeIndex(_results_three())
    # Rerank says the original index 2 (sha) is the best for this query.
    scripted = {
        "result": [{"index": 0, "score": 0.8}, {"index": 1, "score": 0.85}, {"index": 2, "score": 0.9}],
        "profile": "Test Reranker",
    }
    resp = _run_search_nl(index, "hash function", scripted)

    assert resp["ok"] is True
    assert resp["rerank"]["applied"] is True
    assert resp["rerank"]["profile"] == "Test Reranker"
    # The adaptive gate keeps the rerank-best at the top.
    assert resp["items"][0]["addr"] == "0x403000"
    assert resp["items"][0]["rerank_score"] == pytest.approx(0.9)
    # Rerank score becomes the ordering score.
    assert resp["items"][0]["score"] == pytest.approx(0.9)


def test_rerank_not_applied_when_scores_are_constant():
    index = _FakeIndex(_results_three())
    # Identical scores (e.g. a headless conversion) must not reorder.
    scripted = {
        "result": [{"index": 0, "score": 0.5}, {"index": 1, "score": 0.5}, {"index": 2, "score": 0.5}],
        "profile": "Broken Reranker",
    }
    resp = _run_search_nl(index, "anything", scripted)

    assert resp["ok"] is True
    assert resp["rerank"]["applied"] is False
    # Recall order preserved, no rerank score populated.
    assert [i["addr"] for i in resp["items"]] == ["0x401000", "0x402000", "0x403000"]
    assert all(i.get("rerank_score") is None for i in resp["items"])


def test_rerank_skipped_when_no_reranker_installed():
    index = _FakeIndex(_results_three())
    resp = _run_search_nl(index, "anything", None)

    assert resp["ok"] is True
    assert resp["rerank"]["applied"] is False
    assert resp["rerank"]["profile"] is None
    assert [i["addr"] for i in resp["items"]] == ["0x401000", "0x402000", "0x403000"]


# ---------------------------------------------------------------------------
# Reranker.reset — model switching without process restart
# ---------------------------------------------------------------------------

def test_reset_swaps_the_singleton_without_leaving_a_stale_instance():
    import ida_pro_mcp.host.intelligence.rerank as rerank_mod

    first = rerank_mod.Reranker.reset("/nonexistent/reranker.gguf")
    assert isinstance(first, rerank_mod.Reranker)
    assert first._use_llama is False  # bogus path -> not enabled

    second = rerank_mod.Reranker.reset("/nonexistent/reranker.gguf")
    assert second is not first  # a reset always builds a fresh singleton


def test_reset_default_ctx_is_bounded_by_profile_max():
    import ida_pro_mcp.host.intelligence.rerank as rerank_mod

    rr = rerank_mod.Reranker.reset("/nonexistent/reranker.gguf")
    assert rr._ctx <= rr._profile.max_context
    assert rr._ctx >= 1024
    # A pair is a bounded document + query; 4096 covers every pair without a
    # laptop-sized KV cache.
    assert rr._ctx <= 4096
