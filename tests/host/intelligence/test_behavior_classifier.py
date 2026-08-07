"""Tests for the zero-shot BehaviorClassifier scoring path.

Covers classify / classify_vec (including the block=True on-demand anchor
embedding), refresh_anchors subset warming, and clear_cache invalidation.
"""

from __future__ import annotations

import os

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier
from ida_pro_mcp.host.intelligence.helpers import _EmbedResult


class _FixedVectorEmbedder:
    """Embedder that maps every input to one fixed unit vector."""

    backend = "test"
    dim = 3

    def __init__(self, vector: list[float] | None = None):
        self._vector = vector or [1.0, 0.0, 0.0]
        self.embed_calls: list[str] = []

    def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
        self.embed_calls.append(str(text or ""))
        return _EmbedResult(self._vector, self.backend, True)

    def embed_query(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="query")


class _ModelEmbedder(_FixedVectorEmbedder):
    """Embedder with a real model path (disk-cache eligible)."""

    backend = "native-llama"
    _model_path = "/models/fake.gguf"


def test_classify_vec_skips_uncached_anchors_without_blocking():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    assert classifier.classify_vec([1.0, 0.0, 0.0], threshold=0.5, block=False) == []


def test_classify_vec_embeds_missing_anchors_when_blocking():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    rows = classifier.classify_vec([1.0, 0.0, 0.0], threshold=0.99, top_k=1, block=True)
    assert len(rows) == 1
    assert rows[0]["behavior"] in BehaviorClassifier.ANCHORS
    assert rows[0]["confidence"] == 1.0


def test_classify_vec_threshold_filters_below_cutoff():
    # Anti-parallel query (cosine -1.0) never passes even a lenient threshold.
    classifier = BehaviorClassifier(_FixedVectorEmbedder(vector=[-1.0, 0.0, 0.0]))
    classifier.refresh_anchors(["crypto_symmetric", "crypto_hash"])
    rows = classifier.classify_vec(
        [1.0, 0.0, 0.0], threshold=0.0, top_k=4, block=False
    )
    # cosine is -1.0, strictly below 0.0, so nothing matches.
    assert rows == []


def test_classify_returns_scored_rows_with_backend_and_explain():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    classifier.refresh_anchors(["crypto_symmetric"])
    rows = classifier.classify("some pseudocode to classify", threshold=0.5, top_k=2)
    assert rows
    first = rows[0]
    assert first["behavior"] == "crypto_symmetric"
    assert first["confidence"] == 1.0
    assert first["backend"] == "test"
    assert "explain" in first


def test_classify_falls_back_to_blocking_when_nothing_was_prewarmed():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    # No anchors refreshed: block=False finds nothing, so classify re-runs
    # with block=True and embeds anchors on demand.
    rows = classifier.classify("some pseudocode", threshold=0.5, top_k=2)
    assert len(rows) == 2
    assert all(row["backend"] == "test" for row in rows)


def test_classify_returns_empty_when_embedding_fails():
    class _FailingEmbedder(_FixedVectorEmbedder):
        def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
            return _EmbedResult(None, "unavailable", False)

    classifier = BehaviorClassifier(_FailingEmbedder())
    classifier.refresh_anchors(["crypto_symmetric"])
    assert classifier.classify("pseudocode", threshold=0.5) == []


def test_classify_empty_text_returns_empty():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    assert classifier.classify("") == []
    assert classifier.classify("   ") == []


def test_refresh_anchors_only_warms_named_behaviors():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    classifier.refresh_anchors(["crypto_symmetric", "network_http"])
    with classifier._anchor_lock:
        assert set(classifier._anchor_embs) == {"crypto_symmetric", "network_http"}


def test_clear_cache_invalidates_cached_anchors():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    classifier.refresh_anchors(["crypto_symmetric"])
    assert classifier.classify_vec([1.0, 0.0, 0.0], threshold=0.5, block=False)

    classifier.clear_cache()
    assert classifier.classify_vec([1.0, 0.0, 0.0], threshold=0.5, block=False) == []


def test_refresh_all_anchors_warms_every_category():
    classifier = BehaviorClassifier(_FixedVectorEmbedder())
    classifier.refresh_anchors()
    with classifier._anchor_lock:
        assert set(classifier._anchor_embs) == set(BehaviorClassifier.ANCHORS)


def test_zero_budget_block_embed_returns_without_embedding():
    embedder = _FixedVectorEmbedder()
    classifier = BehaviorClassifier(embedder)
    rows = classifier.classify_vec(
        [1.0, 0.0, 0.0], threshold=0.5, top_k=4, block=True, embed_budget_sec=0.0
    )
    assert rows == []
    assert embedder.embed_calls == []


def test_anchor_cache_persists_across_instances_and_skips_reembed(monkeypatch, tmp_path):
    monkeypatch.setattr("ida_pro_mcp.host.config.CACHE_DIR", str(tmp_path))
    first = BehaviorClassifier(_ModelEmbedder())
    first.refresh_anchors(["crypto_symmetric", "crypto_hash"])
    assert len(first._anchor_embs) == 2
    cache_path = first._cache_path()
    assert os.path.exists(cache_path)

    second = BehaviorClassifier(_ModelEmbedder())
    with second._anchor_lock:
        assert set(second._anchor_embs) == {"crypto_symmetric", "crypto_hash"}
    # A fresh instance must not re-embed what the disk cache restored.
    assert second._embedder.embed_calls == []

    # Clearing the in-memory cache keeps the disk copy; re-warm re-embeds and
    # the file is rewritten (not appended with stale behavior keys).
    second.clear_cache()
    second.refresh_anchors(["crypto_symmetric"])
    with second._anchor_lock:
        assert set(second._anchor_embs) == {"crypto_symmetric"}


def test_anchor_cache_rejected_when_vector_width_mismatches(monkeypatch, tmp_path):
    monkeypatch.setattr("ida_pro_mcp.host.config.CACHE_DIR", str(tmp_path))

    class _WideModelEmbedder(_ModelEmbedder):
        dim = 7

    # A cache written by a 3-dim embedder must not be loaded by a 7-dim one.
    classifier = BehaviorClassifier(_WideModelEmbedder())
    with classifier._anchor_lock:
        assert classifier._anchor_embs == {}
