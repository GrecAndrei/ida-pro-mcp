from __future__ import annotations

import pytest

from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from ida_pro_mcp.host.intelligence.helpers import _EmbedResult


class _UnavailableEmbedder:
    backend = "unavailable"
    dim = 0

    def embed_vector(self, text: str):
        return None


class _FixedEmbedder:
    backend = "test"
    dim = 3

    def embed_vector(self, text: str):
        return [0.0, 0.6, 0.8]


class _BatchResult:
    def __init__(self, vector):
        self.vector = vector


class _BatchEmbedder:
    backend = "test"
    dim = 3

    def embed_batch(self, texts: list[str]):
        return [_BatchResult([0.0, 0.6, 0.8]) for _ in texts]


class _PrefixFailureEmbedder:
    backend = "test"
    dim = 3

    def embed_batch(self, texts: list[str]):
        return [
            _BatchResult([0.0, 0.6, 0.8]) if index < 2 else _BatchResult(None)
            for index, _text in enumerate(texts)
        ]


class _KeywordEmbedder:
    """Deterministic test embedder: text containing a keyword maps to a fixed
    unit vector, so similarity relationships are fully controllable."""

    backend = "test"
    dim = 2

    def _vec(self, text: str) -> list[float]:
        if "alpha" in text:
            return [1.0, 0.0]
        if "gamma" in text:
            return [-1.0, 0.0]
        return [0.0, 1.0]  # beta and everything else

    def embed_vector(self, text: str):
        return self._vec(str(text or ""))

    def embed_query_vector(self, text: str):
        return self._vec(str(text or ""))

    def embed_document(self, text: str):
        return _EmbedResult(self._vec(str(text or "")), self.backend, True)

    def embed_documents(self, texts: list[str]):
        return [_EmbedResult(self._vec(t), self.backend, True) for t in texts]


class _CountingEmbedder(_KeywordEmbedder):
    def __init__(self):
        self.embed_document_calls = 0
        self.embed_documents_calls = 0

    def embed_document(self, text: str):
        self.embed_document_calls += 1
        return super().embed_document(text)

    def embed_documents(self, texts: list[str]):
        self.embed_documents_calls += 1
        return super().embed_documents(texts)


def test_index_does_not_claim_success_when_embedding_is_unavailable(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _UnavailableEmbedder())

    assert index.index("0x401000", "fixture", "fixture pseudocode") is False
    assert index.size == 0


def test_index_persists_a_successful_embedding_for_a_fresh_reader(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    writer = FunctionEmbeddingIndex(db_path, _FixedEmbedder())

    assert writer.index("0x401000", "fixture", "fixture pseudocode") is True
    assert writer.size == 1

    reader = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    assert reader.size == 1


def test_reader_refreshes_rows_written_after_its_cache_was_created(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    reader = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    writer = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    assert reader.size == 0

    assert writer.index("0x401000", "fixture", "fixture pseudocode") is True

    assert reader.refresh_from_disk() == 1


def test_index_many_persists_batch_results_for_a_fresh_reader(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    writer = FunctionEmbeddingIndex(db_path, _BatchEmbedder())

    result = writer.index_many(
        [
            ("0x401000", "first", "first fixture pseudocode", None),
            (
                "0x401100",
                "second",
                "second fixture pseudocode",
                {"func_size": 32, "index_quality": "full"},
            ),
        ]
    )

    assert result == {"indexed": 2, "failed": 0}
    reader = FunctionEmbeddingIndex(db_path, _BatchEmbedder())
    assert reader.size == 2
    assert reader.quality_counts() == {"full": 1, "unknown": 1}


def test_index_many_returns_retry_boundary_after_partial_failure(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _PrefixFailureEmbedder())

    result = index.index_many([
        ("0x401000", "first", "first", None),
        ("0x401100", "second", "second", None),
        ("0x401200", "third", "third", None),
    ])

    assert result == {"indexed": 2, "failed": 1, "resume_after_ea": "0x401100"}
    assert index.size == 2


def test_fast_refresh_does_not_downgrade_an_existing_full_decomp_vector(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    index = FunctionEmbeddingIndex(db_path, _BatchEmbedder())
    assert index.index_many(
        [("0x401000", "target", "deep_behavior_marker full pseudocode", {"index_quality": "full"})]
    ) == {"indexed": 1, "failed": 0}

    assert index.index_many(
        [("0x401000", "renamed_target", "short fast signature", {"index_quality": "fast"})]
    ) == {"indexed": 1, "failed": 0}

    assert index.quality_counts() == {"full": 1}
    matches = index.search_text("deep behavior marker", top_k=5)
    assert matches and matches[0]["name"] == "renamed_target"


def test_lexical_search_normalizes_behavior_verbs_and_print_apis(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _BatchEmbedder())
    index.index_many(
        [
            (
                "0x401000",
                "fixture_entry",
                'int fixture_entry(void) { puts("AGENT_SURFACE_MARKER"); }',
                {"index_quality": "full"},
            ),
            (
                "0x401100",
                "fixture_leaf",
                "int fixture_leaf(int value) { return value + 7; }",
                {"index_quality": "full"},
            ),
        ]
    )

    matches = index.search_text("function that prints the fixed agent surface marker", top_k=2)

    assert matches[0]["name"] == "fixture_entry"
    assert {"print", "puts", "agent", "surface", "marker"}.intersection(matches[0]["matched_tokens"])


def test_semantic_candidates_are_filtered_by_address_range_before_limit(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _BatchEmbedder())
    index.index_many(
        [
            ("0x1000", "global_best", "packet decoder exact marker", None),
            ("0x3f00", "near_low", "packet decoder", None),
            ("0x4100", "near_high", "packet decoder", None),
            ("0x9000", "global_second", "packet decoder exact marker", None),
        ]
    )

    matches = index.search_text(
        "packet decoder exact marker",
        top_k=2,
        address_ranges=[(0x3E00, 0x4201)],
    )

    assert {match["ea"] for match in matches} == {"0x3f00", "0x4100"}


def _index_alpha_beta(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _KeywordEmbedder())
    index.index_many(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", None),
            ("0x2000", "beta_fn", "beta unrelated work", None),
        ]
    )
    return index


def test_similar_vec_ranks_by_cosine(tmp_path):
    index = _index_alpha_beta(tmp_path)

    hits = index.similar_vec([1.0, 0.0], top_k=5, threshold=0.5)
    assert hits[0]["ea"] == "0x1000"
    assert hits[0]["similarity"] == pytest.approx(1.0, abs=1e-6)

    hits_beta = index.similar_vec([0.0, 1.0], top_k=5, threshold=0.5)
    assert hits_beta[0]["ea"] == "0x2000"


def test_similar_vec_excludes_ea(tmp_path):
    index = _index_alpha_beta(tmp_path)

    hits = index.similar_vec([1.0, 0.0], top_k=5, threshold=0.0, exclude_ea="0x1000")
    assert hits and hits[0]["ea"] == "0x2000"


def test_similar_vec_respects_address_ranges(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _KeywordEmbedder())
    index.index_many(
        [
            ("0x1000", "alpha_low", "alpha one", None),
            ("0x3000", "alpha_mid", "alpha two", None),
            ("0x5000", "alpha_high", "alpha three", None),
        ]
    )

    hits = index.similar_vec(
        [1.0, 0.0], top_k=5, threshold=0.5, address_ranges=[(0x2000, 0x4000)]
    )
    assert [h["ea"] for h in hits] == ["0x3000"]


def test_similar_vec_applies_threshold_and_top_k(tmp_path):
    index = _index_alpha_beta(tmp_path)

    # Threshold above 1.0: nothing passes.
    assert index.similar_vec([1.0, 0.0], top_k=5, threshold=1.5) == []
    # top_k=1 returns only the best.
    hits = index.similar_vec([1.0, 0.0], top_k=1, threshold=0.0)
    assert len(hits) == 1
    assert hits[0]["ea"] == "0x1000"


def test_similar_embeds_then_ranks_like_similar_vec(tmp_path):
    index = _index_alpha_beta(tmp_path)

    hits = index.similar("alpha query text", top_k=5, threshold=0.5)
    assert hits and hits[0]["ea"] == "0x1000"
    direct = index.similar_vec([1.0, 0.0], top_k=5, threshold=0.5)
    assert hits[0]["similarity"] == direct[0]["similarity"]


def test_similar_supports_address_ranges_and_exclude(tmp_path):
    index = _index_alpha_beta(tmp_path)

    hits = index.similar("alpha query", top_k=5, threshold=0.0, exclude_ea="0x1000")
    assert hits and hits[0]["ea"] == "0x2000"

    ranged = index.similar("alpha query", top_k=5, threshold=0.5, address_ranges=[(0x0000, 0x2000)])
    assert [h["ea"] for h in ranged] == ["0x1000"]


def test_similar_skips_embedding_when_cache_is_empty(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "empty.embeddings.db"), _CountingEmbedder())
    assert index.similar("alpha query") == []
    assert index.similar("") == []
    assert index.similar("   ") == []
    # Never touched the embedder — the cache being empty short-circuits.
    assert index._embedder.embed_document_calls == 0


def test_search_dispatches_vector_to_similar_vec_and_text_to_hybrid(tmp_path):
    index = _index_alpha_beta(tmp_path)

    vec_hits = index.search([1.0, 0.0], top_k=5, threshold=0.5)
    assert vec_hits and vec_hits[0]["ea"] == "0x1000"

    str_hits = index.search("alpha behavior", top_k=5, threshold=0.0)
    assert str_hits and str_hits[0]["ea"] == "0x1000"
    assert "score" in str_hits[0]


def test_hybrid_search_merges_semantic_and_lexical_with_rank_reason(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _KeywordEmbedder())
    index.index_many(
        [
            ("0x1000", "packet_parse", "alpha packet parse loop", None),
            ("0x2000", "hash_round", "beta hash round mixing", None),
        ]
    )

    hits = index.hybrid_search("alpha packet parse", top_k=5, threshold=0.0)
    assert hits and hits[0]["ea"] == "0x1000"
    assert hits[0]["similarity"] == pytest.approx(1.0, abs=1e-6)
    assert set(hits[0]["rank_reason"]) == {"semantic", "lexical", "token_coverage", "exact"}


def test_hybrid_search_empty_query_returns_empty(tmp_path):
    index = _index_alpha_beta(tmp_path)
    assert index.hybrid_search("") == []


def test_verify_metadata_detects_backend_and_dimension_change(tmp_path):
    index = _index_alpha_beta(tmp_path)
    assert index.verify_metadata(_KeywordEmbedder())["ok"] is True

    class _OtherBackend:
        backend = "unavailable"
        dim = 0

        def embed_vector(self, text):
            return None

    check = index.verify_metadata(_OtherBackend())
    assert check["ok"] is False
    assert "embedding_backend" in check["mismatches"]


def test_needs_rebuild_fires_when_embedding_format_changes(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")

    class _FormatA(_KeywordEmbedder):
        embedding_format = "profile-v1:a"

    index = FunctionEmbeddingIndex(db_path, _FormatA())
    assert index.needs_rebuild(_FormatA()) is False

    class _FormatB(_KeywordEmbedder):
        embedding_format = "profile-v1:b"

    assert index.needs_rebuild(_FormatB()) is True


def test_reader_auto_refreshes_after_rebuild_replaces_rows(tmp_path):
    """A rebuild (rows deleted + rewritten with different vectors) must not
    keep serving stale in-RAM vectors on the next read.

    Regression: after index_batch upgraded an index from fast to full
    quality, search/nl kept ranking against the pre-rebuild vectors because
    the assembler-cached index only refreshed when empty.  The read path
    now notices the DB mtime moved and reloads."""
    import sqlite3
    import time

    db_path = str(tmp_path / "sample.embeddings.db")
    writer = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert writer.index("0x401000", "alpha_fn", "alpha body") is True

    reader = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert reader.size == 1
    hits = reader.similar_vec([1.0, 0.0], top_k=1, threshold=0.0)
    assert hits and hits[0]["ea"] == "0x401000"

    time.sleep(0.01)
    # Simulate a full rebuild: the only row is deleted and rewritten with a
    # different embedding (gamma -> [-1, 0]).
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM func_embeddings")
        conn.commit()
    rebuilder = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert rebuilder.index("0x401000", "gamma_fn", "gamma body") is True

    hits = reader.similar_vec([1.0, 0.0], top_k=1, threshold=0.0)
    assert hits == [], "stale pre-rebuild vectors leaked into the ranking"
