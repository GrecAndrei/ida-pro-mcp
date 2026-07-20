from __future__ import annotations

from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex


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
