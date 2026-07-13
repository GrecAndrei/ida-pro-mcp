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


def test_index_many_persists_batch_results_for_a_fresh_reader(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    writer = FunctionEmbeddingIndex(db_path, _BatchEmbedder())

    result = writer.index_many(
        [
            ("0x401000", "first", "first fixture pseudocode", None),
            ("0x401100", "second", "second fixture pseudocode", {"func_size": 32}),
        ]
    )

    assert result == {"indexed": 2, "failed": 0}
    reader = FunctionEmbeddingIndex(db_path, _BatchEmbedder())
    assert reader.size == 2
