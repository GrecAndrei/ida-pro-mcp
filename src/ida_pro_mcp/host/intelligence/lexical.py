"""Deterministic lexical view over legacy function-index storage."""

from __future__ import annotations

from typing import Any

from .embeddings import FunctionEmbeddingIndex


class _LexicalIdentity:
    backend = "lexical"
    dim = 0
    embedding_format = "lexical"

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict[str, Any]:
        return {"backend": self.backend, "ready": True, "dim": 0}


class LexicalFunctionIndex(FunctionEmbeddingIndex):
    """Read/search existing signature rows without constructing a model.

    Jev is a typed-question provider, not an embedding provider.  This view
    keeps deterministic lexical retrieval and existing SQLite evidence usable;
    vector rows are never compared or regenerated.
    """

    def __init__(self, db_path: str):
        super().__init__(db_path, _LexicalIdentity())

    def _load_cache(self) -> None:
        """Keep legacy vector payloads out of the provider-only cache."""
        with self._cache_refresh_lock, self._cache_lock:
            self._cache = {}
            try:
                from .embeddings import _file_mtime_ns

                self._db_mtime_ns = _file_mtime_ns(self._db_path)
            except OSError:
                self._db_mtime_ns = 0

    @property
    def size(self) -> int:
        """Count signature rows, including rows with no vector payload."""
        try:
            with self._conn() as conn:
                return int(conn.execute("SELECT COUNT(*) FROM func_embeddings").fetchone()[0])
        except Exception:
            return 0

    def needs_rebuild(self, current_embedder: Any, source_fingerprint: str | None = None) -> bool:
        # A lexical read must never delete or rewrite legacy vector evidence.
        return False

    def search(self, query_or_vec: Any, top_k: int = 10, threshold: float = 0.0, exclude_ea: str | None = None, address_ranges=None):
        if isinstance(query_or_vec, (list, tuple)):
            return []
        return self.search_text(
            str(query_or_vec or ""),
            top_k=top_k,
            threshold=threshold,
            exclude_ea=exclude_ea,
            address_ranges=address_ranges,
        )

    def hybrid_search(self, query: str, top_k: int = 10, threshold: float = 0.0, exclude_ea: str | None = None, address_ranges=None):
        return self.search_text(
            query,
            top_k=top_k,
            threshold=threshold,
            exclude_ea=exclude_ea,
            address_ranges=address_ranges,
        )

    def similar(self, pseudocode: str, top_k: int = 5, exclude_ea: str | None = None, threshold: float = 0.0, address_ranges=None):
        return self.search_text(
            pseudocode,
            top_k=top_k,
            threshold=threshold,
            exclude_ea=exclude_ea,
            address_ranges=address_ranges,
        )

    def similar_vec(self, *args, **kwargs):
        return []

    def index(self, *args, **kwargs):
        return super().index(*args, **kwargs)

    def index_many(self, *args, **kwargs):
        return super().index_many(*args, **kwargs)
