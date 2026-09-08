from __future__ import annotations

import pytest

from ida_pro_mcp.host.intelligence import embeddings as embeddings_mod
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


class _RaisingEmbedder:
    backend = "test"
    dim = 3

    def embed_vector(self, text: str):
        raise RuntimeError("synthetic embedding failure")


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


def test_index_many_counts_fallback_embedder_exception_as_failure(tmp_path):
    index = FunctionEmbeddingIndex(
        str(tmp_path / "sample.embeddings.db"), _RaisingEmbedder()
    )

    result = index.index_many([("0x401000", "broken", "broken", None)])

    assert result == {"indexed": 0, "failed": 1, "resume_after_ea": None}
    assert index.size == 0


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
    assert matches
    assert matches[0]["name"] == "renamed_target"


def test_fast_refresh_rename_invalidates_same_process_lexical_idf(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    index = FunctionEmbeddingIndex(db_path, _BatchEmbedder())
    assert index.index_many(
        [
            ("0x401000", "target", "deep behavior marker full pseudocode", {"index_quality": "full"}),
            ("0x401100", "other", "common utility marker", {"index_quality": "full"}),
        ]
    ) == {"indexed": 2, "failed": 0}

    # Warm the in-process IDF snapshot before the higher-quality row is renamed.
    assert index.search_text("deep behavior marker", top_k=5)
    assert index.index_many(
        [("0x401000", "rare_unique", "short fast signature", {"index_quality": "fast"})]
    ) == {"indexed": 1, "failed": 0}

    same_process = index.search_text("rare_unique", top_k=5)
    fresh_reader = FunctionEmbeddingIndex(db_path, _BatchEmbedder())
    fresh_process = fresh_reader.search_text("rare_unique", top_k=5)
    assert same_process and fresh_process
    assert same_process[0]["score"] == pytest.approx(fresh_process[0]["score"])


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


def test_lexical_prefilter_uses_token_boundaries_before_candidate_limit(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _BatchEmbedder())
    rows = [
        (f"0x{i * 0x10:x}", f"strcpy_{i}", "strcpy unrelated work", None)
        for i in range(2000)
    ]
    rows.append(("0x900000", "cpy_target", "cpy target behavior", None))
    assert index.index_many(rows)["indexed"] == len(rows)

    matches = index.search_text("cpy", top_k=5)

    assert matches
    assert matches[0]["name"] == "cpy_target"


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
    assert hits
    assert hits[0]["ea"] == "0x2000"


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
    assert hits
    assert hits[0]["ea"] == "0x1000"
    direct = index.similar_vec([1.0, 0.0], top_k=5, threshold=0.5)
    assert hits[0]["similarity"] == direct[0]["similarity"]


def test_similar_supports_address_ranges_and_exclude(tmp_path):
    index = _index_alpha_beta(tmp_path)

    hits = index.similar("alpha query", top_k=5, threshold=0.0, exclude_ea="0x1000")
    assert hits
    assert hits[0]["ea"] == "0x2000"

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
    assert vec_hits
    assert vec_hits[0]["ea"] == "0x1000"

    str_hits = index.search("alpha behavior", top_k=5, threshold=0.0)
    assert str_hits
    assert str_hits[0]["ea"] == "0x1000"
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
    assert hits
    assert hits[0]["ea"] == "0x1000"
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

    db_path = str(tmp_path / "sample.embeddings.db")
    writer = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert writer.index("0x401000", "alpha_fn", "alpha body") is True

    reader = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert reader.size == 1
    hits = reader.similar_vec([1.0, 0.0], top_k=1, threshold=0.0)
    assert hits
    assert hits[0]["ea"] == "0x401000"

    # Simulate a full rebuild: the only row is deleted and rewritten with a
    # different embedding (gamma -> [-1, 0]).
    # Force the reader's freshness marker behind the on-disk state instead of
    # sleeping to cross a filesystem timestamp boundary.
    reader._db_mtime_ns = -1
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM func_embeddings")
        conn.commit()
    rebuilder = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert rebuilder.index("0x401000", "gamma_fn", "gamma body") is True
    hits = reader.similar_vec([1.0, 0.0], top_k=1, threshold=0.0)
    assert hits == [], "stale pre-rebuild vectors leaked into the ranking"


def test_structured_search_composes_every_metadata_constraint_and_api_filter(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "sample.embeddings.db"), _BatchEmbedder())
    assert index.index_many([
        (
            "0x401000",
            "packet_parser",
            "int packet_parser(int x) { recvfrom(sock, dst, 128, 0, addr, len); return x; }",
            {
                "func_size": 220,
                "bb_count": 6,
                "has_loops": 1,
                "api_count": 3,
                "string_count": 2,
                "segment": ".text",
                "is_thunk": 0,
                "cyclomatic": 7,
            },
        ),
        (
            "0x402000",
            "tiny_thunk",
            "int tiny_thunk(void) { return 0; }",
            {
                "func_size": 32,
                "bb_count": 1,
                "has_loops": 0,
                "api_count": 0,
                "string_count": 0,
                "segment": ".plt",
                "is_thunk": 1,
                "cyclomatic": 1,
            },
        ),
    ]) == {"indexed": 2, "failed": 0}

    rows = index.search_structured(
        {
            "min_size": 200,
            "max_size": 240,
            "min_bb": 5,
            "max_bb": 7,
            "has_loops": True,
            "min_api": 2,
            "max_api": 4,
            "min_strings": 1,
            "max_strings": 3,
            "segment": ".text",
            "is_thunk": False,
            "min_cyclomatic": 6,
            "max_cyclomatic": 8,
            "apis": ["recvfrom"],
        },
        query="packet",
        top_k=10,
    )
    assert len(rows) == 1
    assert rows[0]["ea"] == "0x401000"
    assert rows[0]["has_loops"] is True
    assert rows[0]["is_thunk"] is False
    assert rows[0]["score"] > 0
    assert index.search_structured({"apis": [""]}) == []


def test_embedding_state_metadata_and_cache_views_are_consistent(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    index = FunctionEmbeddingIndex(db_path, _KeywordEmbedder())
    assert index.index("0x401000", "alpha_fn", "alpha behavior") is True

    metadata = index.metadata()
    assert metadata["embedding_backend"] == "test"
    assert metadata["embedding_dim"] == 2
    assert index.recent_functions(limit=1)[0]["ea"] == "0x401000"
    assert index.quality_counts() == {"unknown": 1}
    state = index.build_embedding_state_payload()
    assert state["backend"] == "test"
    assert state["embedding_dim"] == 2
    assert state["index_metadata"]["function_count"] == 1
    assert state["last_indexed_functions"][0]["name"] == "alpha_fn"
    assert index.db_changed_since_load() is False
    assert index.cache_keys() == {"0x401000"}
    assert index.cache_snapshot()[0][0] == "0x401000"
    index.cache_store("0x402000", [0.0, 1.0])
    assert index.size == 2


# ── fallback-arc gap closure (offline; tmp_path only) ─────────────────────


def test_sample_single_line_skips_spread():
    assert "only one line" in embeddings_mod._sample_pseudocode_lines("only one line", 96)


def test_build_document_short_identifier_list():
    doc = embeddings_mod.build_decomp_document("f", "y" * 2000, max_chars=1024)
    assert doc.startswith("function: f")


def test_safe_file_head_sha256_reads_file(tmp_path):
    import hashlib

    target = tmp_path / "head.bin"
    target.write_bytes(b"0123456789abcdef")
    assert embeddings_mod._safe_file_head_sha256(str(target)) == hashlib.sha256(
        b"0123456789abcdef"
    ).hexdigest()
    assert embeddings_mod._safe_file_head_sha256(str(tmp_path / "missing")) == ""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert embeddings_mod._safe_file_head_sha256(str(empty)) == hashlib.sha256(
        b""
    ).hexdigest()
    assert embeddings_mod._safe_file_head_sha256(str(target), max_bytes=0) == (
        hashlib.sha256(b"").hexdigest()
    )


def test_safe_stat_reads_file(tmp_path):
    import os

    target = tmp_path / "sized.bin"
    target.write_bytes(b"12345")
    size, mtime_ns = embeddings_mod._safe_stat(str(target))
    st = os.stat(target)
    assert (size, mtime_ns) == (st.st_size, st.st_mtime_ns)
    assert embeddings_mod._safe_stat(str(tmp_path / "missing")) == (0, 0)


def test_split_identifier_token_skips_empty_chunks():
    assert embeddings_mod._split_identifier_token("_abc") == ["abc"]


def test_tokenize_search_text_second_loop_cap():
    assert embeddings_mod._tokenize_search_text("readBytes writeBytes", max_tokens=6) == [
        "read",
        "bytes",
        "byte",
        "write",
        "readbytes",
        "readbyte",
    ]


def _config_import_interceptor(monkeypatch, handler):
    import builtins

    real_import = builtins.__import__

    def _intercept(name, *args, **kwargs):
        fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist", ())
        handled = handler(str(name), tuple(fromlist or ()))
        if handled is not None:
            if isinstance(handled, Exception):
                raise handled
            return handled
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _intercept)


def test_init_without_config_modules(monkeypatch, tmp_path):
    def _handler(name, fromlist):
        if fromlist == ("CACHE_DIR",) and name in ("config", "host.config"):
            return ImportError("no config module")
        return None

    _config_import_interceptor(monkeypatch, _handler)
    db_path = str(tmp_path / "plain.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    assert index._db_path == db_path


def test_init_falls_back_when_db_unwritable(monkeypatch, tmp_path):
    import hashlib
    import os
    import types

    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")

    def _handler(name, fromlist):
        if fromlist == ("CACHE_DIR",) and name in ("config", "host.config"):
            return types.SimpleNamespace(CACHE_DIR=str(tmp_path))
        return None

    _config_import_interceptor(monkeypatch, _handler)
    db_path = str(tmp_path / "blocker" / "idx.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    digest = hashlib.sha256(os.path.abspath(db_path).encode("utf-8")).hexdigest()[:16]
    expected = os.path.join(str(tmp_path), "fallback_indexes", f"{digest}.embeddings.db")
    assert index._db_path == expected
    assert os.path.isfile(expected)


def test_init_rebuild_failure_reraises(monkeypatch, tmp_path):
    armed = {"rebuild": False}
    original_meta_set = FunctionEmbeddingIndex._meta_set

    def _maybe_boom(self, conn, key, value):
        if armed["rebuild"]:
            raise RuntimeError("txn boom")
        return original_meta_set(self, conn, key, value)

    def _force_rebuild(self, *args, **kwargs):
        armed["rebuild"] = True
        return True

    monkeypatch.setattr(FunctionEmbeddingIndex, "_meta_set", _maybe_boom)
    monkeypatch.setattr(FunctionEmbeddingIndex, "needs_rebuild", _force_rebuild)
    with pytest.raises(RuntimeError, match="txn boom"):
        FunctionEmbeddingIndex(str(tmp_path / "rebuild.db"), _FixedEmbedder())


def test_source_idb_path_without_suffix(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "plain.db"), _FixedEmbedder())
    assert index._source_idb_path() == str(tmp_path / "plain.db")


def test_source_fingerprint_stats_real_file(tmp_path):
    import hashlib
    import os

    src = tmp_path / "firmware"
    src.write_bytes(b"fake-idb-bytes")
    index = FunctionEmbeddingIndex(
        str(tmp_path / "firmware.embeddings.db"), _FixedEmbedder()
    )
    st = os.stat(src)
    expected = hashlib.sha256(
        f"{src}:{st.st_size}:{st.st_mtime_ns}".encode()
    ).hexdigest()
    assert index._source_fingerprint() == expected


def test_embedder_meta_snapshot_ignores_status_errors(tmp_path):
    class _StatusBoom:
        backend = "test"
        dim = 3

        def embed_vector(self, text):
            return [0.0, 0.6, 0.8]

        def status(self, probe=False):
            raise RuntimeError("status exploded")

    index = FunctionEmbeddingIndex(str(tmp_path / "snap.db"), _StatusBoom())
    snapshot = index._embedder_meta_snapshot()
    assert snapshot["embedding_backend"] == "test"
    assert snapshot["embedding_dim"] == "3"


def test_verify_metadata_garbage_schema(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "meta.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    with sqlite3.connect(db_path) as conn:
        index._meta_set(conn, "index_schema_version", "junk")
        conn.commit()
    check = index.verify_metadata(_FixedEmbedder())
    assert check["ok"] is False
    assert check["mismatches"]["index_schema_version"]["stored"] == 0


def test_verify_metadata_garbage_dimension(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "metadim.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    with sqlite3.connect(db_path) as conn:
        index._meta_set(conn, "embedding_dim", "junk")
        conn.commit()
    check = index.verify_metadata(_FixedEmbedder())
    assert check["ok"] is False
    assert check["mismatches"]["embedding_dim"]["stored"] == 0


def test_init_relative_db_path_skips_makedirs(monkeypatch, tmp_path):
    import os

    monkeypatch.chdir(tmp_path)
    index = FunctionEmbeddingIndex("relative.db", _FixedEmbedder())
    assert index._db_path == "relative.db"
    assert os.path.isfile(tmp_path / "relative.db")


def test_embedder_meta_snapshot_prefers_status_paths(tmp_path):
    class _StatusPaths:
        backend = "test"
        dim = 3

        def embed_vector(self, text):
            return [0.0, 0.6, 0.8]

        def status(self, probe=False):
            return {"model_path": "/models/m.gguf", "server_bin": "/bin/srv"}

    index = FunctionEmbeddingIndex(str(tmp_path / "statuspaths.db"), _StatusPaths())
    snapshot = index._embedder_meta_snapshot()
    assert snapshot["model_path"] == "/models/m.gguf"
    assert snapshot["server_bin"] == "/bin/srv"


def test_metadata_coerces_numeric_fields(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "coerce.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    metadata = index.metadata()
    assert metadata["index_schema_version"] == 4
    assert isinstance(metadata["embedding_dim"], int)
    assert isinstance(metadata["model_size"], int)
    assert isinstance(metadata["server_size"], int)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM embedding_meta WHERE key IN ('model_size', 'server_size')")
        conn.commit()
    sparse = index.metadata()
    assert "model_size" not in sparse
    assert "server_size" not in sparse


# ── index_many / index_async gap closure ──────────────────────────────────


def test_needs_rebuild_compares_explicit_fingerprint(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "fp.db"), _FixedEmbedder())
    assert index.needs_rebuild(_FixedEmbedder(), source_fingerprint="abc") is True


def test_index_many_keeps_higher_quality_row_without_rename(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "quality.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    first = index.index_many(
        [("0x1000", "keep_fn", "alpha behavior decode", {"index_quality": "full"})]
    )
    assert first["indexed"] == 1
    second = index.index_many([("0x1000", "keep_fn", "alpha behavior decode", None)])
    assert second == {"indexed": 1, "failed": 0}
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name, index_quality FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()
    assert row == ("keep_fn", "full")


def test_index_many_refreshes_metadata_on_unchanged_row(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "refresh.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    result = index.index_many(
        [("0x1000", "alpha_fn", "alpha behavior decode", {"func_size": 7})]
    )
    assert result == {"indexed": 1, "failed": 0}
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT func_size FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()
    assert row == (7,)


def test_index_many_updates_tokens_on_rename(tmp_path):
    import sqlite3

    db_path = str(tmp_path / "rename.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    result = index.index_many(
        [("0x1000", "renamed_fn", "alpha behavior decode", None)]
    )
    assert result == {"indexed": 1, "failed": 0}
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()
    assert row == ("renamed_fn",)


def test_index_many_batch_failure_falls_back_to_rows(tmp_path):
    class _BatchBoomEmbedder:
        backend = "test"
        dim = 3

        def embed_documents(self, texts):
            raise RuntimeError("batch down")

        def embed_vector(self, text):
            return [0.0, 0.6, 0.8]

    index = FunctionEmbeddingIndex(str(tmp_path / "batchboom.db"), _BatchBoomEmbedder())
    result = index.index_many(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", None),
            ("0x2000", "beta_fn", "beta unrelated work", None),
        ]
    )
    assert result["indexed"] == 2
    assert result["failed"] == 0


def test_index_many_without_vector_embedder_marks_failed(tmp_path):
    import types

    index = FunctionEmbeddingIndex(
        str(tmp_path / "novec.db"), types.SimpleNamespace(backend="x", dim=3)
    )
    result = index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    assert result == {"indexed": 0, "failed": 1, "resume_after_ea": None}


def test_index_many_persist_failure_reports_ready_prefix(tmp_path):
    class _UnpackableEmbedder:
        backend = "test"
        dim = 3

        def embed_vector(self, text):
            return ["a", "b", "c"]

    index = FunctionEmbeddingIndex(
        str(tmp_path / "unpackable.db"), _UnpackableEmbedder()
    )
    result = index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    assert result == {"indexed": 0, "failed": 1, "resume_after_ea": None}


def test_index_many_reports_resume_after_prefix(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "resume.db"), _PrefixFailureEmbedder())
    result = index.index_many(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", None),
            ("0x2000", "beta_fn", "beta unrelated work", None),
            ("0x3000", "gamma_fn", "gamma third task", None),
        ]
    )
    assert result == {"indexed": 2, "failed": 1, "resume_after_ea": "0x2000"}


def test_index_async_returns_early_on_cache_hit(monkeypatch, tmp_path):
    import threading

    index = FunctionEmbeddingIndex(str(tmp_path / "asyncearly.db"), _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])

    def _boom(*args, **kwargs):
        raise AssertionError("must not spawn a thread on cache hit")

    monkeypatch.setattr(threading, "Thread", _boom)
    assert index.index_async("0x1000", "alpha_fn", "alpha behavior decode") is None


def test_index_async_survives_db_check_error(monkeypatch, tmp_path):
    import sqlite3

    index = FunctionEmbeddingIndex(str(tmp_path / "asyncflaky.db"), _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    calls = {"count": 0}
    real_conn = index._conn

    def _flaky():
        calls["count"] += 1
        if calls["count"] == 1:
            raise sqlite3.OperationalError("locked")
        return real_conn()

    monkeypatch.setattr(index, "_conn", _flaky)
    assert index.index_async("0x1000", "alpha_fn", "alpha behavior decode") is None
    assert calls["count"] >= 1
    index._async_gate.acquire()
    index._async_gate.release()


def test_index_async_saturated_gate_runs_inline(monkeypatch, tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "asyncsat.db"), _FixedEmbedder())
    for _ in range(4):
        index._async_gate.acquire()
    try:
        assert (
            index.index_async("0x1000", "alpha_fn", "alpha behavior decode") is None
        )
    finally:
        for _ in range(4):
            index._async_gate.release()
    assert index.size == 1


def test_similarity_candidates_empty_index(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "empty.db"), _FixedEmbedder())
    assert index._similarity_candidates(None, None) == []


# ── search_text / hybrid / structured gap closure ─────────────────────────


class _AlphaEmbedder:
    """Dim-2 keyword embedder with full query/document method coverage."""

    backend = "test"
    dim = 2

    def _vec(self, text):
        return [1.0, 0.0] if "alpha" in str(text or "") else [0.0, 1.0]

    def embed_vector(self, text):
        return self._vec(text)

    def embed_query_vector(self, text):
        return self._vec(text)

    def embed_document(self, text):
        from ida_pro_mcp.host.intelligence.helpers import _EmbedResult

        return _EmbedResult(self._vec(text), self.backend, True)

    def embed_documents(self, texts):
        from ida_pro_mcp.host.intelligence.helpers import _EmbedResult

        return [_EmbedResult(self._vec(t), self.backend, True) for t in texts]


def _index_alpha_beta_search(tmp_path, name="search.db"):
    index = FunctionEmbeddingIndex(str(tmp_path / name), _AlphaEmbedder())
    index.index_many(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", None),
            ("0x2000", "beta_fn", "beta unrelated work", None),
        ]
    )
    return index


def test_similar_falls_back_to_embed_vector(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "simfb.db"), _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    hits = index.similar("alpha query")
    assert [hit["ea"] for hit in hits] == ["0x1000"]


def test_similar_none_embedding_returns_empty(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "simnone.db"), _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    index._embedder = _UnavailableEmbedder()
    assert index.similar("alpha") == []


def test_search_text_blank_query_returns_empty(tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    assert index.search_text("") == []
    assert index.search_text("   ") == []


def test_search_text_exclude_ea(tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    hits = index.search_text("alpha", exclude_ea="0x2000")
    assert [hit["ea"] for hit in hits] == ["0x1000"]
    assert index.search_text("alpha", exclude_ea="0x1000") == []
    assert [hit["ea"] for hit in index.search_text("alpha", exclude_ea="0x9999")] == [
        "0x1000"
    ]


def test_search_text_punct_row_skipped(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "punct.db"), _FixedEmbedder())
    index.index_many([("0x1000", "!!!", "???", None)])
    assert index.search_text("!!!") == []


def test_search_text_threshold_filters(tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    assert index.search_text("alpha", threshold=99.0) == []


def test_search_text_db_failure_returns_empty(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)

    def _boom():
        raise OSError("db gone")

    monkeypatch.setattr(index, "_conn", _boom)
    assert index.search_text("alpha") == []


def test_search_text_without_phrase_normalization(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    monkeypatch.setattr(embeddings_mod, "_normalize_search_text", lambda text: "")
    hits = index.search_text("alpha beta")
    assert "0x1000" in {hit["ea"] for hit in hits}


class _FakeSearchCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._stamp

    def __iter__(self):
        return iter(self._rows)


class _FakeSearchConn:
    """Serve a fixed stamp (keeps the cached IDF) plus crafted SELECT rows."""

    def __init__(self, stamp, rows):
        self._stamp = stamp
        self._rows = rows

    def execute(self, sql, params=()):
        cursor = _FakeSearchCursor(self._rows)
        cursor._stamp = self._stamp
        return cursor

    def close(self):
        pass


def _search_with_rows(monkeypatch, index, rows):
    import sqlite3

    # Warm the cached IDF with a real search so the fake connection only
    # serves the stamp check plus the crafted SELECT rows.
    assert index.search_text("alpha")
    with sqlite3.connect(index._db_path) as conn:
        stamp = conn.execute(
            "SELECT COUNT(*), COALESCE(MAX(indexed_at), 0.0) FROM func_embeddings"
        ).fetchone()
    stamp = (stamp[0], float(stamp[1]))
    monkeypatch.setattr(index, "_conn", lambda: _FakeSearchConn(stamp, rows))
    return stamp


def _search_row(ea, name, sig, tokens, ea_int=0x1000, indexed_at=1.0):
    return (ea, name, sig, tokens, tokens, indexed_at, ea_int)


def test_search_text_python_exclude_guard(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    rows = [
        _search_row("0x2000", "alpha twin", "alpha twin routine", "alpha twin"),
        _search_row("0x1000", "alpha_fn", "alpha behavior decode", "alpha behavior decode fn"),
    ]
    _search_with_rows(monkeypatch, index, rows)
    hits = index.search_text("alpha", exclude_ea="0x2000")
    assert [hit["ea"] for hit in hits] == ["0x1000"]


def test_search_text_ea_int_fallback(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    rows = [
        _search_row("0x9999", "alpha_fn", "alpha behavior decode", "alpha", ea_int=None),
        _search_row("not-an-ea", "alpha_fn", "alpha behavior decode", "alpha", ea_int=None),
    ]
    _search_with_rows(monkeypatch, index, rows)
    hits = index.search_text("alpha", address_ranges=[(0, 2**40)])
    assert [hit["ea"] for hit in hits] == ["0x9999"]


def test_search_text_out_of_range_guard(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    rows = [_search_row("0x1000", "alpha_fn", "alpha behavior decode", "alpha")]
    _search_with_rows(monkeypatch, index, rows)
    assert index.search_text("alpha", address_ranges=[(0x2000, 0x3000)]) == []


def _insert_blank_ea_row(index, name, signature_text, search_tokens):
    import sqlite3

    with sqlite3.connect(index._db_path) as conn:
        conn.execute(
            "INSERT INTO func_embeddings(ea, name, dim, vec_blob, pseudo_hash, indexed_at,"
            " source_kind, source_hash, signature_text, signature_hash, document_text,"
            " ea_int, search_tokens, name_tokens)"
            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "", name, 2, index._pack([1.0, 0.0]), "ph", 1.0, "function", "sh",
                signature_text, "sighash", signature_text or "doc", 0, search_tokens,
                search_tokens,
            ),
        )
        conn.commit()


def test_search_text_empty_blob_skipped(tmp_path):
    index = _index_alpha_beta_search(tmp_path, name="emptyblob.db")
    _insert_blank_ea_row(index, "", "", "alpha marker")
    eas = {hit["ea"] for hit in index.search_text("alpha")}
    assert "0x1000" in eas
    assert "" not in eas


def test_hybrid_skips_empty_ea_hits(tmp_path):
    index = _index_alpha_beta_search(tmp_path, name="hybridempty.db")
    _insert_blank_ea_row(
        index, "alpha marker", "alpha marker routine", "alpha marker"
    )
    assert "" in {hit["ea"] for hit in index.search_text("alpha")}
    index.cache_store("", [1.0, 0.0])
    hits = index.hybrid_search("alpha")
    assert hits
    assert all(hit["ea"] for hit in hits)
    assert "0x1000" in {hit["ea"] for hit in hits}


def test_hybrid_backfills_missing_signature(monkeypatch, tmp_path):
    index = _index_alpha_beta_search(tmp_path)
    monkeypatch.setattr(
        index,
        "similar_vec",
        lambda *args, **kwargs: [
            {"ea": "0x1000", "name": "alpha_fn", "similarity": 1.0, "signature": ""}
        ],
    )
    hits = index.hybrid_search("alpha")
    assert hits[0]["ea"] == "0x1000"
    assert hits[0]["signature"] != ""


def test_index_many_iterator_input_skips_resume_scan(tmp_path):
    index = FunctionEmbeddingIndex(
        str(tmp_path / "resumeiter.db"), _PrefixFailureEmbedder()
    )
    rows = iter(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", None),
            ("0x2000", "beta_fn", "beta unrelated work", None),
            ("0x3000", "gamma_fn", "gamma third task", None),
        ]
    )
    result = index.index_many(rows)
    assert result == {"indexed": 2, "failed": 1, "resume_after_ea": None}


def test_index_async_stale_row_reindexes_inline(monkeypatch, tmp_path):
    import sqlite3

    db_path = str(tmp_path / "asyncstale.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    index.index_many([("0x1000", "alpha_fn", "alpha behavior decode", None)])
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE func_embeddings SET pseudo_hash=? WHERE ea=?", ("stale", "0x1000")
        )
        conn.commit()
    for _ in range(4):
        index._async_gate.acquire()
    try:
        assert (
            index.index_async("0x1000", "alpha_fn", "alpha behavior decode") is None
        )
    finally:
        for _ in range(4):
            index._async_gate.release()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT pseudo_hash FROM func_embeddings WHERE ea=?", ("0x1000",)
        ).fetchone()
    assert row[0] != "stale"


def test_search_structured_without_apis(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "structured.db"), _FixedEmbedder())
    index.index_many(
        [
            ("0x1000", "alpha_fn", "alpha behavior decode", {"func_size": 5}),
            ("0x2000", "beta_fn", "beta unrelated work", {"func_size": 0}),
        ]
    )
    rows = index.search_structured({"min_size": 1})
    assert [row["ea"] for row in rows] == ["0x1000"]


def test_search_structured_apis_without_rows(tmp_path):
    index = FunctionEmbeddingIndex(
        str(tmp_path / "structuredempty.db"), _FixedEmbedder()
    )
    assert index.search_structured({"apis": ["socket"]}) == []


def test_search_structured_apis_fetch_failure_empties(monkeypatch, tmp_path):
    import sqlite3

    index = FunctionEmbeddingIndex(
        str(tmp_path / "structuredapis.db"), _FixedEmbedder()
    )
    index.index_many(
        [("0x1000", "alpha_fn", "socket(AF_INET, 0) alpha", {"func_size": 5})]
    )
    assert index.search_structured({"apis": ["socket"]})
    calls = {"count": 0}
    real_conn = index._conn

    def _flaky():
        calls["count"] += 1
        if calls["count"] == 2:
            raise sqlite3.OperationalError("locked")
        return real_conn()

    monkeypatch.setattr(index, "_conn", _flaky)
    assert index.search_structured({"apis": ["socket"]}) == []
