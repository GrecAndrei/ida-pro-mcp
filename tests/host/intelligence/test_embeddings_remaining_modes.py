"""Boundary coverage for lexical documents and the SQLite embedding index."""

from __future__ import annotations

import re
import sqlite3

import pytest

from ida_pro_mcp.host.intelligence import embeddings as emb
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from tests.host.intelligence.test_function_embedding_index import (
    _BatchEmbedder,
    _FixedEmbedder,
    _KeywordEmbedder,
)


def test_document_and_search_helpers_cover_empty_limits_variants_and_synonyms():
    pattern = re.compile(r"([A-Za-z]+)")
    assert emb._unique_matches(pattern, "Alpha alpha beta", 2) == ["Alpha", "beta"]
    assert emb._unique_matches(pattern, "alpha", 0) == ["alpha"]
    assert emb._sample_pseudocode_lines("", 20) == ""
    assert emb._sample_pseudocode_lines("one line", 0) == ""
    assert emb._sample_pseudocode_lines("one line", 100) == "one line"
    assert len(emb._sample_pseudocode_lines("\n".join("line" + str(i) for i in range(40)), 80)) <= 80

    assert emb._format_document_section("calls", [], 100) == ""
    assert emb._format_document_section("calls", ["x"], 7) == ""
    assert emb._format_document_section("calls", ["long-value"], 12) == "calls: long-"
    assert emb._decomp_operation_features("x %= 2; y[v] ^= 1; z <<= 1; memcpy(a, b, 4);") == [
        "modulo", "array_index", "bitwise_xor", "shift_left", "buffer_copy"
    ]
    assert emb._split_identifier_token("") == []
    assert emb._split_identifier_token("0x401000") == ["0x401000"]
    assert emb._split_identifier_token("123") == ["123"]
    assert emb._split_identifier_token("HTTPServerWorker") == ["http", "server", "worker"]
    assert emb._search_token_forms("bodies") == ["bodies", "body"]
    assert emb._search_token_forms("switches") == ["switches", "switch"]
    assert emb._search_token_forms("writes") == ["writes", "write"]
    assert emb._search_token_forms("writing") == ["writing", "writ", "write"]
    assert emb._weighted_token_score(set(), {"x"}, {}) == (0.0, [])
    score, matched = emb._weighted_token_score({"socket"}, {"network"}, {"socket": 1.0, "network": 1.0})
    assert score > 0 and matched == ["network"]
    assert emb._tokenize_search_text("int x = 7; socket recv 0x401000", max_tokens=2) == ["socket", "recv"]
    assert emb._ea_to_int("0x401000") == 0x401000
    assert emb._ea_to_int("not-an-address") is None
    assert emb._clip_signature("  lots   of   text  ", 20) == "lots of text"
    assert emb._clip_signature("x" * 20, 10) == "xxxxxxx..."


def test_long_document_keeps_identifier_branch_and_all_header_sections():
    identifiers = "\n".join(
        f"unique_identifier_{i}(arg_{i}, 0x{i + 1000:x});" for i in range(220)
    )
    pseudocode = (
        'int dispatch_payload(void) {\n'
        'if (count > 1000) while (count--) { send_packet("MARKER"); }\n'
        f"{identifiers}\n"
        "return 123456;\n}"
    )
    document = emb.build_decomp_document("dispatch_payload", pseudocode, max_chars=2048)
    assert len(document) <= 2048
    assert "function:" in document
    assert "string_literals:" in document
    assert "calls:" in document
    assert "constants:" in document
    assert "behavior_identifiers:" in document
    assert "control_profile:" in document
    assert "MARKER" in document


def test_index_reload_metadata_and_row_helpers_fail_soft(tmp_path, monkeypatch):
    db_path = str(tmp_path / "index.embeddings.db")
    index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
    assert index.index("0x401000", "good", "good body") is True
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO func_embeddings(ea,name,dim,vec_blob) VALUES(?,?,?,?)",
            ("0x402000", "broken", 3, b"x"),
        )
        conn.commit()
    index._load_cache()
    assert set(index._cache) == {"0x401000"}
    assert index._unpack(index._pack([1.0, 2.0])) == pytest.approx([1.0, 2.0])
    assert index._row_meta_for_eas([]) == {}
    assert index._row_docs_for_eas([]) == {}
    assert index._source_idb_path().endswith("index")
    assert index._source_fingerprint()
    assert emb._safe_stat("") == (0, 0)

    monkeypatch.setattr(index, "_conn", lambda: (_ for _ in ()).throw(OSError("closed")))
    assert index.recent_functions() == []
    assert index.quality_counts() == {}
    assert index._row_meta_for_eas(["0x401000"]) == {}
    assert index._row_docs_for_eas(["0x401000"]) == {}
    index._load_cache()
    assert index._cache == {}


def test_index_many_fallbacks_empty_inputs_and_search_edge_rows(tmp_path):
    index = FunctionEmbeddingIndex(str(tmp_path / "index.embeddings.db"), _FixedEmbedder())
    assert index.index_many([]) == {"indexed": 0, "failed": 0}
    assert index.index_many([("not-an-ea", "", "", None)]) == {"indexed": 1, "failed": 0}
    assert index.search_text("!!!") == []
    index.cache_store("not-an-ea", [1.0, 0.0])
    assert index._similarity_candidates(None, [(0, 10)]) == []
    assert index.search(["bad", object()]) == []

    class NoBatch:
        backend = "test"
        dim = 3

        def embed_vector(self, _text):
            return [0.0, 0.6, 0.8]

    fallback = FunctionEmbeddingIndex(str(tmp_path / "fallback.embeddings.db"), NoBatch())
    assert fallback.index("0x5000", "fallback", "fallback text") is True
    assert fallback.size == 1


def test_index_structured_api_and_hybrid_unavailable_paths(tmp_path, monkeypatch):
    index = FunctionEmbeddingIndex(str(tmp_path / "index.embeddings.db"), _KeywordEmbedder())
    assert index.index_many([
        ("0x1000", "alpha", "alpha socket recv", {"func_size": 10}),
        ("0x2000", "beta", "beta file open", {"func_size": 20}),
    ]) == {"indexed": 2, "failed": 0}
    assert index.search_structured({"max_size": 20, "apis": "socket"}, query="alpha", top_k=1)[0]["name"] == "alpha"
    assert index.search_structured({"apis": [" "]}) == []
    assert index.search_structured({"apis": ["socket"]}, query="alpha", top_k=10)

    class Unavailable:
        def embed_query_vector(self, _text):
            return None

    index._embedder = Unavailable()
    lexical_only = index.hybrid_search("alpha socket", top_k=5, threshold=0.0)
    assert lexical_only and lexical_only[0]["similarity"] == 0.0
    assert index.hybrid_search("alpha", threshold=10.0) == []

    monkeypatch.setattr(index, "_conn", lambda: (_ for _ in ()).throw(OSError("db")))
    assert index.search_structured({"min_size": 1}) == []
