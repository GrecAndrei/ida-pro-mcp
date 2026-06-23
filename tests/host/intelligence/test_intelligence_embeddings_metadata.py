from __future__ import annotations

import sqlite3

from ida_pro_mcp.services import FunctionEmbeddingIndex


class _FakeEmbedder:
    backend = "tfidf-fallback"
    dim = 1536

    def embed(self, text: str):
        # Deterministic fixed-size vector.
        v = [0.0] * self.dim
        v[0] = 1.0 if text else 0.0
        return v

    def status(self, probe: bool = False):
        return {"model_path": "", "server_bin": ""}


def test_embedding_meta_created_and_readable(tmp_path):
    db = tmp_path / "sample.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    meta = idx.metadata()
    assert meta["index_schema_version"] == 2
    assert meta["embedding_backend"] == "tfidf-fallback"
    assert meta["embedding_dim"] == 1536
    assert "source_idb_path" in meta
    assert "source_fingerprint" in meta


def test_old_schema_migrates_with_additive_columns(tmp_path):
    db = tmp_path / "legacy.i64.embeddings.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        """
        CREATE TABLE func_embeddings (
            ea TEXT PRIMARY KEY,
            name TEXT,
            dim INTEGER,
            vec_blob BLOB NOT NULL,
            pseudo_hash TEXT,
            indexed_at REAL
        )
        """
    )
    conn.commit()
    conn.close()

    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    idx.index("0x401000", "sub_401000", "memcpy recv parse")
    cols = {row[1] for row in idx._conn().execute("PRAGMA table_info(func_embeddings)").fetchall()}
    assert "source_kind" in cols
    assert "source_hash" in cols
    assert "signature_hash" in cols


def test_verify_metadata_and_needs_rebuild(tmp_path):
    db = tmp_path / "verify.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    idx.index("0x401000", "sub_401000", "http send recv")
    ok = idx.verify_metadata(_FakeEmbedder())
    assert ok["ok"] is True
    assert idx.needs_rebuild(_FakeEmbedder()) is False

    class _DifferentEmbedder(_FakeEmbedder):
        backend = "bge-code-v1"

    mismatch = idx.verify_metadata(_DifferentEmbedder())
    assert mismatch["ok"] is False
    assert "embedding_backend" in mismatch["mismatches"]
    assert idx.needs_rebuild(_DifferentEmbedder()) is True


def test_capsule_state_contains_embedder_and_index_snapshot(tmp_path):
    db = tmp_path / "capsule.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    idx.index("0x401000", "sub_401000", "http send recv parser")
    idx.index("0x402000", "sub_402000", "aes round key schedule")

    state = idx.capsule_state(
        anchor_metadata={"anchor_hash_sha256": "deadbeef", "anchor_count": 2},
        thresholds={"classification_default": 0.25, "similarity_threshold": 0.55},
        recent_limit=1,
    )

    assert state["backend"] == "tfidf-fallback"
    assert state["embedding_dim"] == 1536
    assert state["index_metadata"]["implementation"] == "FunctionEmbeddingIndex"
    assert state["index_metadata"]["function_count"] == 2
    assert state["anchor_metadata"]["anchor_hash_sha256"] == "deadbeef"
    assert state["thresholds"]["classification_default"] == 0.25
    assert len(state["last_indexed_functions"]) == 1
    assert state["last_indexed_functions"][0]["ea"] in {"0x401000", "0x402000"}


def test_function_embedding_hybrid_search_uses_true_cosine_and_lexical_reason(tmp_path):
    db = tmp_path / "hybrid.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    idx.index("0x401000", "AESDecryptRoundKey", "void f() { uint8_t sbox; round_key(); }")
    idx.index("0x402000", "CopyBuffer", "void g() { memcpy(dst, src, len); }")

    # Deliberately non-normalized query vector. Old dot-product scoring could
    # produce similarities above 1.0; hybrid search should report true cosine.
    rows = idx.search([10.0] + [0.0] * 1535, top_k=2, threshold=0.0)
    assert rows
    assert rows[0]["similarity"] <= 1.0

    hits = idx.hybrid_search("crypto cipher decrypt round", top_k=2, threshold=0.0)
    assert hits
    assert hits[0]["ea"] == "0x401000"
    assert hits[0]["rank_reason"]["lexical"] > 0
    assert set(hits[0].get("matched_tokens") or []).intersection({"aes", "decrypt", "cipher", "crypto", "round"})
