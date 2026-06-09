from __future__ import annotations

import hashlib

from ida_pro_mcp.host.intelligence_embeddings import SemanticObject, SemanticObjectIndex


class _FakeEmbedder:
    dim = 8
    backend = "tfidf-fallback"

    def embed(self, text: str):
        # Deterministic simple embedding with token-bucket counts.
        vec = [0.0] * self.dim
        toks = [t.lower() for t in text.split() if t.strip()]
        for t in toks:
            vec[int(hashlib.md5(t.encode("utf-8")).hexdigest(), 16) % self.dim] += 1.0
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        return [x / norm for x in vec]


def test_semantic_object_index_upsert_and_mixed_kind_search(tmp_path):
    db = tmp_path / "semantic.sqlite3"
    idx = SemanticObjectIndex(str(db), _FakeEmbedder())

    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x401000",
            title="parse_http_headers",
            text="recv socket parse http headers user agent",
            metadata={"source": "function"},
        )
    )
    idx.upsert_object(
        SemanticObject(
            kind="gadget",
            stable_ref="0x500010",
            title="pop_rdi_ret",
            text="pop rdi ; ret",
            metadata={"source": "gadget"},
        )
    )

    assert idx.size == 2
    # Mixed kind search should return function hit first for HTTP query.
    rows = idx.search_text("http recv parser", top_k=5, threshold=0.1)
    assert rows
    assert rows[0]["kind"] == "function"
    assert rows[0]["stable_ref"] == "0x401000"

    # Kind filter should isolate gadget results.
    gadget_rows = idx.search_text("pop ret", kind="gadget", top_k=5, threshold=0.1)
    assert gadget_rows
    assert gadget_rows[0]["kind"] == "gadget"
    assert gadget_rows[0]["stable_ref"] == "0x500010"


def test_semantic_object_index_vector_search_and_fallback(tmp_path):
    db = tmp_path / "semantic2.sqlite3"
    idx = SemanticObjectIndex(str(db), _FakeEmbedder())
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x700000",
            title="aes_encrypt_block",
            text="aes sub bytes shift rows mix columns round key",
            metadata={},
        )
    )
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x700100",
            title="file_copy",
            text="open read write file copy buffer",
            metadata={},
        )
    )

    # Vector search should prioritize AES-like query.
    qvec = _FakeEmbedder().embed("aes round key encrypt")
    rows = idx.search_vec(qvec, kind="function", top_k=2, threshold=0.0)
    assert rows
    assert rows[0]["stable_ref"] == "0x700000"

    # Semantic search should return at least one hit and preserve kind metadata.
    sem = idx.semantic_search("encrypt aes block", kind="function", top_k=2, threshold=0.0)
    assert sem
    assert sem[0]["kind"] == "function"


def test_semantic_object_index_title_tokens_and_hybrid_rescue(tmp_path):
    db = tmp_path / "semantic3.sqlite3"
    idx = SemanticObjectIndex(str(db), _FakeEmbedder())
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x800000",
            title="parse_http_headers",
            text="generic state machine",
            metadata={},
        )
    )
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x800100",
            title="copy_file_buffer",
            text="generic state machine",
            metadata={},
        )
    )

    rows = idx.semantic_search("http headers", kind="function", top_k=2, threshold=0.0)

    assert rows
    assert rows[0]["stable_ref"] == "0x800000"
    assert rows[0].get("score", 0) > 0


def test_semantic_object_index_camelcase_synonym_and_rank_reason(tmp_path):
    db = tmp_path / "semantic4.sqlite3"
    idx = SemanticObjectIndex(str(db), _FakeEmbedder())
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x900000",
            title="AESDecryptRoundKey",
            text="generic transform with lookup tables",
            metadata={"source": "name"},
        )
    )
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x900100",
            title="PlainCopyRoutine",
            text="generic transform with lookup tables",
            metadata={},
        )
    )

    rows = idx.semantic_search("crypto cipher decrypt", kind="function", top_k=2, threshold=0.0)

    assert rows
    assert rows[0]["stable_ref"] == "0x900000"
    assert "rank_reason" in rows[0]
    assert set(rows[0].get("matched_tokens") or []).intersection({"aes", "decrypt", "cipher", "crypto"})
