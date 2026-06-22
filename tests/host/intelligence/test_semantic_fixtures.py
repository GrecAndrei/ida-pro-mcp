from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, _extract_signature
from ida_pro_mcp.host.intelligence.embeddings import SemanticObject, SemanticObjectIndex


FIX_DIR = Path(__file__).parent / "fixtures" / "semantic"


class _TokenEmbedder:
    backend = "fake-token"
    dim = 8

    _TOKENS = {
        "crypto": 0,
        "aes": 0,
        "round": 0,
        "key": 0,
        "http": 1,
        "network": 1,
        "recv": 1,
        "overflow": 2,
        "memcpy": 2,
        "decrypt": 3,
        "xor": 3,
        "file": 4,
        "fopen": 4,
        "write": 4,
    }

    def _norm(self, v):
        s = sum(x * x for x in v) ** 0.5 or 1.0
        return [x / s for x in v]

    def embed(self, text: str):
        v = [0.0] * self.dim
        low = (text or "").lower()
        for token, idx in self._TOKENS.items():
            if token in low:
                v[idx] += 1.0
        return self._norm(v)


def _fixture(name: str) -> str:
    return (FIX_DIR / name).read_text(encoding="utf-8")


def test_signature_extractor_removes_noise_tokens():
    pseudo = "int parse_user_input(char *buf, int len) { memcpy(buf, src, len); return 0; }"
    sig = _extract_signature(pseudo)
    assert "parse" in sig
    assert "user" in sig
    assert "input" in sig
    assert "memcpy" not in sig
    assert "int" not in sig


def test_signature_extractor_splits_camelcase_identifiers():
    sig = _extract_signature("void AESDecryptRoundKeySchedule() { MixColumns(state); }")
    low = sig.lower().split()
    assert "decrypt" in low
    assert "round" in low
    assert "key" in low
    assert "mix" in low
    assert "columns" in low


def test_semantic_object_index_mixed_kind_retrieval(tmp_path):
    idx = SemanticObjectIndex(str(tmp_path / "semantic.db"), _TokenEmbedder())
    idx.upsert_object(
        SemanticObject(
            kind="function",
            stable_ref="0x401000",
            title="http_post",
            text=_fixture("http_client.c.txt"),
            metadata={"source": "fixture"},
        )
    )
    idx.upsert_object(
        SemanticObject(
            kind="gadget",
            stable_ref="g1",
            title="xor_decode",
            text=_fixture("string_decrypt.c.txt"),
            metadata={"source": "fixture"},
        )
    )

    rows = idx.semantic_search("http recv headers", kind="function", top_k=3, threshold=0.0)
    assert rows
    assert rows[0]["stable_ref"] == "0x401000"


def test_behavior_classifier_fixture_triage_with_fake_embedder():
    emb = _TokenEmbedder()
    clf = BehaviorClassifier(emb)
    # Override anchors for deterministic fake-token matching in unit test.
    clf.ANCHORS = {
        "network_http": "http recv send headers",
        "crypto_symmetric": "aes round key crypto",
        "buffer_overflow": "stack overflow memcpy",
    }

    rows_http = clf.classify(_fixture("http_client.c.txt"), threshold=0.0, top_k=2, block=True)
    rows_crypto = clf.classify(_fixture("crypto_aes.c.txt"), threshold=0.0, top_k=2, block=True)

    assert rows_http
    assert rows_http[0]["behavior"] == "network_http"
    assert rows_crypto
    assert rows_crypto[0]["behavior"] == "crypto_symmetric"
    assert rows_crypto[0].get("matched_tokens")
