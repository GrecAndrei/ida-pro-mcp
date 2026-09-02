"""Deterministic and optional-embedding semantic matching coverage."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_support_module  # noqa: E402


def _module():
    mod = load_support_module("semantic_matching")
    mod._EMBEDDER = None
    mod._EMB_CACHE.clear()
    return mod


def test_tokenization_cache_keys_and_deterministic_scores():
    sm = _module()
    assert sm._cache_key("  GetProcAddress " ) == "getprocaddress"
    assert sm.semantic_tokens("") == []
    assert sm.semantic_tokens("uart0 GPIO_2 getProcAddress x5 0x401000") == [
        "uart0", "uart", "gpio", "get", "proc", "address", "x5", "0x401000"
    ]
    assert sm.semantic_score_cheap("", "x") == 0.0
    assert sm.semantic_score_cheap("x", " ") == 0.0
    assert sm.semantic_score_cheap("same", "same") == 120.0
    assert sm.semantic_score_cheap("alpha", "beta", substring_bonus=0, include_fuzzy=False) == 0.0
    assert sm._ngram_tokens("getProcAddress") == ["get", "proc", "address", "get proc", "proc address"]
    assert sm._edit_similarity("", "x") == 0.0
    assert sm._edit_similarity("same", "same") == 1.0
    assert 0.0 < sm._edit_similarity("cat", "cut") < 1.0
    assert sm._tfidf_cosine_score([], []) == 0.0
    assert sm._phrase_like("short phrase") is True
    assert sm._phrase_like("x" * 24) is True
    assert sm._phrase_like("short") is False


@pytest.mark.parametrize(
    "scores,expected",
    [([], False), ([0.0, 20.0], False), ([95.0], True), ([100.0, 70.0], True), ([100.0, 85.0], False)],
)
def test_winner_decisive_boundaries(scores, expected):
    assert _module()._winner_decisive(scores) is expected


def test_embedding_batch_caches_successes_and_tolerates_failures(monkeypatch):
    sm = _module()

    class Embedder:
        def __init__(self):
            self.calls = []

        def embed_documents(self, texts):
            self.calls.append(texts)
            return [
                SimpleNamespace(ok=True, vector=[1.0, 0.0]),
                SimpleNamespace(ok=False, vector=[1.0]),
                None,
                SimpleNamespace(ok=True, vector=[]),
            ]

    embedder = Embedder()
    sm._EMBEDDER = embedder
    assert sm._embed_batch(["", "one", "two", "three", "four"]) == {"one": [1.0, 0.0]}
    assert embedder.calls == [["one", "two", "three", "four"]]
    assert sm._embed_batch(["ONE"]) == {"one": [1.0, 0.0]}

    embedder.embed_documents = lambda _texts: (_ for _ in ()).throw(RuntimeError("native"))
    assert sm._embed_batch(["uncached"] ) == {}
    sm._EMBEDDER = None
    sm.BgeCodeEmbedder = lambda: (_ for _ in ()).throw(RuntimeError("constructor"))
    assert sm._get_embedder() is None
    assert sm._embed_batch(["x"]) == {}

    class NoBatch:
        pass

    sm._EMBEDDER = NoBatch()
    assert sm._embed_batch(["x"]) == {}
    monkeypatch.setattr(sm, "_EMBEDDER", None)
    monkeypatch.setattr(sm, "BgeCodeEmbedder", None)
    assert sm._get_embedder() is None


def test_semantic_score_uses_embedding_only_for_ambiguous_text(monkeypatch):
    sm = _module()
    calls = []
    monkeypatch.setattr(sm, "_embedding_score", lambda q, c: calls.append((q, c)) or 77.0)
    assert sm.semantic_score("", "x", return_detail=True) == {"score": 0.0, "method": "exact"}
    assert sm.semantic_score("same", "same", return_detail=True) == {"score": 120.0, "method": "exact"}
    decisive = sm.semantic_score("abc", "abc_suffix", substring_bonus=60)
    assert decisive >= 105.0
    assert calls == []
    assert sm.semantic_score("function handles configuration parsing", "config parser") == 77.0
    assert calls
    monkeypatch.setattr(sm, "_embedding_score", lambda *_args: None)
    detail = sm.semantic_score("function handles configuration parsing", "unrelated")
    assert detail >= 0.0
    assert sm.semantic_score("abc", "xyz", include_fuzzy=False) >= 0.0


def test_semantic_scores_covers_identifier_phrase_and_partial_batches(monkeypatch):
    sm = _module()
    assert sm.semantic_scores("q", []) == []
    assert sm.semantic_scores("name", ["name", "other"]) == [120.0, 0.0]

    class Embedder:
        def __init__(self):
            self.calls = []

        def embed_documents(self, texts):
            self.calls.append(texts)
            return [SimpleNamespace(ok=True, vector=[1.0, 0.0]) for _ in texts]

        def cosine(self, left, right):
            return 2.0 if left is right else 0.5

    emb = Embedder()
    sm._EMBEDDER = emb
    monkeypatch.setattr(sm, "_winner_decisive", lambda _scores: False)
    scores = sm.semantic_scores("a long phrase about configuration", ["configuration parser", "other"], top_n=1)
    assert scores[0] == 60.0
    assert len(emb.calls) == 1
    monkeypatch.setattr(emb, "cosine", lambda *_args: (_ for _ in ()).throw(RuntimeError("cosine")))
    assert sm.semantic_scores("another long phrase", ["candidate"], force_embed=True)[0] >= 0.0

    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {})
    fallback = sm.semantic_scores("long phrase query", ["candidate"], force_embed=True)
    assert fallback == sm.semantic_scores("long phrase query", ["candidate"], force_embed=False)


def test_embedding_score_clamps_and_handles_missing_or_bad_cosine(monkeypatch):
    sm = _module()
    emb = SimpleNamespace(cosine=lambda _left, _right: 2.0)
    sm._EMBEDDER = emb
    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {"q": [1], "c": [2]})
    assert sm._embedding_score("q", "c") == 120.0
    monkeypatch.setattr(emb, "cosine", lambda *_args: (_ for _ in ()).throw(ValueError("bad")))
    assert sm._embedding_score("q", "c") is None
    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {"q": [1]})
    assert sm._embedding_score("q", "c") is None


def test_normalize_action_exact_alias_fuzzy_and_fallback(monkeypatch):
    sm = _module()
    actions = ["read", "write"]
    aliases = {"inspect": "read"}
    assert sm.normalize_action("READ", actions=actions, aliases=aliases, fallback="read", threshold=50) == "read"
    assert sm.normalize_action("inspect", actions=actions, aliases=aliases, fallback="write", threshold=50) == "read"
    assert sm.normalize_action(None, actions=actions, aliases=aliases, fallback="write", threshold=50) == "write"
    monkeypatch.setattr(sm, "semantic_scores", lambda *_args, **_kwargs: [80.0, 10.0, 0.0])
    assert sm.normalize_action("reed", actions=actions, aliases=aliases, fallback="write", threshold=50) == "read"
    monkeypatch.setattr(sm, "semantic_scores", lambda *_args, **_kwargs: [1.0, 2.0, 3.0])
    assert sm.normalize_action("unknown", actions=actions, aliases=aliases, fallback="write", threshold=50) == "write"
