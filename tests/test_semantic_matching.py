"""Unit tests for deterministic/batched semantic scoring helpers.

These helpers run host-side (no live IDA); the embedder is stubbed at the
``ida_pro_mcp.services`` import boundary so behavior is asserted on inputs
and outputs, not implementation details.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "support" / "semantic_matching.py"


class _FakeEmbedResult:
    def __init__(self, vector):
        self.vector = vector
        self.ok = vector is not None


class _FakeEmbedder:
    """Stub embedder: maps text -> vector; records batched calls."""

    def __init__(self, vectors):
        self._vectors = dict(vectors)
        self.embed_calls: list[list[str]] = []

    def embed_documents(self, texts):
        self.embed_calls.append(list(texts))
        return [_FakeEmbedResult(self._vectors.get(t)) for t in texts]

    def embed_vector(self, text):
        return self._vectors.get(text)

    @staticmethod
    def cosine(a, b):
        if not a or not b:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        na = sum(x * x for x in a) ** 0.5
        nb = sum(y * y for y in b) ** 0.5
        if na <= 1e-12 or nb <= 1e-12:
            return 0.0
        return dot / (na * nb)


def _load(embedder):
    services = types.ModuleType("ida_pro_mcp.services")
    services.BgeCodeEmbedder = lambda: embedder
    pkg = types.ModuleType("ida_pro_mcp")
    pkg.__path__ = []
    sys.modules["ida_pro_mcp"] = pkg
    sys.modules["ida_pro_mcp.services"] = services
    spec = importlib.util.spec_from_file_location("semantic_matching_ut", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_cheap_scoring_is_deterministic_without_embedder():
    sm = _load(None)
    assert sm.semantic_score_cheap("fixture_entry", "fixture_entry") == 120.0
    assert sm.semantic_score_cheap("fixture_entry", "fixture_leaf") > 0.0
    assert sm.semantic_score_cheap("fixture_entry", "fixture_leaf") < 120.0
    assert sm.semantic_score_cheap("fixture_entry", "puts") == 0.0
    assert sm.semantic_score_cheap("", "puts") == 0.0


def test_semantic_score_exact_short_circuits_without_embedding():
    embedder = _FakeEmbedder({})
    sm = _load(embedder)
    assert sm.semantic_score("fixture_entry", "fixture_entry") == 120.0
    assert embedder.embed_calls == []


def test_semantic_score_embeds_only_ambiguous_phrase_pairs():
    embedder = _FakeEmbedder({
        "function that prints marker": [1.0, 0.0, 1.0],
        "fixture_entry": [0.9, 0.1, 1.0],
    })
    sm = _load(embedder)
    score = sm.semantic_score("function that prints marker", "fixture_entry")
    assert score > 100.0, "phrase pair should use embedding similarity"
    assert len(embedder.embed_calls) == 1
    assert set(embedder.embed_calls[0]) == {"function that prints marker", "fixture_entry"}

    # Short, unrelated identifiers are deterministic-only: no embed call.
    embedder.embed_calls.clear()
    assert sm.semantic_score("fixture_entry", "puts") == 0.0
    assert embedder.embed_calls == []


def test_semantic_scores_skips_embedding_for_identifier_queries():
    embedder = _FakeEmbedder({})
    sm = _load(embedder)
    scores = sm.semantic_scores(
        "fixture_entry", ["fixture_entry", "fixture_leaf", "main"], top_n=3
    )
    assert scores[0] == 120.0
    assert scores[1] > scores[2]
    assert embedder.embed_calls == [], "identifier queries must not embed per candidate"


def test_semantic_scores_batches_embedding_for_phrase_queries():
    vectors = {
        "function that prints marker": [1.0, 0.0, 1.0],
        "fixture_entry": [0.9, 0.1, 1.0],
        "main": [0.0, 1.0, 0.0],
        "fixture_leaf": [0.0, 0.0, 1.0],
    }
    embedder = _FakeEmbedder(vectors)
    sm = _load(embedder)
    scores = sm.semantic_scores(
        "function that prints marker",
        ["main", "fixture_leaf", "fixture_entry"],
        top_n=3,
    )
    # Embedding rescore lifts the semantically closest candidate to the top.
    assert scores[2] > scores[0]
    assert scores[2] > 100.0
    # Exactly one batched call, containing the query plus the candidates.
    assert len(embedder.embed_calls) == 1
    assert "function that prints marker" in embedder.embed_calls[0]

    # A second call reuses the cache: no new native embedding.
    embedder.embed_calls.clear()
    again = sm.semantic_scores(
        "function that prints marker",
        ["main", "fixture_leaf", "fixture_entry"],
        top_n=3,
    )
    assert again == scores
    assert embedder.embed_calls == []


def test_semantic_scores_respects_top_n_pool():
    vectors = {
        "function that prints marker": [1.0, 0.0, 1.0],
        "main": [0.0, 1.0, 0.0],
        "fixture_entry": [0.9, 0.1, 1.0],
    }
    embedder = _FakeEmbedder(vectors)
    sm = _load(embedder)
    scores = sm.semantic_scores(
        "function that prints marker",
        ["main", "fixture_entry"],
        top_n=1,
    )
    # Only the top-1 pool slot is rescored; the other keeps its cheap score.
    assert scores[1] == 0.0
    assert len(embedder.embed_calls[0]) == 2  # one candidate + query


def test_semantic_scores_skips_embedding_when_winner_is_decisive():
    embedder = _FakeEmbedder({})
    sm = _load(embedder)
    # "fixture entry" matches "fixture_entry" deterministically at 120 while
    # "fixture_leaf" lags far behind, so no costly batch embed is needed.
    scores = sm.semantic_scores(
        "fixture entry",
        ["fixture_entry", "fixture_leaf"],
        top_n=2,
    )
    assert scores[0] == 120.0
    assert embedder.embed_calls == []


def test_winner_gate_does_not_skip_close_contests():
    vectors = {
        "surface marker": [1.0, 0.0],
        "IDA_MCP_AGENT_SURFACE_MARKER": [0.95, 0.1],
        "AGENT_SURFACE_STRING_000": [0.7, 0.7],
    }
    embedder = _FakeEmbedder(vectors)
    sm = _load(embedder)
    scores = sm.semantic_scores(
        "surface marker",
        ["AGENT_SURFACE_STRING_000", "IDA_MCP_AGENT_SURFACE_MARKER"],
        top_n=2,
    )
    assert scores[1] > scores[0], "close contest must be resolved by embedding"
    assert embedder.embed_calls, "close contest must trigger the batch embed"


def test_normalize_action_still_normalizes_fuzzy_actions():
    actions = ("eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops")
    # Small pools (like action lists) are force-embedded in one batch, so the
    # stub needs vectors: "offst" is nearest to "offset".
    vectors = {
        "offst": [1.0, 0.0],
        "offset": [0.98, 0.2],
        "compute": [0.0, 1.0],
        "eval": [0.1, 0.99],
        "convert": [0.0, 1.0],
        "resolve": [0.0, 1.0],
        "deref": [0.0, 1.0],
        "chain": [0.0, 1.0],
        "align": [0.0, 1.0],
        "bitops": [0.0, 1.0],
    }
    sm = _load(_FakeEmbedder(vectors))
    assert sm.normalize_action(
        "offst", actions=actions, aliases={"compute": "eval"}, fallback="eval", threshold=35.0
    ) == "offset"
    assert sm.normalize_action(
        "compute", actions=actions, aliases={"compute": "eval"}, fallback="eval", threshold=35.0
    ) == "eval"
    assert sm.normalize_action(
        "totally-unrelated", actions=actions, aliases={"compute": "eval"}, fallback="eval", threshold=35.0
    ) == "eval"


def test_normalize_action_falls_back_when_embedding_unavailable():
    actions = ("eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops")
    sm = _load(_FakeEmbedder({}))
    # Exact alias still resolves even with no vectors anywhere.
    assert sm.normalize_action(
        "compute", actions=actions, aliases={"compute": "eval"}, fallback="eval", threshold=35.0
    ) == "eval"
