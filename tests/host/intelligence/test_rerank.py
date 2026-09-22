from __future__ import annotations

import json
from types import SimpleNamespace

from ida_pro_mcp.host.intelligence.providers import (
    Answer,
    ProviderRequest,
    ProviderResponse,
    StateSnapshot,
    Usage,
)
from ida_pro_mcp.host.intelligence.rerank import Reranker


class _Provider:
    def __init__(self, *, max_input_chars: int = 32_768, score: float = 1.0):
        self.config = SimpleNamespace(
            provider_id="jev",
            mode="jev",
            model="jev-latest",
            max_input_chars=max_input_chars,
            max_questions=64,
        )
        self.score = score
        self.state = None
        self.questions = None

    def status(self):
        return {"ready": True}

    def invoke(self, state, questions, **_kwargs):
        self.state = state
        self.questions = list(questions)
        return ProviderResponse(
            "jev-1.13.0",
            {
                question.question_id: Answer(
                    question.question_id,
                    "score",
                    self.score,
                    confidence=0.77,
                )
                for question in self.questions
            },
            Usage(1, 1, 2),
        )


def test_rerank_questions_include_the_candidate_their_scores_refer_to():
    provider = _Provider()
    reranker = Reranker(provider=provider)

    result = reranker.rerank(
        "network socket connection",
        ["socket_connect peer_send", "hash_init compress digest"],
    )

    assert result == [{"index": 0, "score": 0.5}, {"index": 1, "score": 0.5}]
    assert set(provider.state) == {"query_signature"}
    first, second = provider.questions
    assert first.question_id == "doc_0"
    assert second.question_id == "doc_1"
    assert first.instructions["candidate_index"] == 0
    assert second.instructions["candidate_index"] == 1
    assert "socket" in first.instructions["candidate_signature"]
    assert "hash" in second.instructions["candidate_signature"]
    assert first.instructions["candidate_signature"] != second.instructions["candidate_signature"]


def test_rerank_request_respects_configured_serialized_input_limit():
    provider = _Provider(max_input_chars=5_000, score=0.0)
    reranker = Reranker(provider=provider)
    unique_identifiers = " ".join(f"function_segment_{index:03d}" for index in range(40))

    result = reranker.rerank(
        unique_identifiers,
        [unique_identifiers for _ in range(64)],
    )

    assert result
    request = ProviderRequest(
        StateSnapshot.from_mapping(provider.state),
        tuple(provider.questions),
        provider.config.model,
    )
    encoded = json.dumps(request.to_wire(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= provider.config.max_input_chars
    assert len(provider.questions) < 64
