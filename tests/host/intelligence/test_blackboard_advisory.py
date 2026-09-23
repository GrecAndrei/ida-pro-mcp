from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.intelligence.advisory import organize_blackboard
from ida_pro_mcp.host.intelligence.providers import Answer, ProviderResponse, Usage


class _Provider:
    config = SimpleNamespace(
        model="fixture-model", max_questions=36, max_input_chars=32_768
    )

    def __init__(self, *, invalid_lane: bool = False):
        self.questions = []
        self.state = None
        self.invalid_lane = invalid_lane

    def invoke(self, state, questions, **_kwargs):
        self.state = state
        self.questions = list(questions)
        answers = {}
        for question in self.questions:
            if question.type == "choice":
                lane = "made_up" if self.invalid_lane else "lane_facts"
                answers[question.question_id] = Answer(
                    question.question_id, "choice", lane, confidence=0.91
                )
            else:
                answers[question.question_id] = Answer(
                    question.question_id, "score", 2.0, confidence=0.84
                )
        return ProviderResponse("fixture-model", answers, Usage(1, 1, 2))


def test_organize_blackboard_returns_only_bounded_observed_recommendations():
    provider = _Provider()
    result = organize_blackboard(
        {"workspace_signature": "network parser"},
        [
            {
                "entry_id": "finding-1",
                "address": "0x1000",
                "signature": "network parser",
                "category": "general",
                "kind": "finding",
                "status": "open",
                "current_lane": "lane_now",
                "content": "must never be sent",
            }
        ],
        [
            {
                "entry_id": "finding-1",
                "from_address": "0x1000",
                "to_address": "0x1010",
                "direction": "callee",
                "from_signature": "network parser",
                "to_signature": "decode packet",
            }
        ],
        [
            {
                "entry_a": "finding-1",
                "entry_b": "finding-2",
                "relation": "shared_signature",
                "shared_terms": "network parser",
            }
        ],
        provider=provider,
    )

    assert result["ok"] is True
    assert result["organization"] == [
        {
            "entry_id": "finding-1",
            "current_lane": "lane_now",
            "suggested_lane": "lane_facts",
            "confidence": 0.91,
        }
    ]
    assert result["xrefs"][0]["to_address"] == "0x1010"
    assert result["relations"][0]["entry_b"] == "finding-2"
    serialized = str([question.to_wire() for question in provider.questions])
    assert "must never be sent" not in serialized
    assert all("content" not in question.instructions["candidate"] for question in provider.questions)


def test_organize_blackboard_rejects_provider_lanes_outside_fixed_choices():
    result = organize_blackboard(
        {},
        [{"entry_id": "f1", "signature": "parser", "current_lane": "lane_now"}],
        [],
        [],
        provider=_Provider(invalid_lane=True),
    )

    assert result["error"] is True
    assert result["code"] == "PROVIDER_PROTOCOL_ERROR"
