from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.intelligence import advisory
from ida_pro_mcp.host.intelligence.advisory import organize_blackboard
from ida_pro_mcp.host.intelligence.providers import (
    Answer,
    ProviderResponse,
    ProviderUnavailableError,
    Usage,
)


class _Provider:
    config = SimpleNamespace(
        model="fixture-model", max_questions=36, max_input_chars=32_768
    )

    def __init__(self, *, invalid_lane: bool = False):
        self.questions = []
        self.state = None
        self.call_kwargs = {}
        self.invalid_lane = invalid_lane

    def invoke(self, state, questions, **kwargs):
        self.state = state
        self.questions = list(questions)
        self.call_kwargs = dict(kwargs)
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
    assert result["evidence"]["applied"] is False
    assert result["evidence"]["fail_closed_order"]
    assert result["evidence"]["budget_burn"]["total_tokens"] == 2
    assert provider.call_kwargs["operation"] == "blackboard_organize"
    assert provider.call_kwargs["deadline_seconds"] == 8.0
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


def test_organize_blackboard_respects_provider_question_limit_and_interleaves_candidates():
    provider = _Provider()
    provider.config = SimpleNamespace(
        model="fixture-model", max_questions=2, max_input_chars=32_768
    )

    result = organize_blackboard(
        {},
        [
            {"entry_id": "finding-1", "signature": "first", "current_lane": "lane_now"},
            {"entry_id": "finding-2", "signature": "second", "current_lane": "lane_now"},
        ],
        [
            {
                "entry_id": "finding-1",
                "from_address": "0x1000",
                "to_address": "0x1010",
                "from_signature": "xref signature",
            }
        ],
        [],
        provider=provider,
    )

    assert result["ok"] is True
    assert [question.question_id for question in provider.questions] == [
        "finding_0",
        "xref_0",
    ]


def test_organize_blackboard_uses_provider_question_window_without_output_truncation():
    provider = _Provider()
    provider.config = SimpleNamespace(
        model="fixture-model", max_questions=64, max_input_chars=262_144
    )
    findings = [
        {
            "entry_id": f"finding-{index}",
            "signature": f"bounded signature {index}",
            "current_lane": "lane_now",
        }
        for index in range(30)
    ]
    xrefs = [
        {
            "entry_id": f"finding-{index}",
            "from_address": f"0x{0x1000 + index:x}",
            "to_address": f"0x{0x2000 + index:x}",
            "from_signature": f"caller signature {index}",
        }
        for index in range(30)
    ]
    relations = [
        {
            "entry_a": f"finding-{index}",
            "entry_b": f"finding-{index + 1}",
            "shared_terms": f"shared signature {index}",
        }
        for index in range(30)
    ]

    result = organize_blackboard(
        {}, findings, xrefs, relations, provider=provider
    )

    assert result["ok"] is True
    assert len(provider.questions) == 64
    assert len(result["organization"]) == 22
    assert len(result["xrefs"]) == 21
    assert len(result["relations"]) == 21


def test_organize_blackboard_provider_selection_failure_preserves_bounded_evidence(monkeypatch):
    def unavailable(**_kwargs):
        raise ProviderUnavailableError("provider is unavailable")

    monkeypatch.setattr(advisory, "_provider", unavailable)
    result = organize_blackboard(
        {},
        [{"entry_id": "finding-1", "signature": "bounded parser signature"}],
        [],
        [],
    )

    assert result["error"] is True
    assert result["code"] == "PROVIDER_UNAVAILABLE"
    assert result["evidence"]["applied"] is False
    assert result["evidence"]["signatures_seen"] == [
        {"id": "finding_0", "preview": "bounded parser signature"}
    ]
    assert result["message"] == "provider is unavailable"


def test_organize_blackboard_fails_closed_for_provider_limits_and_responses():
    finding = [{"entry_id": "f1", "signature": "packet parser", "current_lane": "lane_now"}]

    bad_config = _Provider()
    bad_config.config = SimpleNamespace(max_questions="invalid", max_input_chars=1000)
    assert organize_blackboard({}, finding, [], [], provider=bad_config)["code"] == "PROVIDER_CONFIG_INVALID"

    tiny_config = _Provider()
    tiny_config.config = SimpleNamespace(model="fixture-model", max_questions=36, max_input_chars=1)
    too_large = organize_blackboard({}, finding, [], [], provider=tiny_config)
    assert too_large["reason"] == "no_candidates_fit_provider_budget"

    invalid_model = _Provider()
    invalid_model.config = SimpleNamespace(model=" ", max_questions=36, max_input_chars=1000)
    invalid_request = organize_blackboard({}, finding, [], [], provider=invalid_model)
    assert invalid_request["reason"] == "no_candidates_fit_provider_budget"

    class MissingAnswer(_Provider):
        def invoke(self, _state, _questions, **_kwargs):
            return ProviderResponse("fixture-model", {}, Usage(1, 1, 2))

    missing = organize_blackboard({}, finding, [], [], provider=MissingAnswer())
    assert missing["error"] is True
    assert missing["code"] == "PROVIDER_PROTOCOL_ERROR"

    class FailedProvider(_Provider):
        def invoke(self, _state, _questions, **_kwargs):
            raise RuntimeError("private provider detail")

    failed = organize_blackboard({}, finding, [], [], provider=FailedProvider())
    assert failed["error"] is True
    assert failed["code"] == "PROVIDER_ERROR"
    assert failed["evidence"]["applied"] is False
    assert "private provider detail" not in str(failed)

    assert advisory._bounded_probability(float("nan")) == 0.0


def test_organize_blackboard_omits_low_confidence_link_scores():
    class LowScores(_Provider):
        def invoke(self, state, questions, **_kwargs):
            self.questions = list(questions)
            return ProviderResponse(
                "fixture-model",
                {
                    question.question_id: Answer(
                        question.question_id,
                        question.type,
                        "keep_current" if question.type == "choice" else 0.0,
                        confidence=0.1,
                    )
                    for question in questions
                },
                Usage(1, 1, 2),
            )

    result = organize_blackboard(
        {},
        [{"entry_id": "f1", "signature": "parser", "current_lane": "lane_now"}],
        [{"entry_id": "f1", "from_address": "0x1000", "to_address": "0x1010"}],
        [{"entry_a": "f1", "entry_b": "f2", "relation": "shared_tag"}],
        provider=LowScores(),
    )
    assert result["ok"] is True
    assert result["organization"] == []
    assert result["xrefs"] == []
    assert result["relations"] == []
