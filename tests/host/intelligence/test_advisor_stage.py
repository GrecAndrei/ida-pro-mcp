"""Focused unit tests for the locked Jev advisor-stage cut."""

from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from ida_pro_mcp.host.analysis.arch_profile import infer_binary_arch_profile
from ida_pro_mcp.host.intelligence.advisor_stage import (
    DETAIL_POOL_CAPS,
    accept_advisory_requested,
    build_evidence_card,
    cap_pool,
    fail_closed,
    invoke_advisor,
    orders_disagree,
    pool_cap,
    run_advisor_stage,
    signature_previews,
)
from ida_pro_mcp.host.intelligence.providers import Answer, ProviderResponse, Question, Usage


def test_pool_sizes_triage_normal_deep():
    assert DETAIL_POOL_CAPS == {"triage": 4, "normal": 8, "deep": 16}
    assert pool_cap("triage") == 4
    assert pool_cap("normal") == 8
    assert pool_cap("deep") == 16
    assert len(cap_pool(list(range(20)), "triage")) == 4
    assert len(cap_pool(list(range(20)), "normal")) == 8
    assert len(cap_pool(list(range(20)), "deep")) == 16


def test_primary_stays_deterministic_and_disagreement_flag():
    primary = ["a", "b", "c", "d"]
    stage = run_advisor_stage(
        primary,
        detail="triage",
        accept_advisory=False,
        score_fn=lambda pool: (list(reversed(pool)), 0.9, {"calls": 1}),
    )
    assert stage["items"] == ["a", "b", "c", "d"]
    assert stage["advisory_order"] == ["d", "c", "b", "a"]
    assert stage["applied"] is False
    assert stage["disagreement"] is True
    assert stage["evidence"]["disagreement"] is True
    assert stage["evidence"]["applied"] is False
    assert stage["evidence"]["fail_closed_order"] == ["a", "b", "c", "d"]


def test_applied_requires_opt_in():
    assert accept_advisory_requested({}) is False
    assert accept_advisory_requested({"accept_advisory": False}) is False
    assert accept_advisory_requested({"accept_advisory": True}) is True
    stage = run_advisor_stage(
        ["a", "b", "c"],
        detail="normal",
        accept_advisory=True,
        score_fn=lambda pool: (["c", "a", "b"], 0.8, {}),
    )
    assert stage["items"] == ["c", "a", "b"]
    assert stage["applied"] is True
    assert orders_disagree(["a", "b", "c"], ["c", "a", "b"])


def test_evidence_card_caps():
    pool = [{"id": i, "signature": ("x" * 80) + str(i)} for i in range(20)]
    card = build_evidence_card(
        signatures_seen=signature_previews(pool),
        budget_burn={"total_tokens": 12},
        confidence=0.77,
        fail_closed_order=[0, 1, 2],
        applied=False,
        disagreement=True,
    )
    assert len(card["signatures_seen"]) == 16
    assert all(len(row["preview"]) <= 64 for row in card["signatures_seen"])
    assert card["budget_burn"]["total_tokens"] == 12
    assert card["confidence"] == 0.77
    assert card["fail_closed_order"] == [0, 1, 2]
    assert card["applied"] is False
    assert card["disagreement"] is True


def test_fail_closed_path():
    stage = fail_closed(
        ["a", "b", "c"],
        detail="normal",
        error={"error": True, "code": "JEV_UNAVAILABLE", "message": "down"},
    )
    assert stage.primary_order == ["a", "b", "c"]
    assert stage.advisory_order is None
    assert stage.applied is False
    assert stage.evidence["applied"] is False
    assert stage.evidence["fail_closed_order"] == ["a", "b", "c"]
    assert stage.error["code"] == "JEV_UNAVAILABLE"

    stage2 = run_advisor_stage(
        ["a", "b"],
        detail="normal",
        accept_advisory=True,
        score_fn=lambda _pool: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert stage2["items"] == ["a", "b"]
    assert stage2["advisory_order"] is None
    assert stage2["applied"] is False
    assert str(stage2["evidence"].get("reason") or "").startswith("fail_closed:")


def test_invoke_advisor_routes_provider_and_keeps_primary():
    class _Provider:
        config = SimpleNamespace(provider_id="jev", mode="jev", model="jev-test")

        def invoke(self, state, questions, **kwargs):
            return ProviderResponse(
                "jev-test",
                {
                    "q0": Answer("q0", "score", 0.1, confidence=0.5),
                    "q1": Answer("q1", "score", 0.9, confidence=0.9),
                },
                Usage(1, 1, 2),
            )

    pool = [{"id": "low"}, {"id": "high"}]
    questions = [
        Question(question_id="q0", type="score", instructions="a", criteria=["x", "y", "z"]),
        Question(question_id="q1", type="score", instructions="b", criteria=["x", "y", "z"]),
    ]

    def _order(response, items):
        return [items[1], items[0]]

    stage = invoke_advisor(
        {},
        questions,
        deterministic_pool=pool,
        detail="normal",
        accept_advisory=False,
        provider=_Provider(),
        advisory_order_from_response=_order,
        confidence_from_response=lambda _r: 0.9,
    )
    assert stage.primary_order == pool
    assert stage.advisory_order == [pool[1], pool[0]]
    assert stage.applied is False
    assert stage.disagreement is True
    assert stage.evidence["budget_burn"]["total_tokens"] == 2


def test_arch_advisory_does_not_write_processor_bitness():
    def fake_advisory(*_args, **_kwargs):
        return {
            "ok": True,
            "choice": "riscv32",
            "processor": "riscv",
            "bitness": 32,
            "endian": "little",
            "confidence": 0.93,
            "source": "provider_advisory",
            "evidence": {"applied": False},
        }

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(os.urandom(256))
        path = tf.name
    try:
        with patch(
            "ida_pro_mcp.host.analysis.arch_profile._jev_raw_architecture_advisory",
            side_effect=fake_advisory,
        ):
            inf = infer_binary_arch_profile(path)
        assert inf.get("processor") in (None, "")
        assert inf.get("bitness") in (None, "")
        assert isinstance(inf.get("advisory"), dict)
        assert inf["advisory"]["processor"] == "riscv"
        assert inf["advisory"]["bitness"] == 32
        assert inf["advisory"].get("applied") is False
        assert "provider advisory" in str(inf.get("warning") or "")
    finally:
        os.unlink(path)
