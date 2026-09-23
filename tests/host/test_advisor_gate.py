"""Advisor-stage gate contract (innovator v2)."""

from __future__ import annotations

from ida_pro_mcp.host.intelligence.advisor_gate import (
    DETAIL_POOL_CAPS,
    build_evidence_card,
    orders_disagree,
    pool_cap,
    run_advisor_stage,
)


def test_pool_caps_named():
    assert DETAIL_POOL_CAPS == {"triage": 4, "normal": 8, "deep": 16}
    assert pool_cap("triage") == 4
    assert pool_cap("normal") == 8
    assert pool_cap("deep") == 16
    assert pool_cap("wat") == 8


def test_evidence_card_caps_signatures():
    pool = [f"sig-{i}-" + ("x" * 80) for i in range(20)]
    card = build_evidence_card(
        pool=pool,
        advisory_order=None,
        fail_closed_order=pool[:8],
        applied=False,
        disagreement=False,
    )
    assert len(card["signatures_seen"]) == 16
    assert card["signatures_capped"] is True
    assert all(len(row["preview"]) <= 64 for row in card["signatures_seen"])
    assert card["applied"] is False


def test_primary_stays_deterministic_without_accept():
    primary = ["a", "b", "c", "d"]
    stage = run_advisor_stage(
        primary,
        detail="triage",
        accept_advisory=False,
        score_fn=lambda pool: (list(reversed(pool)), 0.9, {"calls": 1}),
    )
    assert stage["items"] == ["a", "b", "c", "d"][:4]
    assert stage["advisory_order"] == ["d", "c", "b", "a"]
    assert stage["applied"] is False
    assert stage["disagreement"] is True
    assert stage["evidence"]["disagreement"] is True
    assert stage["evidence"]["applied"] is False


def test_accept_advisory_opt_in_applies():
    primary = ["a", "b", "c"]
    stage = run_advisor_stage(
        primary,
        detail="normal",
        accept_advisory=True,
        score_fn=lambda pool: (["c", "a", "b"], 0.8, {}),
    )
    assert stage["items"] == ["c", "a", "b"]
    assert stage["applied"] is True
    assert orders_disagree(["a", "b", "c"], ["c", "a", "b"])


def test_fail_closed_on_score_error():
    stage = run_advisor_stage(
        ["a", "b"],
        detail="normal",
        accept_advisory=True,
        score_fn=lambda _pool: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert stage["items"] == ["a", "b"]
    assert stage["advisory_order"] is None
    assert stage["applied"] is False
    assert stage["evidence"]["reason"].startswith("fail_closed:")


def test_accept_advisory_string_false_is_not_opt_in():
    from ida_pro_mcp.host.intelligence.advisor_stage import accept_advisory_requested

    assert accept_advisory_requested({"accept_advisory": "false"}) is False
    assert accept_advisory_requested({"accept_advisory": False}) is False
    assert accept_advisory_requested({"accept_advisory": "true"}) is True
    assert accept_advisory_requested({"accept_rerank": "false"}) is False
    assert accept_advisory_requested({"accept_rerank": True}) is True
    # raw bool() trap must not be used — "false" string must not apply
    assert bool("false") is True  # documents why we forbid bool(...)
