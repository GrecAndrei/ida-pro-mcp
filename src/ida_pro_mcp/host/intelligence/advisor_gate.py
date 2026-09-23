"""Compatibility shim — prefer ``advisor_stage`` (innovator v2 gate).

Kept so existing imports of ``advisor_gate`` continue to work this release.
"""

from __future__ import annotations

from .advisor_stage import (
    DETAIL_POOL_CAPS,
    AdvisorStageResult,
    accept_advisory_requested,
    build_evidence_card as _build_evidence_card_stage,
    orders_disagree,
    pool_cap,
    resolve_detail,
    run_advisor_stage,
    signature_previews,
)

_MAX_SIGNATURES = 16
_PREVIEW_CHARS = 64


def build_evidence_card(
    *,
    pool=None,
    advisory_order=None,
    fail_closed_order=None,
    budget_burn=None,
    confidence=None,
    applied: bool = False,
    disagreement: bool = False,
    reason: str | None = None,
    signatures_seen=None,
):
    """Backward-compatible evidence card builder.

    Older call sites pass ``pool=`` / ``fail_closed_order=``; the stage API uses
    ``signatures_seen`` / ``fail_closed_order`` directly.
    """
    if signatures_seen is None and pool is not None:
        signatures_seen = signature_previews(pool)
    card = _build_evidence_card_stage(
        signatures_seen=signatures_seen,
        budget_burn=budget_burn,
        confidence=confidence,
        fail_closed_order=fail_closed_order or [],
        applied=applied,
        disagreement=disagreement,
    )
    if pool is not None:
        card["signatures_capped"] = len(list(pool)) > _MAX_SIGNATURES
    if advisory_order is not None:
        card["advisory_order"] = list(advisory_order)
    else:
        card["advisory_order"] = None
    if reason is not None:
        card["reason"] = reason
    return card


__all__ = [
    "DETAIL_POOL_CAPS",
    "AdvisorStageResult",
    "accept_advisory_requested",
    "build_evidence_card",
    "orders_disagree",
    "pool_cap",
    "resolve_detail",
    "run_advisor_stage",
]
