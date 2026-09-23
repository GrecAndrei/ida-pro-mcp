"""Single host advisor stage for Jev/custom typed questions.

Contract (innovator product note v2):
- Primary order is always the deterministic pool order.
- Jev lives in sibling ``advisory_order``; ``applied=True`` only on explicit
  opt-in (``accept_advisory=True`` / analyst ack).
- Every advisory result carries an evidence card.
- Pool size is capped by the shared ``detail`` dial: triage=4, normal=8, deep=16.
- Fail closed: provider error/timeout/disabled returns deterministic order with
  ``applied=False`` and ``fail_closed_order`` populated.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .providers import (
    ProviderError,
    Question,
    provider_error_payload,
    resolve_provider,
)

DETAIL_POOL_CAPS: dict[str, int] = {
    "triage": 4,
    "normal": 8,
    "deep": 16,
}
DEFAULT_DETAIL = "normal"
MAX_SIGNATURES_SEEN = 16
MAX_SIGNATURE_PREVIEW = 64


def resolve_detail(detail: Any = None) -> str:
    key = str(detail or DEFAULT_DETAIL).strip().lower()
    return key if key in DETAIL_POOL_CAPS else DEFAULT_DETAIL


def pool_cap(detail: Any = None) -> int:
    return DETAIL_POOL_CAPS[resolve_detail(detail)]


def cap_pool(items: Sequence[Any], detail: Any = None) -> list[Any]:
    """Return the deterministic pool truncated to the detail cap."""
    return list(items)[: pool_cap(detail)]


def _truthy_opt_in(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on", "ack", "accept"}


def accept_advisory_requested(args: Mapping[str, Any] | None = None, *, accept_advisory: Any = None) -> bool:
    """Explicit opt-in only — never soft-default authority."""
    if accept_advisory is not None:
        return _truthy_opt_in(accept_advisory)
    if not isinstance(args, Mapping):
        return False
    if "accept_advisory" in args:
        return _truthy_opt_in(args.get("accept_advisory"))
    # Analyst ack aliases kept narrow on purpose.
    for key in ("advisory_ack", "apply_advisory", "accept_rerank"):
        if key in args:
            return _truthy_opt_in(args.get(key))
    return False


def _preview_text(value: Any, *, limit: int = MAX_SIGNATURE_PREVIEW) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def signature_previews(
    items: Sequence[Any],
    *,
    id_keys: Sequence[str] = ("id", "addr", "ea", "address", "base", "choice", "index"),
    preview_keys: Sequence[str] = ("signature", "preview", "name", "title", "reason", "query_signature"),
) -> list[dict[str, Any]]:
    """Build ≤16 bounded signature entries (id|hash + preview ≤64). Never full blobs."""
    seen: list[dict[str, Any]] = []
    for index, raw in enumerate(items[:MAX_SIGNATURES_SEEN]):
        if isinstance(raw, Mapping):
            item_id = None
            for key in id_keys:
                if raw.get(key) not in (None, ""):
                    item_id = str(raw.get(key))[:128]
                    break
            if item_id is None:
                item_id = str(index)
            preview_src = None
            for key in preview_keys:
                if raw.get(key) not in (None, ""):
                    preview_src = raw.get(key)
                    break
            if preview_src is None:
                preview_src = raw.get("candidate") or raw
            preview = _preview_text(preview_src)
            entry: dict[str, Any] = {"id": item_id, "preview": preview}
            digest = raw.get("hash") or raw.get("sig_hash")
            if digest:
                entry["hash"] = str(digest)[:64]
            seen.append(entry)
        else:
            seen.append({"id": str(index), "preview": _preview_text(raw)})
    return seen


def orders_disagree(
    deterministic_order: Sequence[Any],
    advisory_order: Sequence[Any] | None,
    *,
    key: Callable[[Any], Any] | None = None,
) -> bool:
    if advisory_order is None:
        return False
    if len(deterministic_order) != len(advisory_order):
        return True
    if key is None:
        return list(deterministic_order) != list(advisory_order)
    return [key(item) for item in deterministic_order] != [key(item) for item in advisory_order]


def build_evidence_card(
    *,
    signatures_seen: Sequence[Mapping[str, Any]] | None = None,
    budget_burn: Any = None,
    confidence: Any = None,
    fail_closed_order: Sequence[Any] | None = None,
    applied: bool = False,
    disagreement: bool = False,
) -> dict[str, Any]:
    """Evidence card required on every advisory result."""
    previews = list(signatures_seen or [])[:MAX_SIGNATURES_SEEN]
    cleaned: list[dict[str, Any]] = []
    for row in previews:
        if not isinstance(row, Mapping):
            continue
        entry: dict[str, Any] = {
            "preview": _preview_text(row.get("preview")),
        }
        if row.get("id") not in (None, ""):
            entry["id"] = str(row.get("id"))[:128]
        if row.get("hash") not in (None, ""):
            entry["hash"] = str(row.get("hash"))[:64]
        cleaned.append(entry)
    conf: float | None
    try:
        conf = None if confidence is None else float(confidence)
    except (TypeError, ValueError, OverflowError):
        conf = None
    if conf is not None and math.isnan(conf):
        conf = None
    if conf is not None:
        conf = round(max(0.0, min(1.0, conf)), 4)
    burn = budget_burn
    if burn is None:
        burn = {}
    return {
        "signatures_seen": cleaned,
        "budget_burn": burn,
        "confidence": conf,
        "fail_closed_order": list(fail_closed_order or []),
        "applied": bool(applied),
        "disagreement": bool(disagreement),
    }


def _budget_burn_from_usage(usage: Any) -> dict[str, Any]:
    if usage is None:
        return {}
    if isinstance(usage, Mapping):
        return {
            key: usage.get(key)
            for key in ("input_tokens", "output_tokens", "total_tokens", "estimated_cost_usd")
            if usage.get(key) is not None
        }
    payload: dict[str, Any] = {}
    for key in ("input_tokens", "output_tokens", "total_tokens", "estimated_cost_usd"):
        value = getattr(usage, key, None)
        if value is not None:
            payload[key] = value
    to_dict = getattr(usage, "to_dict", None)
    if callable(to_dict) and not payload:
        try:
            raw = to_dict()
            if isinstance(raw, Mapping):
                return _budget_burn_from_usage(raw)
        except Exception:
            return {}
    return payload


def _order_ids(items: Sequence[Any], *, id_keys: Sequence[str] = ("id", "addr", "ea", "address", "base", "index")) -> list[Any]:
    ordered: list[Any] = []
    for index, raw in enumerate(items):
        if isinstance(raw, Mapping):
            for key in id_keys:
                if raw.get(key) not in (None, ""):
                    ordered.append(raw.get(key))
                    break
            else:
                ordered.append(index)
        else:
            ordered.append(raw)
    return ordered


@dataclass
class AdvisorStageResult:
    """Gate result: primary stays deterministic; advisory is sibling-only."""

    primary_order: list[Any]
    advisory_order: list[Any] | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    response: Any = None
    error: dict[str, Any] | None = None
    pool: list[Any] = field(default_factory=list)
    scores: list[dict[str, Any]] | None = None
    answer: Any = None

    @property
    def applied(self) -> bool:
        return bool((self.evidence or {}).get("applied"))

    @property
    def disagreement(self) -> bool:
        return bool((self.evidence or {}).get("disagreement"))

    def selected_order(self) -> list[Any]:
        if self.applied and self.advisory_order is not None:
            return list(self.advisory_order)
        return list(self.primary_order)

    def to_public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "order": list(self.primary_order),
            "advisory_order": None if self.advisory_order is None else list(self.advisory_order),
            "evidence": dict(self.evidence or {}),
            "applied": self.applied,
            "disagreement": self.disagreement,
        }
        if self.error is not None:
            payload["error"] = dict(self.error)
        if self.scores is not None:
            payload["scores"] = list(self.scores)
        return payload


def fail_closed(
    deterministic_order: Sequence[Any],
    *,
    detail: Any = None,
    signatures: Sequence[Any] | None = None,
    error: Mapping[str, Any] | None = None,
    confidence: Any = None,
    budget_burn: Any = None,
) -> AdvisorStageResult:
    pool = cap_pool(deterministic_order, detail)
    fail_order = _order_ids(pool)
    evidence = build_evidence_card(
        signatures_seen=signature_previews(signatures if signatures is not None else pool),
        budget_burn=budget_burn or {},
        confidence=confidence,
        fail_closed_order=fail_order,
        applied=False,
        disagreement=False,
    )
    return AdvisorStageResult(
        primary_order=list(pool),
        advisory_order=None,
        evidence=evidence,
        error=dict(error) if error else None,
        pool=list(pool),
    )


def _provider(*, provider=None, ledger=None):
    if provider is not None:
        return provider
    if ledger is None:
        from .providers.registry import default_usage_ledger

        ledger = default_usage_ledger()
    return resolve_provider(with_ledger=True, ledger=ledger)


def invoke_advisor(
    state: Mapping[str, Any],
    questions: Sequence[Question],
    *,
    deterministic_pool: Sequence[Any],
    detail: Any = None,
    accept_advisory: Any = False,
    session_id: str = "",
    operation: str = "advisor_stage",
    deadline_seconds: float | None = None,
    provider=None,
    ledger=None,
    signatures: Sequence[Any] | None = None,
    advisory_order_from_response: Callable[[Any, list[Any]], list[Any] | None] | None = None,
    confidence_from_response: Callable[[Any], Any] | None = None,
    scores_from_response: Callable[[Any, list[Any]], list[dict[str, Any]] | None] | None = None,
    answer_from_response: Callable[[Any], Any] | None = None,
) -> AdvisorStageResult:
    """One host gate before any Jev/provider call.

    Caps the deterministic pool by ``detail``, invokes typed questions on that
    pool only, builds the evidence card, and never soft-applies advisory order.
    """
    pool = cap_pool(deterministic_pool, detail)
    fail_order = _order_ids(pool)
    sig_source = signatures if signatures is not None else pool
    opt_in = accept_advisory_requested(accept_advisory=accept_advisory)

    if not questions:
        return fail_closed(
            pool,
            detail=detail,
            signatures=sig_source,
            error={"error": True, "code": "PROVIDER_PROTOCOL_ERROR", "message": "no advisory questions for pool"},
        )

    try:
        selected = _provider(provider=provider, ledger=ledger)
        response = selected.invoke(
            state,
            list(questions),
            session_id=session_id,
            operation=operation,
            deadline_seconds=deadline_seconds,
        )
    except ProviderError as exc:
        return fail_closed(
            pool,
            detail=detail,
            signatures=sig_source,
            error=provider_error_payload(exc),
        )
    except Exception:
        return fail_closed(
            pool,
            detail=detail,
            signatures=sig_source,
            error={"error": True, "code": "PROVIDER_ERROR", "message": "advisory provider request failed"},
        )

    advisory_order: list[Any] | None = None
    if advisory_order_from_response is not None:
        try:
            advisory_order = advisory_order_from_response(response, list(pool))
        except Exception:
            return fail_closed(
                pool,
                detail=detail,
                signatures=sig_source,
                error={"error": True, "code": "PROVIDER_PROTOCOL_ERROR", "message": "advisory order derivation failed"},
                budget_burn=_budget_burn_from_usage(getattr(response, "usage", None)),
            )

    scores = None
    if scores_from_response is not None:
        try:
            scores = scores_from_response(response, list(pool))
        except Exception:
            return fail_closed(
                pool,
                detail=detail,
                signatures=sig_source,
                error={"error": True, "code": "PROVIDER_PROTOCOL_ERROR", "message": "advisory scores derivation failed"},
                budget_burn=_budget_burn_from_usage(getattr(response, "usage", None)),
            )

    answer = None
    if answer_from_response is not None:
        try:
            answer = answer_from_response(response)
        except Exception:
            return fail_closed(
                pool,
                detail=detail,
                signatures=sig_source,
                error={"error": True, "code": "PROVIDER_PROTOCOL_ERROR", "message": "advisory answer derivation failed"},
                budget_burn=_budget_burn_from_usage(getattr(response, "usage", None)),
            )

    confidence = None
    if confidence_from_response is not None:
        try:
            confidence = confidence_from_response(response)
        except Exception:
            confidence = None

    disagree = orders_disagree(pool, advisory_order)
    # applied means the analyst opted in AND there is an advisory order to use.
    applied = bool(opt_in and advisory_order is not None)

    evidence = build_evidence_card(
        signatures_seen=signature_previews(sig_source),
        budget_burn=_budget_burn_from_usage(getattr(response, "usage", None)),
        confidence=confidence,
        fail_closed_order=fail_order,
        applied=applied,
        disagreement=disagree,
    )
    return AdvisorStageResult(
        primary_order=list(pool),
        advisory_order=None if advisory_order is None else list(advisory_order),
        evidence=evidence,
        response=response,
        pool=list(pool),
        scores=scores,
        answer=answer,
    )


def attach_order_fields(
    result: dict[str, Any],
    stage: AdvisorStageResult,
    *,
    primary_key: str = "items",
    advisory_key: str = "advisory_order",
    evidence_key: str = "evidence",
) -> dict[str, Any]:
    """Attach advisory sibling fields without reordering the primary list.

    When ``stage.applied`` is true the primary list is replaced with the
    advisory order (explicit opt-in only).
    """
    if stage.applied and stage.advisory_order is not None:
        result[primary_key] = list(stage.advisory_order)
    elif primary_key in result:
        # Keep whatever deterministic list the caller already placed.
        pass
    else:
        result[primary_key] = list(stage.primary_order)
    result[advisory_key] = None if stage.advisory_order is None else list(stage.advisory_order)
    result[evidence_key] = dict(stage.evidence or {})
    if stage.error is not None:
        result.setdefault("advisory_error", dict(stage.error))
    return result



def run_advisor_stage(
    deterministic_pool: Sequence[Any],
    *,
    detail: Any = "normal",
    accept_advisory: Any = False,
    score_fn=None,
    budget_burn: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """High-level ordering gate used by ranking call sites.

    ``score_fn(pool) -> (ordered_pool, confidence, burn)`` is optional. When
    missing or failing, fail closed to the deterministic order. Primary list is
    only replaced when ``accept_advisory`` is explicitly true.
    """
    primary = cap_pool(deterministic_pool, detail)
    fail_closed_order = list(primary)
    advisory_order = None
    confidence = None
    burn = dict(budget_burn or {})
    reason = None
    opt_in = accept_advisory_requested(accept_advisory=accept_advisory)

    if score_fn is not None and primary:
        try:
            scored = score_fn(primary)
            if isinstance(scored, tuple):
                ordered = scored[0]
                confidence = scored[1] if len(scored) > 1 else None
                extra_burn = scored[2] if len(scored) > 2 else {}
            else:
                ordered, confidence, extra_burn = scored, None, {}
            if ordered:
                advisory_order = list(ordered)[: pool_cap(detail)]
                if isinstance(extra_burn, Mapping):
                    burn.update(extra_burn)
            else:
                reason = "empty_advisory"
        except Exception as exc:
            reason = f"fail_closed:{type(exc).__name__}"
            advisory_order = None

    disagreement = orders_disagree(primary, advisory_order)
    applied = False
    result_items = list(primary)
    if opt_in and advisory_order is not None and reason is None:
        result_items = list(advisory_order)
        applied = True

    if fail_closed_order and isinstance(fail_closed_order[0], Mapping):
        closed_ids = _order_ids(fail_closed_order)
    else:
        closed_ids = list(fail_closed_order)
    card = build_evidence_card(
        signatures_seen=signature_previews(fail_closed_order),
        budget_burn=burn,
        confidence=confidence,
        fail_closed_order=closed_ids,
        applied=applied,
        disagreement=disagreement,
    )
    if reason:
        card["reason"] = reason
    # Keep advisory_order inside evidence for callers that historically read it there.
    card["advisory_order"] = None if advisory_order is None else list(advisory_order)
    card["signatures_capped"] = len(deterministic_pool) > MAX_SIGNATURES_SEEN
    return {
        "items": result_items,
        "advisory_order": None if advisory_order is None else list(advisory_order),
        "evidence": card,
        "applied": applied,
        "disagreement": disagreement,
    }

__all__ = [
    "DEFAULT_DETAIL",
    "DETAIL_POOL_CAPS",
    "MAX_SIGNATURE_PREVIEW",
    "MAX_SIGNATURES_SEEN",
    "AdvisorStageResult",
    "accept_advisory_requested",
    "attach_order_fields",
    "build_evidence_card",
    "cap_pool",
    "fail_closed",
    "invoke_advisor",
    "orders_disagree",
    "pool_cap",
    "resolve_detail",
    "run_advisor_stage",
    "signature_previews",
]
