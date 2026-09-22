"""Provider-neutral typed-question contracts.

The provider layer deliberately carries only bounded, structured data.  It does
not persist prompts or completions and it never turns provider output into an
authorization decision.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

MAX_STATE_CHARS = 32_768
MAX_TEXT_CHARS = 8_192
MAX_QUESTION_CHARS = 2_048
MAX_QUESTIONS = 64
MAX_RESPONSE_BYTES = 1_048_576

_SECRET_KEY_RE = re.compile(
    r"(?:api[_-]?key|credential|private[_-]?key|secret|password|passwd|token|authorization|cookie|prompt|completion|raw[_-]?(?:request|response))",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|(?:api[_-]?key|secret|token|password|authorization)\s*[:=]\s*[^\s,;]+"
)

_SENSITIVE_CONTEXT_KEYS = {
    "pseudocode",
    "pseudocode_text",
    "pseudo",
    "pseudo_code",
    "decomp",
    "decompilation",
    "decompilation_text",
    "decompiled",
    "decompiled_text",
    "decompiler_output",
    "source_text",
    "source",
    "source_code",
    "source_code_text",
    "raw",
    "raw_code",
    "raw_text",
    "raw_output",
    "document",
    "document_text",
    "function_body",
    "function_code",
    "function_text",
    "code",
    "code_text",
    "body",
    "content",
    "comment",
    "comments",
    "output",
    "result",
    "decompile",
    "decompile_text",
    "decompiled_code",
    "hexrays",
    "ctree",
    "literals",
    "literal",
    "strings",
    "string_literals",
    "raw_decompilation",
}


class ProviderError(RuntimeError):
    """Base provider failure with a stable, safe error code.

    ``message`` is intentionally supplied by the caller from a constant or a
    sanitized value.  Provider response bodies and request content must never
    be attached to this exception.
    """

    code = "PROVIDER_ERROR"
    recoverable = False

    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None):
        safe_message = _SECRET_VALUE_RE.sub("<redacted>", str(message))[:512]
        super().__init__(safe_message)
        self.message = safe_message
        self.details = _safe_details(details or {})


class ProviderUnavailableError(ProviderError):
    code = "PROVIDER_UNAVAILABLE"
    recoverable = True


class JevUnavailableError(ProviderUnavailableError):
    code = "JEV_UNAVAILABLE"


class ProviderConfigError(ProviderError):
    code = "PROVIDER_CONFIG_INVALID"


class ProviderProtocolError(ProviderError):
    code = "PROVIDER_PROTOCOL_ERROR"


class DataPolicyError(ProviderError):
    code = "DATA_POLICY_BLOCKED"


class ProviderTimeoutError(ProviderError):
    code = "PROVIDER_TIMEOUT"
    recoverable = True


class ProviderAuthError(ProviderError):
    code = "PROVIDER_AUTH_FAILED"


class ProviderBudgetError(ProviderError):
    code = "BUDGET_EXCEEDED"


class IntelligenceDisabledError(ProviderError):
    code = "INTELLIGENCE_DISABLED"


class CapabilityUnavailableError(ProviderError):
    code = "CAPABILITY_UNAVAILABLE"


def _safe_details(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep exception details scalar and secret-free."""
    result: dict[str, Any] = {}
    blocked_names = {"body", "content", "payload", "request", "response", "state", "text"}
    for key, item in value.items():
        name = str(key)
        if _SECRET_KEY_RE.search(name) or name.lower() in blocked_names:
            continue
        if isinstance(item, str):
            result[name] = _SECRET_VALUE_RE.sub("<redacted>", _safe_string(item, 512))
        elif isinstance(item, (int, float, bool)) or item is None:
            if isinstance(item, float) and not math.isfinite(item):
                continue
            result[name] = item
        elif isinstance(item, (list, tuple)):
            safe = []
            for entry in item[:16]:
                if isinstance(entry, str):
                    safe.append(_SECRET_VALUE_RE.sub("<redacted>", _safe_string(entry, 256)))
                elif isinstance(entry, (int, float, bool)) or entry is None:
                    safe.append(entry)
            result[name] = safe
    return result


def _safe_string(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    text = str(value or "").replace("\x00", "")
    return text[: max(0, int(limit))]


def _public_label(value: Any, limit: int = 256) -> str | None:
    text = _safe_string(value, limit).replace("\r", " ").replace("\n", " ")
    return "<redacted>" if _SECRET_KEY_RE.search(text) else (text or None)


def _compact_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Bound JSON-like context and drop sensitive/raw fields by default."""
    if depth > 5 or _SECRET_KEY_RE.search(key):
        return None
    if key.lower() in _SENSITIVE_CONTEXT_KEYS:
        return None
    if isinstance(value, str):
        text = _safe_string(value, MAX_TEXT_CHARS if depth < 2 else 2_048)
        if _SECRET_VALUE_RE.search(text):
            return None
        return text
    if isinstance(value, (int, bool)) or value is None:
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:128]:
            child_key = str(raw_key)
            compact = _compact_value(item, key=child_key, depth=depth + 1)
            if compact is not None:
                result[child_key] = compact
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for item in list(value)[:128]:
            compact = _compact_value(item, key=key, depth=depth + 1)
            if compact is not None:
                result.append(compact)
        return result
    # Provider state is JSON-like by contract.  Do not stringify arbitrary
    # objects: their repr can contain paths, credentials, or raw IDA data.
    return None


def compact_state(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return compact, redacted provider context.

    Full decompilation and literal dumps are deliberately excluded.  Callers
    can provide bounded disassembly, bytes, metadata, signatures, and IDs.
    """
    if not isinstance(value, Mapping):
        raise ProviderProtocolError("provider state must be an object")
    compact = _compact_value(value)
    if not isinstance(compact, dict):
        raise ProviderProtocolError("provider state must be an object")
    return compact


@dataclass(frozen=True)
class StateSnapshot:
    """Bounded structured state sent to a provider."""

    values: dict[str, Any]
    provenance: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validate direct construction as well as the ``from_mapping`` factory;
        # callers must not be able to bypass the raw-content and size guards by
        # instantiating the dataclass directly.
        compact = compact_state(self.values)
        if not isinstance(self.provenance, Mapping):
            raise ProviderProtocolError("provider provenance must be an object")
        import json

        encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_STATE_CHARS:
            raise ProviderProtocolError("provider state exceeds the compact context limit")
        safe_provenance: dict[str, str] = {}
        for key, value in (self.provenance or {}).items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                continue
            value_text = _safe_string(value, 256)
            if _SECRET_VALUE_RE.search(value_text):
                value_text = "<redacted>"
            safe_provenance[key_text] = value_text
        object.__setattr__(self, "values", compact)
        object.__setattr__(self, "provenance", safe_provenance)

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        provenance: Mapping[str, Any] | None = None,
    ) -> "StateSnapshot":
        if not isinstance(value, Mapping):
            raise ProviderProtocolError("provider state must be an object")
        if provenance is not None and not isinstance(provenance, Mapping):
            raise ProviderProtocolError("provider provenance must be an object")
        return cls(dict(value), dict(provenance or {}))

    def to_wire(self) -> dict[str, Any]:
        return dict(self.values)


@dataclass(frozen=True)
class Question:
    question_id: str
    type: str
    instructions: Any
    criteria: Any = None

    def __post_init__(self) -> None:
        question_id = self.question_id if isinstance(self.question_id, str) else ""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", question_id):
            raise ProviderProtocolError("question ids must be short stable identifiers")
        kind = self.type if isinstance(self.type, str) else ""
        if kind not in {"noul", "choice", "score"}:
            raise ProviderProtocolError("unsupported typed-question kind")
        if not isinstance(self.instructions, (str, Mapping, list, tuple)):
            raise ProviderProtocolError("question instructions must be a bounded JSON value")
        compact_instructions = _compact_value(self.instructions, depth=1)
        if compact_instructions in (None, "", {}, []):
            raise ProviderProtocolError("question instructions must be non-empty")
        import json

        if len(json.dumps(compact_instructions, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_QUESTION_CHARS:
            raise ProviderProtocolError("question instructions exceed the compact limit")
        if kind == "choice":
            if not isinstance(self.criteria, (Mapping, list, tuple)) or not self.criteria:
                raise ProviderProtocolError("choice questions require criteria")
            if len(self.criteria) > 64:
                raise ProviderProtocolError("choice criteria is too large")
        if kind in {"choice", "score"}:
            compact_criteria = _compact_value(self.criteria, depth=1)
            if compact_criteria in (None, "", {}, []):
                raise ProviderProtocolError("question criteria must be non-empty")
            if len(json.dumps(compact_criteria, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_QUESTION_CHARS:
                raise ProviderProtocolError("question criteria exceed the compact limit")
        if kind == "score":
            if isinstance(self.criteria, Mapping):
                if set(self.criteria) != {"min", "max"}:
                    raise ProviderProtocolError("score question bounds must contain min and max")
                try:
                    lower = float(self.criteria["min"])
                    upper = float(self.criteria["max"])
                except (TypeError, ValueError):
                    raise ProviderProtocolError("score question bounds are malformed") from None
                if not math.isfinite(lower) or not math.isfinite(upper) or lower >= upper:
                    raise ProviderProtocolError("score question bounds are malformed")
            elif not isinstance(self.criteria, (list, tuple)) or not 2 <= len(self.criteria) <= 10:
                raise ProviderProtocolError("score questions require bounds or 2..10 ordered criteria")

    def to_wire(self) -> dict[str, Any]:
        """Return the TypeSafe System One question object.

        Jev identifies questions by the object key in ``questions``; the
        object itself therefore carries no duplicated ``id`` field.  The
        ``instructions``/``criteria`` names are part of the public Jev wire
        contract (and are also the canonical names accepted by custom mode).
        """
        result: dict[str, Any] = {
            "type": str(self.type).lower(),
            "instructions": _compact_value(self.instructions, depth=1),
        }
        if self.criteria is not None:
            criteria = _compact_value(self.criteria, depth=1)
            # TypeSafe Choice criteria are option->description maps.  Accept a
            # bounded list in the provider-neutral helper and normalize it at
            # the wire boundary so Jev receives its native shape.
            if str(self.type).lower() == "choice" and isinstance(criteria, list):
                criteria = {str(option): None for option in criteria[:64]}
            result["criteria"] = criteria
        return result


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated: bool = False

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProviderProtocolError("usage token counts must be non-negative integers")
        if self.total_tokens < self.input_tokens + self.output_tokens:
            raise ProviderProtocolError("usage total_tokens is smaller than its components")

    @classmethod
    def from_wire(cls, value: Any) -> "Usage":
        if not isinstance(value, Mapping):
            raise ProviderProtocolError("provider response usage must be an object")
        raw_input = value.get("input_tokens")
        raw_output = value.get("output_tokens")
        raw_total = value.get("total_tokens", None)
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (raw_input, raw_output)):
            raise ProviderProtocolError("provider response usage is malformed")
        if raw_total is not None and (isinstance(raw_total, bool) or not isinstance(raw_total, int)):
            raise ProviderProtocolError("provider response usage is malformed")
        estimated = value.get("estimated", False)
        if not isinstance(estimated, bool):
            raise ProviderProtocolError("provider response usage estimated flag is malformed")
        return cls(
            input_tokens=raw_input,
            output_tokens=raw_output,
            total_tokens=raw_total if raw_total is not None else raw_input + raw_output,
            estimated=estimated,
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "estimated": self.estimated,
        }


@dataclass(frozen=True)
class Answer:
    question_id: str
    type: str
    value: Any = None
    probability: float | None = None
    probabilities: dict[str, float] | None = None
    legend: dict[str, str] | None = None
    confidence: float | None = None

    @staticmethod
    def _parse_confidence(value: Mapping[str, Any]) -> float | None:
        raw_confidence = value.get("confidence")
        if raw_confidence is None:
            return None
        if isinstance(raw_confidence, bool):
            raise ProviderProtocolError("answer confidence is malformed")
        try:
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            raise ProviderProtocolError("answer confidence is malformed") from None
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ProviderProtocolError("answer confidence is outside 0..1")
        return confidence

    @classmethod
    def from_wire(cls, question_id: str, expected_type: str, value: Any) -> "Answer":
        if not isinstance(value, Mapping):
            raise ProviderProtocolError("provider answer must be an object")
        kind = str(expected_type).lower()
        if str(value.get("type") or kind).lower() != kind:
            raise ProviderProtocolError("provider answer type does not match its question")
        if kind == "choice":
            choice = value.get("choice", value.get("value"))
            if not isinstance(choice, str) or not choice.strip() or len(choice) > 256:
                raise ProviderProtocolError("choice answer is malformed")
            probabilities = value.get("probabilities")
            parsed_probabilities = None
            if probabilities is not None:
                if not isinstance(probabilities, Mapping) or not probabilities or len(probabilities) > 64:
                    raise ProviderProtocolError("choice answer probabilities are malformed")
                parsed_probabilities = {}
                for label, raw_probability in probabilities.items():
                    if isinstance(raw_probability, bool):
                        raise ProviderProtocolError("choice answer probability is malformed")
                    try:
                        probability = float(raw_probability)
                    except (TypeError, ValueError):
                        raise ProviderProtocolError("choice answer probability is malformed") from None
                    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                        raise ProviderProtocolError("choice answer probability is invalid")
                    label_text = str(label)
                    if not label_text or len(label_text) > 128:
                        raise ProviderProtocolError("choice answer probability label is malformed")
                    parsed_probabilities[label_text] = probability
            return cls(
                question_id,
                kind,
                choice,
                probabilities=parsed_probabilities,
                confidence=cls._parse_confidence(value),
            )
        if kind == "noul":
            raw = value.get("noul", value.get("value"))
            raw_probability = value.get("probability")
            if isinstance(raw, bool):
                # The native Jev wire uses a numeric ``noul`` probability,
                # while the provider-neutral contract also accepts a boolean
                # value plus an explicit probability.  Preserve the boolean
                # answer but use the supplied probability for ranking.
                probability = raw_probability if raw_probability is not None else (1.0 if raw else 0.0)
                if isinstance(raw_probability, bool):
                    raise ProviderProtocolError("noul answer probability is malformed")
                try:
                    probability = float(probability)
                except (TypeError, ValueError):
                    raise ProviderProtocolError("noul answer probability is malformed") from None
                if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                    raise ProviderProtocolError("noul answer probability is outside 0..1")
                return cls(question_id, kind, raw, probability=probability)
            try:
                probability = float(raw if raw is not None else raw_probability)
            except (TypeError, ValueError):
                raise ProviderProtocolError("noul answer probability is malformed") from None
            if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                raise ProviderProtocolError("noul answer probability is outside 0..1")
            return cls(question_id, kind, probability, probability=probability)
        raw_probs = value.get("probabilities")
        probabilities: dict[str, float] | None = None
        if raw_probs is not None:
            if not isinstance(raw_probs, Mapping) or not raw_probs or len(raw_probs) > 64:
                raise ProviderProtocolError("score answer probabilities are malformed")
            probabilities = {}
            for label, raw_probability in raw_probs.items():
                if isinstance(raw_probability, bool):
                    raise ProviderProtocolError("score answer probability is malformed")
                try:
                    probability = float(raw_probability)
                except (TypeError, ValueError):
                    raise ProviderProtocolError("score answer probability is malformed") from None
                if not math.isfinite(probability) or probability < 0.0:
                    raise ProviderProtocolError("score answer probability is invalid")
                label_text = str(label)
                if not label_text or len(label_text) > 128:
                    raise ProviderProtocolError("score answer probability label is malformed")
                probabilities[label_text] = probability
        raw_score = value.get("score", value.get("value"))
        score: float | str | None = None
        if raw_score is not None:
            if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                score = float(raw_score)
                if not math.isfinite(score):
                    raise ProviderProtocolError("score answer is not finite")
            elif isinstance(raw_score, str):
                score = _safe_string(raw_score, 256)
            else:
                raise ProviderProtocolError("score answer value is malformed")
        if probabilities is None and score is None:
            raise ProviderProtocolError("score answer has no value")
        legend_raw = value.get("legend")
        legend = None
        if legend_raw is not None:
            if not isinstance(legend_raw, Mapping) or len(legend_raw) > 64:
                raise ProviderProtocolError("score answer legend is malformed")
            legend = {
                str(k)[:128]: _public_label(v, 256) or ""
                for k, v in legend_raw.items()
            }
        return cls(
            question_id,
            kind,
            score,
            probabilities=probabilities,
            legend=legend,
            confidence=cls._parse_confidence(value),
        )


@dataclass(frozen=True)
class ProviderRequest:
    state: StateSnapshot
    questions: tuple[Question, ...]
    model: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model, str)
            or not self.model.strip()
            or len(self.model) > 256
            or _SECRET_KEY_RE.search(self.model)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", self.model.strip())
        ):
            raise ProviderProtocolError("provider model is required and bounded")
        if not self.questions or len(self.questions) > MAX_QUESTIONS:
            raise ProviderProtocolError("provider request must contain 1..64 questions")
        ids = [question.question_id for question in self.questions]
        if len(ids) != len(set(ids)):
            raise ProviderProtocolError("provider question ids must be unique")

    def to_wire(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "state": self.state.to_wire(),
            "questions": {
                question.question_id: question.to_wire() for question in self.questions
            },
        }


@dataclass(frozen=True)
class ProviderResponse:
    model: str
    answers: dict[str, Answer]
    usage: Usage
    latency_ms: float = 0.0
    request_id: str | None = None


@dataclass(frozen=True)
class ProviderCapabilities:
    classify: bool = False
    score: bool = False
    embeddings: bool = False
    lexical_fallback: bool = True

    def names(self) -> list[str]:
        return [
            name
            for name, enabled in (
                ("classify", self.classify),
                ("score", self.score),
                ("embeddings", self.embeddings),
                ("lexical_fallback", self.lexical_fallback),
            )
            if enabled
        ]


@dataclass(frozen=True)
class ProviderStatus:
    mode: str
    provider_id: str
    protocol: str
    model: str | None
    base_url: str | None
    capabilities: ProviderCapabilities
    configured: bool
    ready: bool
    auth_present: bool
    last_error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "provider": _public_label(self.provider_id, 128),
            "protocol": _public_label(self.protocol, 64),
            "model": _public_label(self.model),
            "base_url": self.base_url,
            "capabilities": self.capabilities.names(),
            "configured": self.configured,
            "ready": self.ready,
            "auth_present": self.auth_present,
            "last_error_code": self.last_error_code,
        }
