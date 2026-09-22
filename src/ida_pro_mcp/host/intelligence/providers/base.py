"""Provider interface and strict typed-question response validation."""

from __future__ import annotations

import json
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from typing import Any

from .config import ProviderConfig
from .http import JsonHttpTransport
from .types import (
    _SECRET_KEY_RE,
    MAX_RESPONSE_BYTES,
    Answer,
    CapabilityUnavailableError,
    ProviderCapabilities,
    ProviderProtocolError,
    ProviderRequest,
    ProviderResponse,
    ProviderStatus,
    Question,
    StateSnapshot,
    Usage,
)
from .usage_accounting import UsageLedger


class StateQuestionProvider(ABC):
    """Advisory typed-question provider.

    Implementations must not invoke MCP tools, change IDB state, write
    blackboard findings, or make policy decisions from an answer.
    """

    def __init__(self, config: ProviderConfig, *, ledger: UsageLedger | None = None):
        self.config = config
        self.ledger = ledger
        self._last_error_code: str | None = None

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        raise NotImplementedError

    @abstractmethod
    def invoke(
        self,
        state: Mapping[str, Any] | StateSnapshot,
        questions: Iterable[Question] | Mapping[str, Any],
        *,
        session_id: str = "",
        operation: str = "classify",
        deadline_seconds: float | None = None,
    ) -> ProviderResponse:
        raise NotImplementedError

    def build_request(
        self,
        state: Mapping[str, Any] | StateSnapshot,
        questions: Iterable[Question] | Mapping[str, Any],
    ) -> ProviderRequest:
        snapshot = state if isinstance(state, StateSnapshot) else StateSnapshot.from_mapping(state)
        normalized = normalize_questions(questions)
        return ProviderRequest(snapshot, tuple(normalized), str(self.config.model or ""))

    def status(self) -> ProviderStatus:
        auth_present = bool(self.config.auth and self.config.auth.present())
        return ProviderStatus(
            mode=self.config.mode,
            provider_id=self.config.provider_id,
            protocol=self.config.protocol,
            model=self.config.model,
            base_url=self.config.origin,
            capabilities=self.capabilities,
            configured=True,
            ready=self.config.mode == "disabled" or auth_present,
            auth_present=auth_present,
            last_error_code=self._last_error_code,
        )


def normalize_questions(value: Iterable[Question] | Mapping[str, Any]) -> list[Question]:
    entries: list[tuple[str | None, Any]] = []
    if isinstance(value, Mapping):
        entries = [(str(question_id), raw) for question_id, raw in value.items()]
    else:
        for item in value:
            if isinstance(item, Question):
                entries.append((None, item))
            elif isinstance(item, Mapping):
                entries.append((item.get("id", item.get("question_id")), item))
            else:
                raise ProviderProtocolError("question definitions must be objects")
    items: list[Question] = []
    for question_id, raw in entries:
        if isinstance(raw, Question):
            items.append(raw)
            continue
        if not isinstance(raw, Mapping):
            raise ProviderProtocolError("question definitions must be objects")
        items.append(
            Question(
                question_id=str(question_id or ""),
                type=str(raw.get("type") or ""),
                instructions=raw.get("instructions", raw.get("question", "")),
                criteria=raw.get("criteria", raw.get("choices")),
            )
        )
    return items


def normalize_score_answer(answer: Answer, criteria: Iterable[Any]) -> tuple[float, float]:
    """Return a typed Score as a 0..1 value plus provider confidence.

    TypeSafe Score values are expected positions on the ordered criteria
    scale: a three-level rubric returns 0..2, including fractional values.
    Probability distributions are a fallback for compatible providers that
    omit the aggregate score.
    """
    levels = [str(item).strip() for item in criteria]
    if len(levels) < 2:
        raise ProviderProtocolError("score criteria must contain at least two levels")
    scale = len(levels) - 1
    normalized_levels = {label.casefold(): index for index, label in enumerate(levels)}
    value = answer.value
    score: float | None = None

    if isinstance(value, bool):
        raise ProviderProtocolError("provider score answer is malformed")
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        label = value.strip().casefold()
        if label in normalized_levels:
            score = float(normalized_levels[label])
        else:
            try:
                score = float(label)
            except (TypeError, ValueError):
                score = None

    if score is None and answer.probabilities:
        weighted_score = 0.0
        total_probability = 0.0
        legend = answer.legend or {}
        for key, probability in answer.probabilities.items():
            label = str(legend.get(str(key), key)).strip().casefold()
            level_index = normalized_levels.get(label)
            if level_index is None:
                try:
                    numeric_level = float(key)
                except (TypeError, ValueError):
                    continue
                if not numeric_level.is_integer():
                    continue
                level_index = int(numeric_level)
            if not 0 <= level_index < len(levels):
                continue
            weighted_score += level_index * float(probability)
            total_probability += float(probability)
        if total_probability > 0.0:
            score = weighted_score / total_probability

    if score is None or not math.isfinite(score) or score < -1e-9 or score > scale + 1e-9:
        raise ProviderProtocolError("provider score answer is outside its criteria scale")
    confidence = answer.confidence
    if confidence is None:
        confidence = max((float(item) for item in (answer.probabilities or {}).values()), default=0.0)
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise ProviderProtocolError("provider score confidence is malformed")
    return max(0.0, min(1.0, score / scale)), confidence


def parse_response(
    payload: Any,
    request: ProviderRequest,
    *,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> ProviderResponse:
    """Validate a provider response without retaining its raw contents."""
    try:
        response_limit = int(max_response_bytes)
    except (TypeError, ValueError, OverflowError):
        raise ProviderProtocolError("provider response limit is malformed") from None
    if isinstance(max_response_bytes, bool) or response_limit < 1:
        raise ProviderProtocolError("provider response limit is malformed")
    if isinstance(payload, (bytes, bytearray)):
        if len(payload) > response_limit:
            raise ProviderProtocolError("provider response exceeds the compact limit")
        try:
            payload = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderProtocolError("provider response is not valid JSON") from None
    if not isinstance(payload, Mapping):
        raise ProviderProtocolError("provider response must be an object")
    try:
        encoded_size = len(json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        raise ProviderProtocolError("provider response contains unsupported JSON values") from None
    if encoded_size > response_limit:
        raise ProviderProtocolError("provider response exceeds the compact limit")
    model = payload.get("model")
    if (
        not isinstance(model, str)
        or not model.strip()
        or len(model) > 256
        or _SECRET_KEY_RE.search(model)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model.strip())
    ):
        raise ProviderProtocolError("provider response model is missing or malformed")
    raw_answers = payload.get("answers")
    if isinstance(raw_answers, list):
        answer_map: dict[str, Any] = {}
        for item in raw_answers:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
                raise ProviderProtocolError("provider answer list is malformed")
            answer_id = str(item["id"])
            if answer_id in answer_map:
                raise ProviderProtocolError("provider returned duplicate answers")
            answer_map[answer_id] = dict(item)
    elif isinstance(raw_answers, Mapping):
        answer_map = dict(raw_answers)
    else:
        raise ProviderProtocolError("provider response answers must be an object or list")
    expected = {question.question_id: question for question in request.questions}
    if set(answer_map) != set(expected):
        raise ProviderProtocolError("provider response answers do not match submitted questions")
    answers: dict[str, Answer] = {}
    for question_id, question in expected.items():
        answer = Answer.from_wire(question_id, question.type, answer_map[question_id])
        if question.type == "score":
            criteria = question.criteria
            allowed_labels = (
                {str(item) for item in criteria}
                if isinstance(criteria, (list, tuple))
                else {str(item) for item in criteria}
                if isinstance(criteria, Mapping)
                else set()
            )
            if isinstance(answer.value, str) and answer.value not in allowed_labels:
                raise ProviderProtocolError("score answer contains an unexpected label")
            if answer.probabilities:
                allowed_probability_keys = allowed_labels | {
                    str(index) for index in range(65)
                }
                if set(answer.probabilities) - allowed_probability_keys:
                    raise ProviderProtocolError("score answer probabilities contain unexpected labels")
            if answer.legend:
                # A provider legend is descriptive output, not an open text
                # channel. Retain only labels already supplied by the caller;
                # generated prose/completions never cross the result boundary.
                safe_legend = {
                    key: value for key, value in answer.legend.items()
                    if value in allowed_labels
                }
                answer = Answer(
                    answer.question_id,
                    answer.type,
                    answer.value,
                    answer.probability,
                    answer.probabilities,
                    safe_legend or None,
                    answer.confidence,
                )
        if question.type == "choice":
            allowed = question.criteria
            if isinstance(allowed, Mapping):
                allowed_names = {str(item) for item in allowed}
            else:
                allowed_names = {str(item) for item in allowed or ()}
            if answer.value not in allowed_names:
                raise ProviderProtocolError("choice answer is not one of the submitted choices")
            if answer.probabilities:
                unknown = set(answer.probabilities) - allowed_names
                if unknown:
                    raise ProviderProtocolError("choice answer probabilities contain unknown choices")
        answers[question_id] = answer
    usage = Usage.from_wire(payload.get("usage"))
    request_id = payload.get("request_id")
    if request_id is not None and (
        not isinstance(request_id, str)
        or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", request_id)
    ):
        raise ProviderProtocolError("provider response request_id is malformed")
    safe_request_id = request_id
    return ProviderResponse(model=model.strip(), answers=answers, usage=usage, request_id=safe_request_id)


def assert_capability(provider: StateQuestionProvider, questions: Iterable[Question]) -> None:
    question_list = list(questions)
    if any(question.type == "score" for question in question_list) and not provider.capabilities.score:
        raise CapabilityUnavailableError("provider does not declare score capability")
    if any(question.type in {"choice", "noul"} for question in question_list) and not provider.capabilities.classify:
        raise CapabilityUnavailableError("provider does not declare classify capability")


def safe_provider_error(exc: Exception) -> tuple[str, str, dict[str, Any]]:
    """Convert an exception to an MCP-safe tuple without raw upstream data."""
    code = str(getattr(exc, "code", "PROVIDER_ERROR"))
    message = str(getattr(exc, "message", "provider request failed"))
    details = getattr(exc, "details", {})
    if not isinstance(details, dict):
        details = {}
    return code, message[:512], dict(details)


def invoke_http_json(
    *,
    transport: JsonHttpTransport,
    config: ProviderConfig,
    payload: dict[str, Any],
    headers: dict[str, str],
    deadline_seconds: float | None,
) -> tuple[dict[str, Any], float]:
    """Call the transport and decode one bounded JSON object."""
    timeout = min(
        float(config.connect_timeout_seconds),
        float(config.read_timeout_seconds),
        float(config.total_timeout_seconds if deadline_seconds is None else deadline_seconds),
    )
    response = transport.post_json(
        str(config.base_url).rstrip("/") + str(config.invoke_path),
        payload,
        headers=headers,
        timeout_seconds=timeout,
        max_response_bytes=config.max_response_bytes,
        local_http=config.local_http,
        allowed_origins=config.allowed_origins or ((config.origin,) if config.origin else ()),
    )
    if len(response.body) > config.max_response_bytes:
        raise ProviderProtocolError("provider response exceeds the configured limit")
    try:
        decoded = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderProtocolError("provider response is not valid JSON") from None
    if not isinstance(decoded, dict):
        raise ProviderProtocolError("provider response must be an object")
    return decoded, response.latency_ms
