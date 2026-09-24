"""Shared HTTP implementation for typed-question providers."""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Mapping
from typing import Any

from .base import StateQuestionProvider, assert_capability, invoke_http_json, normalize_questions, parse_response
from .config import ProviderConfig
from .http import JsonHttpTransport, TransportError
from .types import (
    MAX_JEV_REQUEST_BYTES,
    MAX_STATE_AND_LONGEST_QUESTION_BYTES,
    ProviderBudgetError,
    ProviderConfigError,
    ProviderError,
    ProviderProtocolError,
    ProviderRequest,
    ProviderResponse,
    ProviderTimeoutError,
    ProviderUnavailableError,
    StateSnapshot,
)
from .usage_accounting import UsageLedger


def _resolve_path(expression: str, document: Mapping[str, Any]) -> Any:
    """Resolve one closed-DSL placeholder against a JSON-like document."""
    if not isinstance(expression, str) or not expression.startswith("$"):
        return expression
    path = expression[1:]
    match = re.match(r"(?P<root>[A-Za-z_][A-Za-z0-9_-]{0,63})", path)
    if match is None:
        return None
    root = match.group("root")
    if root not in {"state", "model", "questions", "answers", "usage", "response", "body"}:
        return None
    if not isinstance(document, Mapping):
        return None
    current: Any = document.get(root)
    rest = path[match.end() :]
    while rest:
        if rest.startswith("[*]"):
            if isinstance(current, Mapping):
                current = list(current.values())[:64]
            elif isinstance(current, (list, tuple)):
                current = list(current)[:64]
            else:
                return None
            rest = rest[3:]
            continue
        if not rest.startswith("."):
            return None
        field = re.match(r"\.[A-Za-z_][A-Za-z0-9_-]{0,63}", rest)
        if field is None:
            return None
        name = field.group(0)[1:]
        if isinstance(current, Mapping):
            current = current.get(name)
        elif isinstance(current, list):
            current = [item.get(name) if isinstance(item, Mapping) else None for item in current]
        else:
            return None
        rest = rest[field.end() :]
    return current


def _project_mapping(mapping: Mapping[str, Any], document: Mapping[str, Any]) -> dict[str, Any]:
    """Project a JSON document with the validated, non-executable DSL."""
    if not mapping:
        return dict(document)

    def project(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): project(child) for key, child in value.items()}
        if isinstance(value, list):
            return [project(child) for child in value]
        return _resolve_path(value, document)

    projected = project(mapping)
    return projected if isinstance(projected, dict) else {}


class HttpTypedQuestionProvider(StateQuestionProvider):
    """Common bounded HTTP/retry/accounting behavior."""

    unavailable_error = ProviderUnavailableError

    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport: JsonHttpTransport | None = None,
        ledger: UsageLedger | None = None,
        sleep=time.sleep,
    ) -> None:
        self.config = config
        self.transport = transport or JsonHttpTransport()
        self.ledger = ledger
        self._sleep = sleep
        self._last_error_code: str | None = None

    @property
    def capabilities(self):
        return self.config.capabilities

    def status(self):
        from .types import ProviderStatus

        auth_present = bool(self.config.auth and self.config.auth.present())
        unavailable_code = (
            "JEV_UNAVAILABLE" if self.config.mode == "jev" else "PROVIDER_UNAVAILABLE"
        )
        return ProviderStatus(
            mode=self.config.mode,
            provider_id=self.config.provider_id,
            protocol=self.config.protocol,
            model=self.config.model,
            base_url=self.config.origin,
            capabilities=self.capabilities,
            configured=True,
            ready=auth_present,
            auth_present=auth_present,
            last_error_code=self._last_error_code or (None if auth_present else unavailable_code),
        )

    def build_request(self, state, questions) -> ProviderRequest:
        snapshot = state if isinstance(state, StateSnapshot) else StateSnapshot.from_mapping(state)
        normalized = normalize_questions(questions)
        request = ProviderRequest(snapshot, tuple(normalized), str(self.config.model or ""))
        if len(request.questions) > self.config.max_questions:
            raise ProviderProtocolError("provider question count exceeds the configured limit")
        if self.config.mode == "jev":
            state_bytes = len(
                json.dumps(
                    request.state.to_wire(), ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            )
            longest_question_bytes = max(
                len(
                    json.dumps(
                        {question.question_id: question.to_wire()},
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                for question in request.questions
            )
            if state_bytes + longest_question_bytes > MAX_STATE_AND_LONGEST_QUESTION_BYTES:
                raise ProviderProtocolError(
                    "Jev state and longest question exceed the compact context limit"
                )
        request_limit = min(self.config.max_input_chars, MAX_JEV_REQUEST_BYTES) if self.config.mode == "jev" else self.config.max_input_chars
        if len(json.dumps(request.to_wire(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > request_limit:
            raise ProviderProtocolError("provider request exceeds the configured context limit")
        assert_capability(self, request.questions)
        return request

    def _secret(self) -> str:
        secret = self.config.auth.read_secret() if self.config.auth else ""
        if not secret:
            raise self.unavailable_error("provider credential is unavailable")
        if len(secret) > 4096 or any(ord(char) < 0x20 for char in secret):
            raise ProviderConfigError("provider credential is malformed")
        return secret

    def _map_request(self, request: ProviderRequest) -> dict[str, Any]:
        canonical = request.to_wire()
        return _project_mapping(self.config.request_mapping, canonical)

    def _map_response(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.config.response_mapping:
            return payload
        document = dict(payload)
        # Keep the reserved roots authoritative even when an upstream payload
        # contains fields named ``response`` or ``body``.
        document.update({"response": payload, "body": payload})
        mapped = _project_mapping(self.config.response_mapping, document)
        if not isinstance(mapped, dict):
            raise ProviderProtocolError("custom response mapping did not produce an object")
        return mapped

    def invoke(
        self,
        state,
        questions,
        *,
        session_id: str = "",
        operation: str = "classify",
        deadline_seconds: float | None = None,
    ) -> ProviderResponse:
        try:
            request = self.build_request(state, questions)
            secret = self._secret()
        except ProviderError as exc:
            self._last_error_code = exc.code
            raise
        try:
            payload = self._map_request(request)
            encoded_request = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except ProviderError as exc:
            self._last_error_code = exc.code
            raise
        except (TypeError, ValueError):
            self._last_error_code = "PROVIDER_PROTOCOL_ERROR"
            raise ProviderProtocolError("provider request contains unsupported JSON values") from None
        request_limit = min(self.config.max_input_chars, MAX_JEV_REQUEST_BYTES) if self.config.mode == "jev" else self.config.max_input_chars
        if len(encoded_request) > request_limit:
            self._last_error_code = "PROVIDER_PROTOCOL_ERROR"
            raise ProviderProtocolError("provider request exceeds the configured context limit")
        estimated_input_tokens = max(1, math.ceil(len(encoded_request) / 4))
        if self.ledger is not None and estimated_input_tokens > self.ledger.budget.request_input_tokens:
            self._last_error_code = "BUDGET_EXCEEDED"
            raise ProviderBudgetError(
                "provider request token budget exceeded",
                details={"reason": "request_tokens"},
            )
        started = time.monotonic()
        try:
            caller_budget = self.config.total_timeout_seconds if deadline_seconds is None else float(deadline_seconds)
        except (TypeError, ValueError, OverflowError):
            self._last_error_code = "PROVIDER_TIMEOUT"
            raise ProviderTimeoutError("provider request deadline is malformed") from None
        if not math.isfinite(caller_budget) or caller_budget < 0:
            self._last_error_code = "PROVIDER_TIMEOUT"
            raise ProviderTimeoutError("provider request deadline is malformed")
        request_budget = min(float(self.config.total_timeout_seconds), caller_budget)
        request_deadline = started + request_budget
        reservation = None
        if self.ledger is not None:
            try:
                # Reserve the configured per-request maxima, not a byte/4
                # estimate. Provider tokenization differs and an optimistic
                # estimate could turn a valid response into a false budget
                # overrun. Reconciliation releases unused reservations.
                reservation = self.ledger.reserve(
                    session_id=session_id,
                    provider=self.config.provider_id,
                    model=self.config.model,
                    operation=operation,
                    input_price=self.config.input_usd_per_mtok,
                    output_price=self.config.output_usd_per_mtok,
                    allow_unknown_pricing=self.config.allow_unknown_pricing,
                )
            except ProviderError as exc:
                self._last_error_code = exc.code
                raise
        last_error: Exception | None = None
        attempts = max(1, int(self.config.max_attempts))
        for attempt in range(attempts):
            try:
                headers = {self.config.auth.header: self.config.auth.prefix + secret} if self.config.auth else {}
                remaining = request_deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderTimeoutError("provider request exceeded its deadline")
                response_payload, latency_ms = invoke_http_json(
                    transport=self.transport,
                    config=self.config,
                    payload=payload,
                    headers=headers,
                    deadline_seconds=remaining,
                )
                response = parse_response(
                    self._map_response(response_payload),
                    request,
                    max_response_bytes=self.config.max_response_bytes,
                )
                response = ProviderResponse(
                    model=response.model,
                    answers=response.answers,
                    usage=response.usage,
                    latency_ms=latency_ms,
                    request_id=response.request_id,
                )
                if reservation is not None:
                    if (
                        response.usage.input_tokens > reservation.reserved_input_tokens
                        or response.usage.output_tokens > reservation.reserved_output_tokens
                        or response.usage.total_tokens > reservation.reserved_total_tokens
                    ):
                        raise ProviderBudgetError(
                            "provider request token budget exceeded",
                            details={"reason": "request_tokens"},
                        )
                    self.ledger.reconcile(reservation, usage=response.usage, latency_ms=latency_ms)
                self._last_error_code = None
                return response
            except Exception as exc:  # bounded conversion below; never expose body
                last_error = exc
                retryable = isinstance(exc, (TransportError, ProviderTimeoutError))
                if attempt + 1 < attempts and retryable:
                    delay = min(
                        self.config.backoff_max_seconds,
                        self.config.backoff_initial_seconds * (2**attempt),
                        max(0.0, request_deadline - time.monotonic()),
                    )
                    if delay > 0:
                        self._sleep(delay)
                    continue
                break
        code = str(getattr(last_error, "code", "PROVIDER_ERROR"))
        if isinstance(last_error, TransportError):
            # The transport detail is deliberately not part of the public
            # provider contract. Record the same stable unavailable code that
            # the caller receives, while retaining only safe status details.
            code = self.unavailable_error.code
        self._last_error_code = code
        if reservation is not None:
            self.ledger.reconcile(
                reservation,
                usage=None,
                latency_ms=(time.monotonic() - started) * 1000.0,
                error_code=code,
            )
        if isinstance(last_error, TransportError):
            label = "Jev provider is unavailable" if self.config.mode == "jev" else "custom provider is unavailable"
            raise self.unavailable_error(label, details=getattr(last_error, "details", {})) from None
        if isinstance(last_error, ProviderError):
            raise last_error
        raise ProviderError("provider request failed") from None
