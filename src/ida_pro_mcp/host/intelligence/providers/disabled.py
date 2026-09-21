"""Explicitly disabled intelligence provider."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .base import StateQuestionProvider
from .config import ProviderConfig
from .types import (
    IntelligenceDisabledError,
    ProviderCapabilities,
    ProviderConfigError,
    ProviderResponse,
    ProviderStatus,
    Question,
    StateSnapshot,
)


class DisabledProvider(StateQuestionProvider):
    def __init__(self, config: ProviderConfig):
        if config.mode != "disabled":
            raise ProviderConfigError("DisabledProvider requires disabled mode")
        self.config = config
        self._last_error_code = None

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self.config.capabilities

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            mode="disabled",
            provider_id="disabled",
            protocol="none",
            model=None,
            base_url=None,
            capabilities=self.capabilities,
            configured=True,
            ready=True,
            auth_present=False,
            last_error_code=self._last_error_code,
        )

    def invoke(
        self,
        state: Mapping[str, Any] | StateSnapshot,
        questions: Iterable[Question] | Mapping[str, Any],
        *,
        session_id: str = "",
        operation: str = "classify",
        deadline_seconds: float | None = None,
    ) -> ProviderResponse:
        self._last_error_code = "INTELLIGENCE_DISABLED"
        raise IntelligenceDisabledError("intelligence is disabled; deterministic and lexical analysis remain available")
