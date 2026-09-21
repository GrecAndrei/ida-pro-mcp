"""TypeSafe Jev typed-question provider."""

from __future__ import annotations

from .config import JEV_BASE_URL, JEV_INVOKE_PATH, ProviderConfig
from .remote import HttpTypedQuestionProvider
from .types import JevUnavailableError, ProviderConfigError


class JevProvider(HttpTypedQuestionProvider):
    unavailable_error = JevUnavailableError

    def __init__(self, config: ProviderConfig, **kwargs):
        if config.mode != "jev":
            raise ProviderConfigError("JevProvider requires jev mode")
        if config.base_url != JEV_BASE_URL or config.invoke_path != JEV_INVOKE_PATH:
            raise ProviderConfigError("Jev endpoint configuration is immutable")
        super().__init__(config, **kwargs)
