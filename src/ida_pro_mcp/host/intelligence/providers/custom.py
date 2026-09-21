"""Explicit operator-configured typed-question provider."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .config import ProviderConfig
from .remote import HttpTypedQuestionProvider
from .types import ProviderConfigError, ProviderRequest, _compact_value


class CustomProvider(HttpTypedQuestionProvider):
    def __init__(self, config: ProviderConfig, **kwargs):
        if config.mode != "custom":
            raise ProviderConfigError("CustomProvider requires custom mode")
        super().__init__(config, **kwargs)

    def _map_request(self, request: ProviderRequest) -> dict[str, Any]:
        """Use the provider-neutral array form for custom endpoints.

        Jev's native endpoint keys each question by id.  A BYOK endpoint gets
        the interoperable canonical form with an explicit ``id`` field; the
        closed mapping DSL can then project it into a vendor-specific shape.
        """
        canonical_questions: list[dict[str, Any]] = []
        for question in request.questions:
            item: dict[str, Any] = {
                "id": question.question_id,
                "type": question.type,
                "question": _compact_value(question.instructions, depth=1),
            }
            if question.criteria is not None:
                compact_criteria = _compact_value(question.criteria, depth=1)
                item["choices"] = (
                    list(compact_criteria)
                    if isinstance(compact_criteria, (list, tuple, Mapping))
                    else compact_criteria
                )
            canonical_questions.append(item)
        canonical = {
            "model": request.model,
            "state": request.state.to_wire(),
            "questions": canonical_questions,
        }
        from .remote import _project_mapping

        return _project_mapping(self.config.request_mapping, canonical)
