from __future__ import annotations

import json

import pytest

from ida_pro_mcp.host.intelligence.advisory import rank_targets
from ida_pro_mcp.host.intelligence.providers import (
    Answer,
    BudgetConfig,
    CustomProvider,
    DisabledProvider,
    IntelligenceDisabledError,
    JevProvider,
    JevUnavailableError,
    ProviderBudgetError,
    ProviderConfigError,
    ProviderProtocolError,
    ProviderRequest,
    ProviderResponse,
    Question,
    StateSnapshot,
    Usage,
    UsageLedger,
    normalize_score_answer,
    provider_error_payload,
    provider_status,
    resolve_provider_config,
)
from ida_pro_mcp.host.intelligence.providers.base import parse_response
from ida_pro_mcp.host.intelligence.providers.http import HttpResponse, JsonHttpTransport, TransportError
from ida_pro_mcp.host.intelligence.providers.types import MAX_CHOICE_OPTIONS


def _custom_env(**extra):
    env = {
        "IDA_MCP_INTELLIGENCE_MODE": "custom",
        "IDA_MCP_CUSTOM_BASE_URL": "https://provider.example",
        "IDA_MCP_CUSTOM_ALLOWED_ORIGINS": "https://provider.example",
        "IDA_MCP_CUSTOM_MODEL": "pinned",
        "CUSTOM_PROVIDER_API_KEY": "not-a-real-key",
    }
    env.update(extra)
    return env


def test_rank_targets_normalizes_ordinal_scores_and_sends_metadata_only():
    class _Provider:
        def __init__(self):
            self.state = None
            self.questions = None

        def invoke(self, state, questions, **_kwargs):
            self.state = state
            self.questions = list(questions)
            answers = {
                question.question_id: Answer(
                    question.question_id,
                    "score",
                    2.0 if question.question_id == "target_0" else 0.0,
                )
                for question in questions
            }
            return ProviderResponse("fixture", answers, Usage(1, 1, 2))

    provider = _Provider()
    result = rank_targets(
        {"strategy": "unresolved", "query": "parser"},
        [
            {"address": "0x401000", "title": "parse header", "content": "must not be sent"},
            {"address": "0x402000", "title": "idle helper", "reason": "low priority"},
        ],
        provider=provider,
    )

    assert result["ok"] is True
    assert [item["score"] for item in result["scores"]] == [1.0, 0.0]
    assert "targets" not in provider.state
    first_candidate = provider.questions[0].instructions["candidate"]
    assert "content" not in first_candidate
    assert first_candidate["title"] == "parse header"
    assert provider.questions[0].instructions["candidate_index"] == 0


def test_rank_targets_normalizes_midpoint_and_fractional_ordinal_scores():
    class _Provider:
        def invoke(self, _state, questions, **_kwargs):
            return ProviderResponse(
                "fixture",
                {
                    question.question_id: Answer(
                        question.question_id,
                        "score",
                        1.0 if question.question_id == "target_0" else 1.43,
                        confidence=0.82,
                    )
                    for question in questions
                },
                Usage(1, 1, 2),
            )

    result = rank_targets(
        {"strategy": "unresolved"},
        [{"title": "candidate one"}, {"title": "candidate two"}],
        provider=_Provider(),
    )
    assert [item["score"] for item in result["scores"]] == [0.5, 0.715]
    assert [item["confidence"] for item in result["scores"]] == [0.82, 0.82]


def test_typed_answer_keeps_jev_confidence_and_score_scale():
    request = ProviderRequest(
        StateSnapshot.from_mapping({"query": "bounded"}),
        (
            Question("choice", "choice", "Choose one", criteria=["a", "b"]),
            Question("score", "score", "Rate it", criteria=["low", "middle", "high"]),
        ),
        "jev-latest",
    )
    response = parse_response(
        {
            "model": "jev-1.13.0",
            "answers": {
                "choice": {
                    "type": "choice",
                    "choice": "a",
                    "probabilities": {"a": 0.88, "b": 0.12},
                    "confidence": 0.81,
                },
                "score": {
                    "type": "score",
                    "score": 1.43,
                    "legend": {"0": "low", "1": "middle", "2": "high"},
                    "probabilities": {"0": 0.0, "1": 0.57, "2": 0.43},
                    "confidence": 0.72,
                },
            },
            "usage": {"input_tokens": 1, "output_tokens": 1},
        },
        request,
    )
    assert response.answers["choice"].confidence == 0.81
    assert normalize_score_answer(response.answers["score"], ["low", "middle", "high"]) == (0.715, 0.72)


def test_typed_answer_rejects_out_of_range_confidence():
    request = ProviderRequest(
        StateSnapshot.from_mapping({"query": "bounded"}),
        (Question("choice", "choice", "Choose one", criteria=["a", "b"]),),
        "jev-latest",
    )
    with pytest.raises(ProviderProtocolError):
        parse_response(
            {
                "model": "jev-1.13.0",
                "answers": {
                    "choice": {
                        "type": "choice",
                        "choice": "a",
                        "probabilities": {"a": 0.8, "b": 0.2},
                        "confidence": 1.2,
                    }
                },
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
            request,
        )


def test_provider_status_and_errors_are_structured_and_redacted():
    status = provider_status(env={})
    assert status["ok"] is True
    assert status["provider"]["mode"] == "disabled"
    assert status["provider"]["auth_present"] is False
    assert status["provider"]["capabilities"] == ["lexical_fallback"]
    payload = provider_error_payload(ProviderConfigError("invalid provider configuration"))
    assert payload["error"] is True
    assert payload["code"] == "PROVIDER_CONFIG_INVALID"
    assert "secret" not in json.dumps(payload).lower()


def test_status_marks_missing_enabled_credentials_unavailable():
    status = provider_status(env={"IDA_MCP_INTELLIGENCE_MODE": "jev"})
    assert status["ok"] is True
    assert status["provider"]["ready"] is False
    assert status["provider"]["last_error_code"] == "JEV_UNAVAILABLE"


def test_process_environment_credentials_are_read_at_request_time(monkeypatch):
    monkeypatch.setenv("IDA_MCP_INTELLIGENCE_MODE", "jev")
    monkeypatch.setenv("TYPESAFE_API_KEY", "first-key")
    config = resolve_provider_config()
    assert config.auth is not None
    assert config.auth.read_secret() == "first-key"
    monkeypatch.setenv("TYPESAFE_API_KEY", "rotated-key")
    assert config.auth.read_secret() == "rotated-key"


def test_modes_are_explicit_and_legacy_settings_fail_closed():
    assert resolve_provider_config(env={}).mode == "disabled"
    assert resolve_provider_config(env={"IDA_MCP_INTELLIGENCE_MODE": "jev"}).mode == "jev"
    assert resolve_provider_config(env=_custom_env()).mode == "custom"
    with pytest.raises(ProviderConfigError) as exc:
        resolve_provider_config(env={"IDA_MCP_EMBED_BACKEND": "local"})
    assert exc.value.code == "PROVIDER_CONFIG_INVALID"
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            state={"schema_version": 2, "mode": "disabled", "provider": {"api_key": "secret"}}
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env={"IDA_MCP_INTELLIGENCE_MODE": "disabled", "TYPESAFE_API_KEY": "present"}
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(TYPESAFE_API_KEY="jev-key")
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env={
                "IDA_MCP_INTELLIGENCE_MODE": "jev",
                "TYPESAFE_API_KEY": "env-key",
                "TYPESAFE_API_KEY_FILE": "/tmp/jev-key",
            }
        )


def test_custom_mapping_rejects_credential_like_constants():
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(
                IDA_MCP_CUSTOM_REQUEST_MAPPING=json.dumps({"authorization": "Bearer secret-value"}),
            )
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(
                IDA_MCP_CUSTOM_REQUEST_MAPPING=json.dumps({"items": "$questions[*].criteria[*]"}),
            )
        )


def test_auth_source_selectors_cannot_be_silently_ignored():
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(
                IDA_MCP_CUSTOM_API_KEY_FILE="/tmp/provider-key",
                IDA_MCP_CUSTOM_API_KEY_ENV="OTHER_PROVIDER_KEY",
            )
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env={
                "IDA_MCP_INTELLIGENCE_MODE": "jev",
                "TYPESAFE_API_KEY": "jev-key",
                "TYPESAFE_API_KEY_FILE": "/tmp/jev-key",
            }
        )


def test_custom_origin_allowlist_and_loopback_http():
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(
                IDA_MCP_CUSTOM_BASE_URL="https://other.example",
                IDA_MCP_CUSTOM_ALLOWED_ORIGINS="https://provider.example",
            )
        )
    with pytest.raises(ProviderConfigError):
        resolve_provider_config(
            env=_custom_env(
                IDA_MCP_CUSTOM_BASE_URL="http://127.0.0.1:8080",
                IDA_MCP_CUSTOM_ALLOWED_ORIGINS="http://127.0.0.1:8080",
            )
        )
    assert resolve_provider_config(
        env=_custom_env(
            IDA_MCP_CUSTOM_BASE_URL="http://127.0.0.1:8080",
            IDA_MCP_CUSTOM_ALLOWED_ORIGINS="http://127.0.0.1:8080",
            IDA_MCP_CUSTOM_LOCAL_HTTP="true",
        )
    ).local_http
    assert resolve_provider_config(
        env=_custom_env(
            IDA_MCP_CUSTOM_BASE_URL="https://provider.example:8443",
            IDA_MCP_CUSTOM_ALLOWED_ORIGINS="https://provider.example:8443",
        )
    ).origin == "https://provider.example:8443"


def test_state_and_question_context_are_bounded_and_redacted():
    state = StateSnapshot.from_mapping(
        {"name": "fn", "pseudocode": "do not send", "bytes": "90 00"}
    )
    assert "pseudocode" not in state.values
    assert "credential" not in StateSnapshot.from_mapping({"credential": "api_key=secret-value"}).values
    assert "decompiled" not in StateSnapshot.from_mapping({"nested": {"decompiled": "private"}}).values.get("nested", {})
    assert "code" not in StateSnapshot.from_mapping({"code": "private", "signature": "safe"}).values
    assert "output" not in StateSnapshot.from_mapping({"output": "private", "signature": "safe"}).values
    for key in ("decomp", "function_body", "source_code", "document_text", "raw_code", "comments"):
        assert key not in StateSnapshot.from_mapping({key: "private decompilation"}).values
    direct = StateSnapshot({"pseudocode": "private", "signature": "safe"})
    assert direct.values == {"signature": "safe"}
    question = Question("q1", "choice", "pick", ["yes", "no"])
    assert question.to_wire() == {
        "type": "choice",
        "instructions": "pick",
        "criteria": {"yes": None, "no": None},
    }


def test_choice_question_and_probability_maps_support_jev_limit_of_255():
    choices = [f"c{index}" for index in range(MAX_CHOICE_OPTIONS)]
    question = Question("q1", "choice", "Choose the best bounded candidate", choices)
    request = ProviderRequest(
        StateSnapshot.from_mapping({"signature": "bounded"}),
        (question,),
        "jev-1.13.0",
    )

    assert len(request.to_wire()["questions"]["q1"]["criteria"]) == 255
    probabilities = dict.fromkeys(choices, 1 / MAX_CHOICE_OPTIONS)
    response = parse_response(
        {
            "model": "jev-1.13.0",
            "answers": {
                "q1": {
                    "type": "choice",
                    "choice": choices[-1],
                    "probabilities": probabilities,
                }
            },
            "usage": {"input_tokens": 1, "output_tokens": 0},
        },
        request,
    )
    assert len(response.answers["q1"].probabilities) == 255
    assert response.answers["q1"].value == choices[-1]

    with pytest.raises(ProviderProtocolError):
        Question(
            "too_many",
            "choice",
            "Choose one",
            [f"c{index}" for index in range(MAX_CHOICE_OPTIONS + 1)],
        )


def test_jev_context_preflight_does_not_limit_custom_providers(monkeypatch):
    import ida_pro_mcp.host.intelligence.providers.remote as remote

    monkeypatch.setattr(remote, "MAX_STATE_AND_LONGEST_QUESTION_BYTES", 1)
    jev = JevProvider(
        resolve_provider_config(
            env={
                "IDA_MCP_INTELLIGENCE_MODE": "jev",
                "TYPESAFE_API_KEY": "synthetic-key",
            }
        )
    )
    question = Question("q1", "noul", "Check this bounded signature")
    with pytest.raises(ProviderProtocolError, match="Jev state and longest question"):
        jev.build_request({"signature": "bounded"}, [question])

    custom = CustomProvider(resolve_provider_config(env=_custom_env()))
    assert custom.build_request({"signature": "bounded"}, [question]).questions == (
        question,
    )


def test_jev_total_request_preflight_remains_fixed_when_configured_limit_is_higher(monkeypatch):
    import ida_pro_mcp.host.intelligence.providers.remote as remote

    monkeypatch.setattr(remote, "MAX_JEV_REQUEST_BYTES", 1_024)
    jev = JevProvider(
        resolve_provider_config(
            env={
                "IDA_MCP_INTELLIGENCE_MODE": "jev",
                "TYPESAFE_API_KEY": "synthetic-key",
                "IDA_MCP_JEV_MAX_INPUT_CHARS": "1000000",
            }
        )
    )
    custom = CustomProvider(
        resolve_provider_config(
            env=_custom_env(IDA_MCP_CUSTOM_MAX_INPUT_CHARS="4096")
        )
    )
    state = {"signature": "x" * 1_200}
    question = Question("q1", "noul", "check")

    with pytest.raises(ProviderProtocolError, match="configured context limit"):
        jev.build_request(state, [question])
    assert custom.build_request(state, [question]).state.values["signature"]


def test_response_validation_rejects_missing_duplicate_or_bad_usage():
    request = __import__(
        "ida_pro_mcp.host.intelligence.providers.types", fromlist=["ProviderRequest"]
    ).ProviderRequest(
        state=StateSnapshot.from_mapping({"name": "fn"}),
        questions=(Question("q1", "choice", "pick", ["yes"]),),
        model="pinned",
    )
    good = {
        "model": "returned",
        "answers": [{"id": "q1", "type": "choice", "value": "yes"}],
        "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
    }
    assert parse_response(good, request).answers["q1"].value == "yes"
    with pytest.raises(ProviderProtocolError):
        parse_response({**good, "answers": []}, request)
    with pytest.raises(ProviderProtocolError):
        parse_response({**good, "usage": {"input_tokens": True, "output_tokens": 2}}, request)
    with pytest.raises(ProviderProtocolError):
        parse_response(
            {**good, "answers": [{"id": "q1", "type": "choice", "value": "no"}]},
            request,
        )


class _FakeTransport:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def post_json(self, url, payload, **kwargs):
        self.calls.append((url, payload, kwargs))
        return HttpResponse(200, json.dumps(self.body).encode(), {}, 1.5)


def test_custom_mapping_projects_array_questions_and_usage_fields():
    env = _custom_env(
        IDA_MCP_CUSTOM_REQUEST_MAPPING=json.dumps(
            {"input": {"model": "$model", "items": "$questions[*]"}}
        ),
        IDA_MCP_CUSTOM_RESPONSE_MAPPING=json.dumps(
            {
                "model": "$response.model",
                "answers": "$response.answers",
                "usage": {
                    "input_tokens": "$response.usage.prompt_tokens",
                    "output_tokens": "$response.usage.completion_tokens",
                    "total_tokens": "$response.usage.total_tokens",
                },
            }
        ),
    )
    config = resolve_provider_config(env=env)
    transport = _FakeTransport(
        {
            "model": "returned",
            "answers": [{"id": "q1", "type": "noul", "probability": 0.9}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        }
    )
    provider = CustomProvider(config, transport=transport)
    result = provider.invoke({}, [Question("q1", "noul", "check")])
    assert transport.calls[0][1]["input"]["items"][0]["id"] == "q1"
    assert result.usage.total_tokens == 3


def test_custom_provider_uses_typed_transport_without_persisting_body(monkeypatch):
    config = resolve_provider_config(env=_custom_env())
    transport = _FakeTransport(
        {
            "model": "returned",
            "answers": [{"id": "q1", "type": "noul", "probability": 0.9}],
            "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
        }
    )
    provider = CustomProvider(config, transport=transport)
    result = provider.invoke(
        {"name": "fn", "decompilation": "private"},
        [Question("q1", "noul", "is this relevant?")],
    )
    assert result.answers["q1"].probability == pytest.approx(0.9)
    assert "decompilation" not in transport.calls[0][1]["state"]
    assert "not-a-real-key" in transport.calls[0][2]["headers"]["Authorization"]
    assert "private" not in repr(result)


def test_file_credentials_are_bounded_and_not_returned(monkeypatch, tmp_path):
    monkeypatch.delenv("CUSTOM_PROVIDER_API_KEY", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    path = tmp_path / "credential"
    path.write_text("x" * 4097, encoding="utf-8")
    config = resolve_provider_config(
        env={
            "IDA_MCP_INTELLIGENCE_MODE": "custom",
            "IDA_MCP_CUSTOM_BASE_URL": "https://provider.example",
            "IDA_MCP_CUSTOM_ALLOWED_ORIGINS": "https://provider.example",
            "IDA_MCP_CUSTOM_MODEL": "pinned",
            "IDA_MCP_CUSTOM_API_KEY_FILE": str(path),
        }
    )
    assert config.auth is not None
    assert config.auth.read_secret() == ""


def test_jev_missing_key_and_disabled_are_explicit(monkeypatch):
    jev = __import__(
        "ida_pro_mcp.host.intelligence.providers", fromlist=["build_provider"]
    ).build_provider(resolve_provider_config(env={"IDA_MCP_INTELLIGENCE_MODE": "jev"}))
    with pytest.raises(JevUnavailableError):
        jev.invoke({"name": "fn"}, [Question("q1", "noul", "check")])
    disabled = DisabledProvider(resolve_provider_config(env={}))
    with pytest.raises(IntelligenceDisabledError):
        disabled.invoke({}, [Question("q1", "noul", "check")])


def test_ledger_blocks_unknown_price_and_releases_reservation(tmp_path):
    ledger = UsageLedger(
        tmp_path / "usage.sqlite3",
        budget=BudgetConfig(
            request_input_tokens=10,
            request_output_tokens=5,
            request_count_session=2,
            request_count_daily=4,
            token_budget_session=20,
            token_budget_daily=100,
            cost_budget_session=1,
            cost_budget_daily=2,
        ),
    )
    with pytest.raises(Exception) as exc:
        ledger.reserve(
            session_id="s",
            provider="p",
            model="m",
            operation="x",
            input_price=None,
            output_price=None,
        )
    assert getattr(exc.value, "code", None) == "BUDGET_EXCEEDED"
    reservation = ledger.reserve(
        session_id="s",
        provider="p",
        model="m",
        operation="x",
        input_price=1,
        output_price=1,
    )
    ledger.reconcile(reservation, usage=Usage(1, 1, 2), latency_ms=2)
    status = ledger.status(session_id="s")
    assert status["tokens"] == 2
    assert status["warnings"] == []

    oversized = ledger.reserve(
        session_id="s",
        provider="p",
        model="m",
        operation="x",
        input_price=1,
        output_price=1,
    )
    with pytest.raises(ProviderBudgetError):
        ledger.reconcile(oversized, usage=Usage(11, 1, 12), latency_ms=1)
    assert ledger.status(session_id="s")["tokens"] == 2


def test_transport_rejects_private_dns_resolution():
    transport = JsonHttpTransport(resolver=lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.1", 0))])
    with pytest.raises(TransportError):
        transport.post_json(
            "https://provider.example/v1/systemone",
            {},
            timeout_seconds=1,
        )


def test_transport_rejects_public_resolution_for_loopback_http():
    transport = JsonHttpTransport(
        resolver=lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))]
    )
    with pytest.raises(TransportError):
        transport.post_json(
            "http://localhost:8080/v1/systemone",
            {},
            timeout_seconds=1,
            local_http=True,
            allowed_origins=("http://localhost:8080",),
        )


def test_invalid_deadline_does_not_leave_a_reserved_usage_row(tmp_path):
    env = _custom_env(
        IDA_MCP_CUSTOM_INPUT_USD_PER_MTOK="1",
        IDA_MCP_CUSTOM_OUTPUT_USD_PER_MTOK="1",
    )
    config = resolve_provider_config(env=env)
    ledger = UsageLedger(
        tmp_path / "usage.sqlite3",
        budget=BudgetConfig(
            request_input_tokens=100,
            request_output_tokens=5,
            token_budget_session=100,
            token_budget_daily=100,
            cost_budget_session=10,
            cost_budget_daily=10,
        ),
    )
    provider = CustomProvider(config, transport=_FakeTransport({}), ledger=ledger)
    with pytest.raises(Exception) as exc:
        provider.invoke(
            {"signature": "safe"},
            [Question("q1", "noul", "check")],
            deadline_seconds=-1,
        )
    assert getattr(exc.value, "code", None) == "PROVIDER_TIMEOUT"
    assert ledger.status()["requests"] == 0


def test_request_estimate_is_checked_before_transport(tmp_path):
    env = _custom_env(
        IDA_MCP_CUSTOM_MAX_INPUT_CHARS="4096",
        IDA_MCP_CUSTOM_INPUT_USD_PER_MTOK="1",
        IDA_MCP_CUSTOM_OUTPUT_USD_PER_MTOK="1",
    )
    config = resolve_provider_config(env=env)
    ledger = UsageLedger(
        tmp_path / "usage.sqlite3",
        budget=BudgetConfig(
            request_input_tokens=10,
            request_output_tokens=5,
            token_budget_session=100,
            token_budget_daily=100,
            cost_budget_session=10,
            cost_budget_daily=10,
        ),
    )
    transport = _FakeTransport({})
    provider = CustomProvider(config, transport=transport, ledger=ledger)
    with pytest.raises(ProviderBudgetError) as exc:
        provider.invoke(
            {"signature": "x" * 1000},
            [Question("q1", "noul", "check")],
        )
    assert exc.value.details["reason"] == "request_tokens"
    assert transport.calls == []
    assert ledger.status()["requests"] == 0
