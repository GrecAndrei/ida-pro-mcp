from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.intelligence.advisory import assess_function_neighborhood
from ida_pro_mcp.host.intelligence.context import ContextAssembler
from ida_pro_mcp.host.intelligence.providers import (
    Answer,
    BudgetConfig,
    ProviderResponse,
    StateSnapshot,
    Usage,
    resolve_provider_config,
)
from ida_pro_mcp.host.intelligence.providers.registry import default_usage_ledger


def _decompile_payload() -> dict:
    return {
        "results": [
            {
                "addr": "0x401000",
                "name": "decrypt_config",
                "prototype": "int decrypt_config(int mode)",
                "pseudocode": '''
                    int decrypt_config(int mode) {
                        if (mode == 1337 && is_admin) { // COMMENT_SENTINEL
                            return open_socket("LITERAL_SENTINEL");
                        }
                        return parse_packet(input, 0xC0FFEE);
                    }
                ''',
                "callers_context": [
                    {
                        "addr": "0x400120",
                        "name": "handle_request",
                        "signature": "void handle_request(int mode)",
                    },
                    {
                        "addr": "0x400200",
                        "name": "worker_loop",
                        "signature": "int worker_loop(void)",
                    },
                ],
                "callees_context": [
                    {
                        "addr": "0x401200",
                        "name": "open_socket",
                        "signature": "int open_socket(const char *host)",
                    },
                    {
                        "addr": "0x401300",
                        "name": "parse_packet",
                        "signature": "int parse_packet(void *data)",
                    },
                ],
                "api_calls": ["open_socket", "recv"],
                "complexity": {"lines": 12, "branches": 1, "calls": 2},
                "structure": {
                    "cfg": {"nodes": 4, "edges": 5, "cyclomatic_complexity": 2},
                    "control_points": [
                        {
                            "kind": "if",
                            "condition": "mode == 1337 && is_admin /* CONTROL_SENTINEL */",
                        }
                    ],
                    "dataflow": {"argument_variables": ["mode", "input"]},
                },
            }
        ]
    }


class _RecordingProvider:
    def __init__(self, *, omit_answers: bool = False) -> None:
        self.omit_answers = omit_answers
        self.state = None
        self.questions = None
        self.calls = 0

    def invoke(self, state, questions, **_kwargs):
        self.calls += 1
        self.state = StateSnapshot.from_mapping(state).values
        self.questions = list(questions)
        if self.omit_answers:
            answers = {}
        else:
            answers = {}
            for question in self.questions:
                question_id = question.question_id
                if question_id.startswith("behavior_"):
                    answers[question_id] = Answer(
                        question_id, "choice", "network_socket", confidence=0.84
                    )
                elif question_id.startswith("priority_"):
                    value = 0.2 if question_id == "priority_0" else 1.8
                    answers[question_id] = Answer(
                        question_id, "score", value, confidence=0.9
                    )
                elif question_id == "recommended_next":
                    answers[question_id] = Answer(
                        question_id, "choice", "function_0", confidence=0.8
                    )
                elif question_id == "recommended_evidence":
                    answers[question_id] = Answer(
                        question_id, "choice", "inspect_callees", confidence=0.8
                    )
                elif question_id == "evidence_sufficiency":
                    answers[question_id] = Answer(
                        question_id, "score", 1.8, confidence=0.8
                    )
        return ProviderResponse("fixture", answers, Usage(12, 2, 14))


def test_context_assembly_builds_safe_focus_and_neighborhood_packet(monkeypatch):
    calls = []

    def record_assessment(context, functions, **kwargs):
        calls.append((context, functions, kwargs))
        return {
            "ok": True,
            "functions": [
                {
                    "address": "0x401000",
                    "name": "decrypt_config",
                    "relationship": "focus",
                    "behavior": "network_socket",
                }
            ],
            "priorities": [],
            "recommended_next": None,
            "recommended_evidence": "insufficient_context",
            "evidence": {},
            "advisory_order": [],
            "applied": False,
            "disagreement": False,
        }

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.advisory.assess_function_neighborhood",
        record_assessment,
    )
    assembler = object.__new__(ContextAssembler)
    assembler._run_housekeeping = lambda _session: None
    assembler.record_call = lambda *_args: None
    assembler._get_bb_entries = lambda *_args: []
    assembler._perf_start = lambda: 0.0
    assembler._perf_end = lambda *_args: None
    assembler.check_stuck = lambda *_args: None

    payload = _decompile_payload()
    pack = assembler.assemble(
        tool="ida_decompile",
        action="semantic_decompile",
        payload=payload,
        addr="0x401000",
        session_id="synthetic",
        idb_path="",
        mode="compact",
        detail="deep",
    )

    assert len(calls) == 1
    context, candidates, options = calls[0]
    assert options["detail"] == "deep"

    assert [item["relationship"] for item in candidates] == [
        "focus",
        "caller",
        "callee",
        "caller",
        "callee",
    ]
    serialized = repr((context, candidates))
    for private_fragment in (
        "LITERAL_SENTINEL",
        "COMMENT_SENTINEL",
        "CONTROL_SENTINEL",
        "0xC0FFEE",
        "mode == 1337 && is_admin",
    ):
        assert private_fragment not in serialized

    focus = candidates[0]
    assert "open_socket" in focus["signature"]
    assert "parse_packet" in focus["signature"]
    assert focus["api_calls"] == ["open_socket", "recv"]
    assert focus["structure"]["edges"] == 5
    assert focus["structure"]["control_flow"] == [
        {
            "kind": "if",
            "variables": ["is", "admin"],
            "operators": ["equal", "and"],
            "has_constant": True,
        }
    ]
    assert pack["behavior_tags"] == ["network_socket"]


@pytest.mark.parametrize(
    ("detail", "expected_candidates"),
    (("triage", 4), ("normal", 8), ("deep", 16)),
)
def test_neighborhood_advisory_uses_one_bounded_typed_request(detail, expected_candidates):
    functions = [
        {
            "address": f"0x{0x401000 + index * 0x100:x}",
            "name": f"function_{index}",
            "relationship": "callee" if index % 2 else "caller",
            "signature": f"calls=1; call symbols: api_{index}; identifier terms: arg_{index}",
            "api_calls": [f"api_{index}"],
        }
        for index in range(17)
    ]
    provider = _RecordingProvider()
    result = assess_function_neighborhood(
        {
            "focus_address": "0x401000",
            "focus_name": "decrypt_config",
            "focus_signature": "calls=2; call symbols: open_socket parse_packet",
            "raw_decompilation": "DO_NOT_SEND_SENTINEL",
        },
        functions,
        provider=provider,
        detail=detail,
    )

    assert provider.calls == 1
    assert len(provider.state["functions"]) == expected_candidates
    assert len(provider.questions) == expected_candidates * 2 + 3
    assert {question.type for question in provider.questions} == {"choice", "score"}
    assert "raw_decompilation" not in provider.state
    assert "DO_NOT_SEND_SENTINEL" not in repr(provider.state)
    assert result["ok"] is True
    assert len(result["functions"]) == expected_candidates
    assert result["recommended_next"]["candidate_id"] == "function_0"
    assert result["recommended_evidence"] == "inspect_callees"
    assert result["priority_disagreement"] is True
    assert result["advisory_order"][0]["candidate_id"] == "function_0"
    assert result["applied"] is False


def test_malformed_neighborhood_response_fails_closed():
    provider = _RecordingProvider(omit_answers=True)
    result = assess_function_neighborhood(
        {"focus_address": "0x401000"},
        [{"address": "0x401000", "name": "focus", "signature": "calls=0"}],
        provider=provider,
    )

    assert result["error"] is True
    assert result["code"] == "PROVIDER_PROTOCOL_ERROR"
    assert result["functions"] == []
    assert result["recommended_next"] is None
    assert result["applied"] is False
    assert result["advisory_order"] is None


def test_jev_budget_and_pricing_defaults_are_mode_aware(monkeypatch, tmp_path):
    jev_budget = BudgetConfig.from_env({}, provider_mode="jev")
    custom_budget = BudgetConfig.from_env({}, provider_mode="custom")
    assert jev_budget.request_input_tokens == 65_536
    assert jev_budget.token_budget_session == 15_000_000
    assert jev_budget.token_budget_daily == 140_000_000
    assert (jev_budget.cost_budget_session, jev_budget.cost_budget_daily) == (5.0, 20.0)
    assert custom_budget.request_input_tokens == 8_192
    assert custom_budget.token_budget_session == 100_000
    assert custom_budget.token_budget_daily == 500_000

    config = resolve_provider_config(
        env={
            "IDA_MCP_INTELLIGENCE_MODE": "jev",
            "TYPESAFE_API_KEY": "synthetic-key",
        }
    )
    assert config.input_usd_per_mtok == pytest.approx(0.042)
    assert config.output_usd_per_mtok == 0.0
    assert config.max_input_chars == 262_144
    assert config.max_questions == 64

    import ida_pro_mcp.host.intelligence.providers.registry as registry

    monkeypatch.setattr(
        registry,
        "UsageLedger",
        lambda path, *, budget: SimpleNamespace(path=path, budget=budget),
    )
    ledger = default_usage_ledger(
        env={
            "IDA_MCP_INTELLIGENCE_MODE": "jev",
            "IDA_MCP_CACHE_DIR": str(tmp_path),
        }
    )
    assert ledger.budget.request_input_tokens == 65_536
    assert ledger.budget.token_budget_daily == 140_000_000


def test_jev_budget_defaults_can_be_overridden():
    budget = BudgetConfig.from_env(
        {
            "IDA_MCP_JEV_REQUEST_INPUT_TOKENS": "32768",
            "IDA_MCP_JEV_SESSION_TOKEN_BUDGET": "2000000",
            "IDA_MCP_JEV_DAILY_BUDGET_USD": "7.5",
        },
        provider_mode="jev",
    )
    assert budget.request_input_tokens == 32_768
    assert budget.token_budget_session == 2_000_000
    assert budget.cost_budget_daily == 7.5
