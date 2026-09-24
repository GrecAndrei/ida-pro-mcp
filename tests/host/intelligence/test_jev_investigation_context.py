from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.intelligence.advisory import (
    _compact_candidate_features,
    assess_function_neighborhood,
)
from ida_pro_mcp.host.intelligence.context import (
    ContextAssembler,
    _compact_function_signature,
    _decompile_neighborhood_candidates,
    _function_evidence_features,
    _recommended_ida_call,
)
from ida_pro_mcp.host.intelligence.providers import (
    Answer,
    BudgetConfig,
    ProviderResponse,
    StateSnapshot,
    Usage,
    resolve_provider_config,
)
from ida_pro_mcp.host.intelligence.providers.registry import default_usage_ledger
from ida_pro_mcp.host.intelligence.providers.types import MAX_STATE_BYTES


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
    def __init__(
        self,
        *,
        omit_answers: bool = False,
        omit_ids: set[str] | None = None,
        overrides: dict[str, Answer] | None = None,
    ) -> None:
        self.omit_answers = omit_answers
        self.omit_ids = set(omit_ids or ())
        self.overrides = dict(overrides or {})
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
            answers.update(self.overrides)
            for question_id in self.omit_ids:
                answers.pop(question_id, None)
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
    (("triage", 8), ("normal", 16), ("deep", 30)),
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
        for index in range(65)
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


def test_deep_neighborhood_fills_the_available_state_window():
    functions = [
        {
            "address": f"0x{0x401000 + index * 0x100:x}",
            "name": f"function_{index}",
            "relationship": "callee",
            "signature": f"symbol_{index}; " + ("call_symbol " * 1_000),
            "api_calls": [f"api_{index}"],
        }
        for index in range(30)
    ]
    provider = _RecordingProvider()

    result = assess_function_neighborhood(
        {"focus_address": "0x401000", "focus_signature": "focus calls=30"},
        functions,
        provider=provider,
        detail="deep",
    )

    state_size = len(
        json.dumps(provider.state, ensure_ascii=False, separators=(",", ":")).encode()
    )
    assert result["ok"] is True
    assert len(provider.state["functions"]) == 30
    assert len(provider.questions) == 63
    assert MAX_STATE_BYTES - state_size < 2_000
    assert state_size <= MAX_STATE_BYTES
    assert len(provider.state["functions"][0]["signature"]) > 2_048


def test_neighborhood_adapts_candidate_count_to_provider_question_limit():
    provider = _RecordingProvider()
    provider.config = SimpleNamespace(
        model="fixture", mode="custom", max_questions=5, max_input_chars=262_144
    )
    functions = [
        {
            "address": f"0x{0x401000 + index * 0x100:x}",
            "name": f"function_{index}",
            "signature": f"calls=1; api_{index}",
        }
        for index in range(10)
    ]

    result = assess_function_neighborhood(
        {"focus_address": "0x401000"}, functions, provider=provider, detail="deep"
    )

    assert result["ok"] is True
    assert len(provider.state["functions"]) == 1
    assert len(provider.questions) == 5


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
    assert jev_budget.request_output_tokens == 8_192
    assert jev_budget.token_budget_session == 15_000_000
    assert jev_budget.token_budget_daily == 150_000_000
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
    assert ledger.budget.request_output_tokens == 8_192
    assert ledger.budget.token_budget_daily == 150_000_000

    generic = registry.default_usage_ledger(
        env={
            "IDA_MCP_INTELLIGENCE_MODE": "unsupported",
            "IDA_MCP_CACHE_DIR": str(tmp_path),
        }
    )
    assert generic.budget == BudgetConfig.from_env({}, provider_mode="generic")

    disabled = registry.resolve_provider(
        env={
            "IDA_MCP_INTELLIGENCE_MODE": "disabled",
            "IDA_MCP_CACHE_DIR": str(tmp_path),
        },
        with_ledger=True,
    )
    assert type(disabled).__name__ == "DisabledProvider"


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


def test_compact_feature_projection_keeps_safe_bounded_metadata():
    features = _compact_candidate_features(
        {
            "api_calls": ["send", "send", "unsafe label", None, "recv"],
            "crypto_hints": ("AES", "bad label!"),
            "ida_behavior_tags": ["network_socket"],
            "risk_patterns": ["stack_pivot"],
            "complexity": {
                "lines": 12,
                "calls": 2,
                "branches": True,
                "loops": -1,
                "xor_ops": 1_000_001,
            },
            "caller_symbols": [
                None,
                {"address": "0x401000", "name": "handle_request"},
                {"address": "bad address", "name": "unsafe name!"},
                {"name": "worker_loop"},
            ],
            "callee_symbols": "not-a-list",
            "structure": {
                "blocks": 4,
                "edges": 5,
                "entry_blocks": True,
                "exit_blocks": -1,
                "call_targets": ["open_socket", "bad target!"],
                "control_kinds": ["if", "switch"],
                "argument_names": ["input", "mode"],
                "control_flow": [
                    None,
                    {"kind": "goto", "variables": ["ignored"]},
                    {
                        "kind": "if",
                        "variables": ["mode", "unsafe variable!"],
                        "operators": ["equal"],
                        "has_constant": False,
                    },
                ],
            },
        }
    )

    assert features == {
        "api_calls": ["send", "recv"],
        "crypto_hints": ["AES"],
        "ida_behavior_tags": ["network_socket"],
        "risk_patterns": ["stack_pivot"],
        "complexity": {"lines": 12, "calls": 2},
        "caller_symbols": [
            {"address": "0x401000", "name": "handle_request"},
            {"name": "worker_loop"},
        ],
        "structure": {
            "blocks": 4,
            "edges": 5,
            "call_targets": ["open_socket"],
            "control_kinds": ["if", "switch"],
            "argument_names": ["input", "mode"],
                "control_flow": [
                    {
                        "kind": "if",
                        "variables": ["mode"],
                        "operators": ["equal"],
                        "has_constant": False,
                    }
                ],
        },
    }

    assert _compact_candidate_features({"complexity": {"calls": True}}) == {}


def test_function_evidence_features_strip_private_text_and_reject_bad_labels():
    features = _function_evidence_features(
        {
            "api_calls": ["ReadFile", "unsafe label!", 17],
            "crypto_hints": ("AES", "AES"),
            "behavior_tags": ["network_socket"],
            "dangerous_patterns": [
                {"pattern": "gets"},
                "strcpy — local-only note",
                None,
                {"pattern": "unsafe label!"},
            ],
            "callers": [
                None,
                {"addr": "0x401000", "name": "handle_request — local"},
                {"address": "bad address", "name": "unsafe name!"},
            ],
            "callees": [{"address": "401200"}],
            "complexity": {
                "lines": 9,
                "calls": 2,
                "branches": True,
                "loops": -1,
            },
            "structure": {
                "cfg": {
                    "nodes": 4,
                    "edges": 5,
                    "entry_blocks": 1,
                    "exit_blocks": True,
                    "back_edges": -1,
                    "cyclomatic_complexity": 2,
                },
                "call_targets": ["open_socket", "bad target!"],
                "control_points": [
                    None,
                    {"kind": "unsafe kind!", "condition": "ignored()"},
                    {
                        "kind": "if",
                        "condition": 'mode == 7 && input != "SECRET" /* PRIVATE */',
                    },
                ],
                "dataflow": {"argument_variables": ["mode", "input", "bad arg!"]},
            },
        }
    )

    assert features["api_calls"] == ["ReadFile"]
    assert features["crypto_hints"] == ["AES"]
    assert features["ida_behavior_tags"] == ["network_socket"]
    assert features["risk_patterns"] == ["gets", "strcpy"]
    assert features["caller_symbols"] == [
        {"address": "0x401000", "name": "handle_request"}
    ]
    assert features["callee_symbols"] == [{"address": "401200"}]
    assert features["complexity"] == {"lines": 9, "calls": 2}
    assert features["structure"] == {
        "blocks": 4,
        "edges": 5,
        "entry_blocks": 1,
        "cyclomatic_complexity": 2,
        "call_targets": ["open_socket"],
        "control_flow": [
            {
                "kind": "if",
                "variables": ["input"],
                "operators": ["equal", "and", "not_equal"],
                "has_constant": True,
            }
        ],
        "control_kinds": ["if"],
        "argument_names": ["mode", "input"],
    }
    assert "SECRET" not in repr(features)
    assert "PRIVATE" not in repr(features)


def test_decompile_candidates_use_fallback_and_deduplicate_neighbors():
    assert _compact_function_signature(" /* only a comment */ ", "", "empty") == ""
    call_body = "api_0(); " + " ".join(f"api_{index}();" for index in range(52))
    signature = _compact_function_signature(
        call_body,
        "int invoke(int mode)",
        "invoke",
    )
    assert signature.count("api_") == 48
    assert "api_51" not in signature
    assert "prototype terms:" in signature

    candidates = _decompile_neighborhood_candidates(
        {
            "results": [
                {
                    "addr": "0x401000",
                    "name": "focus",
                    "code": "",
                    "callers_context": [
                        None,
                        {"addr": "0x401000", "name": "duplicate", "signature": "int dup()"},
                        {"addr": "0x401001", "name": "empty", "signature": ""},
                        {"addr": "0x401002", "name": "caller", "signature": "void caller()"},
                    ],
                    "callees_context": [
                        {"addr": "0x401100", "name": "callee", "pseudocode_head": "int callee()"}
                    ],
                },
                None,
                {"addr": "0x401200", "name": "batch", "pseudocode": "int batch() { return helper(); }"},
            ]
        },
        "int focus() { return open_socket(); }",
        "0x401000",
        "focus",
    )

    assert [candidate["relationship"] for candidate in candidates] == [
        "focus",
        "callee",
        "caller",
        "batch_member",
    ]
    assert candidates[0]["signature"] == _compact_function_signature(
        "int focus() { return open_socket(); }", "", "focus"
    )


@pytest.mark.parametrize(
    ("evidence", "tool", "arguments"),
    (
        ("inspect_callers", "ida_callers", {"address": "0x401000"}),
        ("inspect_callees", "ida_callees", {"address": "0x401000"}),
        ("inspect_xrefs", "ida_xrefs_to", {"address": "0x401000"}),
        ("inspect_control_flow", "ida_decompile", {"address": "0x401000", "details": True}),
        ("inspect_strings", "ida_list_strings", {"limit": 50}),
    ),
)
def test_recommended_ida_call_maps_evidence_without_execution(evidence, tool, arguments):
    assert _recommended_ida_call(evidence, " 0x401000 ") == {
        "tool": tool,
        "arguments": arguments,
    }


def test_recommended_ida_call_rejects_empty_target_and_unknown_evidence():
    assert _recommended_ida_call("inspect_callers", " ") is None
    assert _recommended_ida_call("run_mutation", "0x401000") is None


def test_neighborhood_advisory_normalizes_invalid_choices_and_fails_closed_on_missing_answers():
    functions = [
        {"address": "0x401000", "name": "focus", "signature": "calls=1; call symbols: api"}
    ]
    provider = _RecordingProvider(
        overrides={
            "behavior_0": Answer("behavior_0", "choice", "unlisted_behavior"),
            "recommended_next": Answer("recommended_next", "choice", "not_in_pool"),
            "recommended_evidence": Answer("recommended_evidence", "choice", "run_shell"),
        }
    )
    normalized = assess_function_neighborhood(
        {"focus_address": "0x401000"}, functions, provider=provider
    )
    assert normalized["functions"][0]["behavior"] == "unknown"
    assert normalized["recommended_next"] is None
    assert normalized["recommended_evidence"] == "insufficient_context"

    missing_behavior = assess_function_neighborhood(
        {"focus_address": "0x401000"},
        functions,
        provider=_RecordingProvider(omit_ids={"behavior_0"}),
    )
    assert missing_behavior["code"] == "PROVIDER_PROTOCOL_ERROR"
    assert missing_behavior["functions"] == []

    missing_priority = assess_function_neighborhood(
        {"focus_address": "0x401000"},
        functions,
        provider=_RecordingProvider(omit_ids={"priority_0"}),
    )
    assert missing_priority["code"] == "PROVIDER_PROTOCOL_ERROR"
    assert missing_priority["message"] == "advisory order derivation failed"

    missing_neighborhood = assess_function_neighborhood(
        {"focus_address": "0x401000"},
        functions,
        provider=_RecordingProvider(omit_ids={"evidence_sufficiency"}),
    )
    assert missing_neighborhood["code"] == "PROVIDER_PROTOCOL_ERROR"
    assert missing_neighborhood["message"] == "advisory answer derivation failed"


def test_neighborhood_advisory_empty_pool_and_oversized_context_fail_closed():
    empty = assess_function_neighborhood(
        {},
        [None, {"address": "0x401000", "name": "no_signature", "signature": " "}],
        provider=_RecordingProvider(),
    )
    assert empty["ok"] is True
    assert empty["functions"] == []
    assert empty["recommended_evidence"] == "insufficient_context"

    provider = _RecordingProvider()
    oversized_context = dict.fromkeys(
        (
            "focus_address",
            "focus_name",
            "focus_signature",
            "query_signature",
            "architecture",
            "bitness",
            "endian",
            "file_format",
            "caller_count",
            "callee_count",
            "candidate_source",
        ),
        "x" * 32_768,
    )
    oversized = assess_function_neighborhood(
        oversized_context,
        [{"address": "0x401000", "name": "focus", "signature": "calls=0"}],
        provider=provider,
    )
    assert oversized["code"] == "PROVIDER_PROTOCOL_ERROR"
    assert oversized["message"] == "function neighborhood exceeds the compact context limit"
    assert provider.calls == 0


def test_decompile_context_empty_signature_omits_advisory_and_normalizes_detail(monkeypatch):
    assembler = object.__new__(ContextAssembler)
    assembler._run_housekeeping = lambda _session: None
    assembler.record_call = lambda *_args: None
    assembler._get_bb_entries = lambda *_args: []
    assembler._perf_start = lambda: 0.0
    assembler._perf_end = lambda *_args: None
    assembler.check_stuck = lambda *_args: None
    called = []

    def should_not_assess(*args, **kwargs):
        called.append((args, kwargs))
        raise AssertionError("empty compact signature must not call the provider")

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.advisory.assess_function_neighborhood",
        should_not_assess,
    )
    pack = assembler.assemble(
        tool="ida_decompile",
        action="semantic_decompile",
        payload={
            "results": [
                {
                    "addr": "0x401000",
                    "name": "comment_only",
                    "pseudocode": "/* " + "local comment " * 12 + "*/",
                }
            ]
        },
        addr="0x401000",
        session_id="synthetic-empty",
        idb_path="",
        mode="compact",
        detail="unrecognized",
    )
    assert called == []
    assert "investigation_advisory" not in pack


def test_decompile_context_accepts_a_local_classifier_double_without_provider():
    class ClassifierDouble:
        def __init__(self):
            self.calls = []

        def classify(self, signature, **kwargs):
            self.calls.append((signature, kwargs))
            return [{"behavior": "network_socket", "confidence": 0.75}]

    classifier = ClassifierDouble()
    assembler = object.__new__(ContextAssembler)
    assembler._classifier = classifier
    assembler._run_housekeeping = lambda _session: None
    assembler.record_call = lambda *_args: None
    assembler._get_bb_entries = lambda *_args: []
    assembler._perf_start = lambda: 0.0
    assembler._perf_end = lambda *_args: None
    assembler.check_stuck = lambda *_args: None

    pack = assembler.assemble(
        tool="ida_decompile",
        action="semantic_decompile",
        payload=_decompile_payload(),
        addr="0x401000",
        session_id="synthetic-double",
        idb_path="",
        mode="compact",
        detail="normal",
    )

    assert len(classifier.calls) == 1
    signature, options = classifier.calls[0]
    assert "open_socket" in signature
    assert options == {"threshold": 0.0, "top_k": 4, "block": False}
    assert pack["behavior_classifications"] == [
        {"behavior": "network_socket", "confidence": 0.75}
    ]
    assert pack["behavior_tags"] == ["network_socket"]
