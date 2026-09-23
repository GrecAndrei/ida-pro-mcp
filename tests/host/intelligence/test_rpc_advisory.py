from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.intelligence import rpc_advisory as advisory
from ida_pro_mcp.host.intelligence.providers import Answer


def test_query_expansion_uses_host_classification_and_confidence_gate(monkeypatch):
    seen = {}

    def classify(state, **kwargs):
        seen["state"] = state
        seen["kwargs"] = kwargs
        return [{"behavior": "crypto_symmetric", "confidence": 0.8}]

    monkeypatch.setattr(
        advisory,
        "ask_behavior",
        classify,
    )
    query = "How does this function prepare cryptographic key material?"
    result = advisory.prepare_rpc_advisory_args(
        "search",
        {"action": "nl", "query": query, "mode": "expand"},
        session_id="session-1",
    )
    assert result == {"_host_expansion_queries": ["crypto symmetric"]}
    assert "query_signature" in seen["state"]
    assert seen["state"]["query_signature"] != query
    assert seen["kwargs"]["session_id"] == "session-1"

    monkeypatch.setattr(
        advisory,
        "ask_behavior",
        lambda *_args, **_kwargs: [{"behavior": "crypto_symmetric", "confidence": 0.2}],
    )
    assert advisory.prepare_rpc_advisory_args(
        "search", {"action": "nl", "query": "find crypto"}, session_id="session-1"
    ) == {}


def test_behavior_candidate_questions_bind_each_signature_to_its_question(monkeypatch):
    seen = {}

    class _Provider:
        config = SimpleNamespace(max_input_chars=32768, max_questions=8, model="jev-test")

        def invoke(self, state, questions, **kwargs):
            seen["state"] = state
            seen["questions"] = list(questions)
            seen["kwargs"] = kwargs
            return SimpleNamespace(
                answers={
                    question.question_id: Answer(
                        question.question_id,
                        "choice",
                        "crypto_symmetric" if index == 0 else "network_http",
                        confidence=0.91,
                    )
                    for index, question in enumerate(questions)
                }
            )

    monkeypatch.setattr(advisory, "resolve_provider", lambda **_kwargs: _Provider())
    matches, error = advisory._classify_behavior_candidates(
        [
            {"addr": "0x401000", "name": "sub_a", "signature": "cipher loop"},
            {"addr": "0x402000", "name": "sub_b", "signature": "socket connect"},
        ],
        "crypto_symmetric",
        session_id="session-2",
    )
    assert error is None
    assert [item["addr"] for item in matches] == ["0x401000"]
    assert seen["state"] == {"requested_behavior": "crypto_symmetric"}
    assert [item.instructions["candidate_signature"] for item in seen["questions"]] == [
        "cipher loop",
        "socket connect",
    ]
    assert all(item.instructions["candidate_index"] == index for index, item in enumerate(seen["questions"]))
    assert seen["kwargs"]["session_id"] == "session-2"


def test_host_rerank_keeps_deterministic_primary_and_exposes_advisory_order(monkeypatch):
    monkeypatch.setattr(
        advisory,
        "provider_status",
        lambda: {"ok": True, "provider": {"provider_id": "jev"}},
    )
    class _Reranker:
        last_error = None
        last_evidence = {
            "signatures_seen": [],
            "budget_burn": {},
            "confidence": 0.9,
            "fail_closed_order": ["0x401000", "0x402000"],
            "applied": False,
            "disagreement": True,
        }

        def __init__(self):
            pass

        def is_enabled(self):
            return True

        def rerank(self, query, documents, *, deadline=None, session_id="", detail="normal", accept_advisory=False):
            assert query == "find crypto"
            assert documents == ["low", "high"]
            assert deadline is not None
            assert session_id == "session-3"
            assert accept_advisory is False
            return [{"index": 0, "score": 0.1}, {"index": 1, "score": 0.9}]

    monkeypatch.setattr("ida_pro_mcp.host.intelligence.rerank.Reranker", _Reranker)
    result = {
        "items": [],
        "results": "",
        "_host_rerank_candidates": [
            {"ea": "0x401000", "name": "low_fn", "similarity": 0.8, "signature": "low"},
            {"ea": "0x402000", "name": "high_fn", "similarity": 0.7, "signature": "high"},
        ],
    }
    cooked = advisory.apply_rpc_advisory(
        "search",
        {"action": "nl", "query": "find crypto", "limit": 1, "timeout_ms": 8000},
        result,
        session_id="session-3",
    )
    assert cooked["rerank"]["applied"] is False
    assert cooked["rerank"]["disagreement"] is True
    assert cooked["rerank"]["pool"] == 2
    # Primary stays deterministic (first pool item), advisory_order has Jev ranking.
    assert cooked["items"][0]["addr"] == "0x401000"
    assert cooked["advisory_order"][0]["addr"] == "0x402000"
    assert cooked["advisory_order"][0]["rerank_score"] == 0.9
    assert cooked["evidence"]["applied"] is False
    assert cooked["advisory_provider"] == "jev"
    assert "_host_rerank_candidates" not in cooked


def test_host_rerank_applies_only_with_accept_advisory(monkeypatch):
    monkeypatch.setattr(
        advisory,
        "provider_status",
        lambda: {"ok": True, "provider": {"provider_id": "jev"}},
    )
    class _Reranker:
        last_error = None
        last_evidence = None

        def is_enabled(self):
            return True

        def rerank(self, query, documents, *, deadline=None, session_id="", detail="normal", accept_advisory=False):
            assert accept_advisory is True
            return [{"index": 0, "score": 0.1}, {"index": 1, "score": 0.9}]

    monkeypatch.setattr("ida_pro_mcp.host.intelligence.rerank.Reranker", _Reranker)
    result = {
        "items": [],
        "results": "",
        "_host_rerank_candidates": [
            {"ea": "0x401000", "name": "low_fn", "similarity": 0.8, "signature": "low"},
            {"ea": "0x402000", "name": "high_fn", "similarity": 0.7, "signature": "high"},
        ],
    }
    cooked = advisory.apply_rpc_advisory(
        "search",
        {"action": "nl", "query": "find crypto", "limit": 1, "timeout_ms": 8000, "accept_advisory": True},
        result,
        session_id="session-3",
    )
    assert cooked["rerank"]["applied"] is True
    assert cooked["items"][0]["addr"] == "0x402000"


def test_nested_gp_advisory_is_added_without_applying_candidate(monkeypatch):
    monkeypatch.setattr(
        advisory,
        "ask_gp",
        lambda state, candidates, **_kwargs: {
            "ok": True,
            "choice": candidates[0],
            "confidence": 0.75,
        },
    )
    result = {
        "ok": True,
        "riscv_gp": {
            "found": True,
            "gp_hex": "0x80001000",
            "applied": False,
            "_host_advisory": {
                "kind": "riscv_gp",
                "state": {"architecture": "riscv"},
                "candidate": "0x80001000",
            },
        },
    }
    cooked = advisory.apply_rpc_advisory("idb", {"action": "overview"}, result, session_id="s")
    assert cooked["riscv_gp"]["found"] is True
    assert cooked["riscv_gp"]["applied"] is False
    assert cooked["riscv_gp"]["advisory_accepted"] is True
    assert "_host_advisory" not in cooked["riscv_gp"]


def test_classify_text_uses_derived_signature_and_strips_bridge_markers(monkeypatch):
    seen = {}

    def classify(state, **kwargs):
        seen["state"] = state
        seen["kwargs"] = kwargs
        return [{"behavior": "crypto_symmetric", "confidence": 0.9}]

    monkeypatch.setattr(advisory, "ask_behavior", classify)
    query = "Explain which routine initializes this cryptographic context."
    result = advisory.apply_rpc_advisory(
        "intelligence",
        {"action": "classify_text", "query": query},
        {"ok": True, "backend": "provider_advisory", "_provider_source_kind": "operator_query"},
        session_id="session-4",
    )
    assert "query_signature" in seen["state"]
    assert seen["state"]["query_signature"] != query
    assert seen["kwargs"]["operation"] == "classify_text"
    assert result["behaviors"][0]["behavior"] == "crypto_symmetric"
    assert "_provider_source_kind" not in result


def test_gadget_and_firmware_results_keep_legacy_advisory_shapes(monkeypatch):
    monkeypatch.setattr(
        advisory,
        "ask_behavior",
        lambda *_args, **_kwargs: [{"behavior": "code_execution", "confidence": 0.84}],
    )
    gadgets = advisory.apply_rpc_advisory(
        "gadgets",
        {"action": "rop"},
        {"ok": True, "count": 2, "_provider_signature": "pop rdi; ret"},
        session_id="session-5",
    )
    assert gadgets["exploit_potential"]["top_primitive"] == "code_execution"
    assert gadgets["exploit_potential"]["confidence"] == 0.84
    assert "_provider_signature" not in gadgets

    candidates = [
        {"base": "0x20000000", "evidence": ["candidate two"]},
        {"base": "0x10000000", "evidence": ["candidate one"]},
    ]
    monkeypatch.setattr(
        advisory,
        "ask_load_base",
        lambda _state, _candidates, **_kwargs: {"ok": True, "choice": "0x10000000"},
    )
    firmware = advisory.apply_rpc_advisory(
        "firmware",
        {"action": "detect_load_base", "timeout_ms": 10000},
        {"ok": True, "arch": "riscv64", "candidates": candidates, "recommended_base": None},
        session_id="session-6",
    )
    assert firmware["recommended_base"] == "0x10000000"
    # Primary candidate order stays deterministic without accept_advisory.
    assert firmware["candidates"][0]["base"] == "0x20000000"


def test_rerank_failure_keeps_lexical_result_and_strips_private_pool(monkeypatch):
    class _Reranker:
        last_error = None

        def is_enabled(self):
            return True

        def rerank(self, *_args, **_kwargs):
            raise RuntimeError("provider response details must not escape")

    monkeypatch.setattr("ida_pro_mcp.host.intelligence.rerank.Reranker", _Reranker)
    monkeypatch.setattr(
        advisory,
        "provider_status",
        lambda: {"ok": True, "provider": {"provider_id": "custom"}},
    )
    result = advisory.apply_rpc_advisory(
        "search",
        {"action": "nl", "query": "crypto", "timeout_ms": 8000},
        {
            "items": [{"addr": "0x1000", "name": "lexical"}],
            "_host_rerank_candidates": [
                {"ea": "0x1000", "name": "lexical", "signature": "crypto"}
            ],
        },
        session_id="session-7",
    )
    assert result["items"][0]["addr"] == "0x1000"
    assert result["rerank"]["reason"] == "provider_error"
    assert result["rerank"]["error"]["message"] == "advisory scoring failed"
    assert result["advisory_provider"] == "custom"
    assert "_host_rerank_candidates" not in result
