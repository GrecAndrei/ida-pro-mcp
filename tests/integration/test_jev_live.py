"""Opt-in live checks for the explicit Jev provider."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.advisory import ask_architecture, ask_behavior
from ida_pro_mcp.host.intelligence.providers import build_provider, resolve_provider_config
from ida_pro_mcp.host.intelligence.providers.usage_accounting import UsageLedger
from ida_pro_mcp.host.intelligence.rerank import Reranker

pytestmark = [
    pytest.mark.live_jev,
    pytest.mark.skipif(
        not os.environ.get("TYPESAFE_API_KEY")
        or os.environ.get("IDA_MCP_INTELLIGENCE_MODE") != "jev",
        reason="Real Jev tests require TYPESAFE_API_KEY and IDA_MCP_INTELLIGENCE_MODE=jev",
    ),
    pytest.mark.timeout(120),
]


def _provider():
    return build_provider(resolve_provider_config())


def _ledger(tmp_path: Path) -> UsageLedger:
    return UsageLedger(tmp_path / "provider_usage.sqlite3")


def test_jev_provider_status_and_capabilities():
    status = _provider().status()
    assert status.ready is True
    assert status.mode == "jev"
    assert status.provider_id == "typesafe-jev"
    assert status.protocol == "typed_questions"
    assert status.auth_present is True
    assert status.capabilities.classify is True
    assert status.capabilities.score is True


def test_jev_behavior_classification(tmp_path: Path):
    result = ask_behavior(
        {
            "function_name": "encrypt_buffer",
            "signature": "void encrypt_buffer(uint8_t*, size_t)",
            "evidence": ["xor_loop", "in_place_buffer_update"],
        },
        provider=_provider(),
        ledger=_ledger(tmp_path),
    )
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0].get("behavior"), str)
    assert 0.0 <= result[0].get("confidence", -1.0) <= 1.0


def test_jev_advisory_reranking(tmp_path: Path):
    provider = build_provider(resolve_provider_config(), ledger=_ledger(tmp_path))
    reranker = Reranker(provider=provider)
    assert reranker.is_enabled() is True

    documents = [
        "network_connect(const char*, int)",
        "calculate_checksum(const uint8_t*, size_t)",
    ]
    result = reranker.rerank("open socket connection", documents)
    assert isinstance(result, list)
    assert len(result) == len(documents)
    assert all(set(item) == {"index", "score"} for item in result)
    assert all(0.0 <= item["score"] <= 1.0 for item in result)


def test_jev_raw_architecture(tmp_path: Path):
    result = ask_architecture(
        {"bytes": "55 48 89 E5 48 83 EC 10"},
        provider=_provider(),
        ledger=_ledger(tmp_path),
    )
    assert result.get("ok") is True
    assert isinstance(result.get("choice"), str)
    assert result.get("source") == "provider_advisory"
    assert 0.0 <= result.get("confidence", -1.0) <= 1.0
