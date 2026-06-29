from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder

FIX_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "semantic"


def _fixture(name: str) -> str:
    return (FIX_DIR / name).read_text(encoding="utf-8")


@pytest.mark.integration
def test_real_embedder_semantic_fixture_triage():
    if os.environ.get("IDA_MCP_TEST_REAL_EMBED", "") not in {"1", "true", "yes"}:
        pytest.skip("Set IDA_MCP_TEST_REAL_EMBED=1 to run real embedder integration")

    emb = BgeCodeEmbedder()
    status = emb.status(probe=True)
    if status.get("backend") != "bge-code-v1":
        pytest.skip("real embedder unavailable (backend is not bge-code-v1)")

    clf = BehaviorClassifier.instance(emb)

    crypto_rows = clf.classify(_fixture("crypto_aes.c.txt"), threshold=0.0, top_k=4, block=True)
    http_rows = clf.classify(_fixture("http_client.c.txt"), threshold=0.0, top_k=4, block=True)

    assert crypto_rows
    assert any(r.get("behavior") == "crypto_symmetric" for r in crypto_rows)
    assert http_rows
    assert any(r.get("behavior") in {"network_http", "network_raw", "c2_communication"} for r in http_rows)
