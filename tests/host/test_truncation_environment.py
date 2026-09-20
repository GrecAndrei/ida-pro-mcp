from __future__ import annotations

import importlib

from ida_pro_mcp.host.stores import truncation


def test_invalid_truncation_environment_values_use_defaults(monkeypatch):
    original_store = truncation._TRUNCATION_STORE
    original_order = truncation._TRUNCATION_ORDER
    try:
        monkeypatch.setenv("IDA_MCP_MAX_TRUNCATION_STORE", "not-an-integer")
        monkeypatch.setenv("IDA_MCP_TRUNCATION_TTL", "not-a-number")
        reloaded = importlib.reload(truncation)

        assert reloaded._MAX_TRUNCATION_STORE == reloaded._DEFAULT_MAX_TRUNCATION_STORE
        assert reloaded._TOKEN_TTL_SEC == reloaded._DEFAULT_TOKEN_TTL_SEC
    finally:
        monkeypatch.delenv("IDA_MCP_MAX_TRUNCATION_STORE", raising=False)
        monkeypatch.delenv("IDA_MCP_TRUNCATION_TTL", raising=False)
        importlib.reload(truncation)
        truncation._TRUNCATION_STORE = original_store
        truncation._TRUNCATION_ORDER = original_order
