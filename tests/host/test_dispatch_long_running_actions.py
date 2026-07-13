from __future__ import annotations

from ida_pro_mcp.host.server.server_dispatch import _long_running_sock_timeout


def test_embedding_indexing_actions_get_the_extended_rpc_timeout(monkeypatch):
    monkeypatch.delenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", raising=False)

    for action in ("index_fast", "index_batch", "index_range", "index_function", "similar_functions"):
        assert _long_running_sock_timeout("intelligence", {"action": action}) == 120


def test_regular_actions_keep_the_default_rpc_timeout(monkeypatch):
    monkeypatch.delenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", raising=False)

    assert _long_running_sock_timeout("intelligence", {"action": "intelligence_status"}) == -1
