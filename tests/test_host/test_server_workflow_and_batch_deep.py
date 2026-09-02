from __future__ import annotations

import pytest

from ida_pro_mcp.host.server.server_workflow import (
    _compose_call_key,
    _tools_cache_lock,
)


def test_compose_call_key() -> None:
    k1 = _compose_call_key("search", {"action": "find", "query": "main"})
    k2 = _compose_call_key("search", {"action": "find", "query": "main"})
    k3 = _compose_call_key("search", {"action": "find", "query": "helper"})

    assert k1 == k2
    assert k1 != k3
    assert k1[0] == "search"
    assert k1[1] == "find"


def test_tools_cache_lock() -> None:
    class DummyServer:
        pass

    srv = DummyServer()
    lock1 = _tools_cache_lock(srv)
    lock2 = _tools_cache_lock(srv)
    assert lock1 is lock2
