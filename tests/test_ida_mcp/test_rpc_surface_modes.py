"""Offline coverage for the IDA-side decorator compatibility surface."""

from __future__ import annotations

import importlib

def test_rpc_decorators_delegate_and_record_metadata(monkeypatch):
    # Resolve the canonical module from ``sys.modules``.  Some IDA-side tests
    # load compatibility modules through a standalone loader; importing
    # through the parent package can otherwise retain a stale child-module
    # attribute while the canonical module has already been restored.
    rpc = importlib.import_module("ida_pro_mcp.ida_mcp.rpc")

    class _Server:
        def tool(self, func):
            return ("tool", func)

        def resource(self, uri):
            return ("resource", uri)

        def prompt(self, func):
            return ("prompt", func)

    monkeypatch.setitem(rpc.tool.__globals__, "MCP_SERVER", _Server())
    rpc.TESTS.clear()
    rpc.MCP_UNSAFE.clear()

    @rpc.test("1 + 1 == 2")
    def sample():
        return True

    assert rpc.TESTS["sample"] == (sample, "1 + 1 == 2")
    assert rpc.test()(sample) is sample

    def tool_func():
        return None

    def prompt_func():
        return None

    assert rpc.tool(tool_func) == ("tool", tool_func)
    assert rpc.resource("ida://sample") == ("resource", "ida://sample")
    assert rpc.prompt(prompt_func) == ("prompt", prompt_func)
    assert rpc.unsafe(tool_func) is tool_func
    assert "tool_func" in rpc.MCP_UNSAFE
