"""Offline lifecycle matrix for the IDA plugin wrapper."""

from __future__ import annotations

import runpy
import sys
import types
from pathlib import Path


def _load_plugin(monkeypatch, server):
    idaapi = types.ModuleType("idaapi")
    idaapi.PLUGIN_KEEP = 1
    idaapi.PLUGIN_HIDE = 2
    idaapi.PLUGIN_FIX = 4
    idaapi.plugin_t = type("plugin_t", (), {})
    package = types.ModuleType("ida_mcp")
    package.MCP_SERVER = server
    package.IdaMcpHttpRequestHandler = object
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_mcp", package)
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"),
        run_name="ida_plugin_boundary_matrix",
    )
    namespace["MCP"].run.__globals__["unload_package"] = lambda _name: None
    return namespace


class _Server:
    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.stopped = 0

    def serve(self, host, port, request_handler):
        self.calls.append((host, port, request_handler))
        if self.error:
            raise OSError(self.error, "bind failed")

    def stop(self):
        self.stopped += 1


def test_plugin_init_restart_and_term_cover_platform_and_existing_server(monkeypatch):
    server = _Server()
    namespace = _load_plugin(monkeypatch, server)
    monkeypatch.setattr(sys, "platform", "darwin")
    plugin = namespace["PLUGIN_ENTRY"]()
    assert plugin.init() == 1
    plugin.mcp = server
    plugin.run(0)
    assert server.stopped == 1
    assert plugin.mcp is server
    plugin.term()
    assert server.stopped == 2
    plugin.mcp = None
    plugin.term()


def test_plugin_reports_port_exhaustion_without_leaking_a_server(monkeypatch, capsys):
    server = _Server(error=98)
    namespace = _load_plugin(monkeypatch, server)
    plugin = namespace["MCP"]()
    plugin.init()
    plugin.MAX_PORT_TRIES = 2
    plugin.run(0)
    assert plugin.mcp is None
    assert [call[1] for call in server.calls] == [13337, 13338]
    assert "Could not find available port" in capsys.readouterr().out


def test_plugin_with_no_port_attempts_is_a_noop(monkeypatch):
    server = _Server()
    namespace = _load_plugin(monkeypatch, server)
    plugin = namespace["MCP"]()
    plugin.init()
    plugin.MAX_PORT_TRIES = 0
    plugin.run(0)
    assert server.calls == []
    assert plugin.mcp is None
